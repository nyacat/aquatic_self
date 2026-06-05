mod connection;
mod request;

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::prelude::{FromRawFd, IntoRawFd};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use aquatic_common::access_list::AccessList;
use aquatic_common::privileges::PrivilegeDropper;
use aquatic_common::rustls_config::RustlsConfig;
#[cfg(feature = "metrics")]
use aquatic_common::CanonicalSocketAddr;
use aquatic_common::ServerStartInstant;
use arc_swap::{ArcSwap, ArcSwapAny};
use futures_lite::future::race;
use futures_lite::StreamExt;
use glommio::channels::channel_mesh::{MeshBuilder, Partial, Receivers, Role, Senders};
use glommio::channels::local_channel::{new_bounded, new_unbounded, LocalReceiver, LocalSender};
use glommio::net::{TcpListener, TcpStream};
use glommio::timer::TimerActionRepeat;
use glommio::{enclose, prelude::*};
use slotmap::DenseSlotMap;

use crate::common::*;
use crate::config::Config;
use crate::workers::socket::connection::{run_connection, ConnectionError};

struct ConnectionHandle {
    close_conn_sender: LocalSender<()>,
    valid_until: Rc<RefCell<ValidUntil>>,
}

type PendingResponses = Rc<RefCell<HashMap<RequestId, Rc<LocalSender<ChannelResponse>>>>>;

#[derive(Clone)]
pub(super) struct SocketWorkerState {
    request_senders: Rc<Senders<ChannelRequest>>,
    registry: PendingResponseRegistry,
    static_index: Arc<StaticIndexArcSwap>,
    worker_index: usize,
    response_consumer_id: ConsumerId,
}

impl SocketWorkerState {
    pub(super) fn register_pending_response(&self) -> PendingResponseGuard {
        self.registry.register()
    }

    pub(super) fn request_senders(&self) -> &Senders<ChannelRequest> {
        self.request_senders.as_ref()
    }

    pub(super) fn worker_index(&self) -> usize {
        self.worker_index
    }

    pub(super) fn response_consumer_id(&self) -> ConsumerId {
        self.response_consumer_id
    }
}

#[derive(Clone)]
struct PendingResponseRegistry {
    senders: PendingResponses,
    next_request_id: Rc<RefCell<u64>>,
}

impl PendingResponseRegistry {
    fn new() -> Self {
        Self {
            senders: Rc::new(RefCell::new(HashMap::new())),
            next_request_id: Rc::new(RefCell::new(0)),
        }
    }

    fn register(&self) -> PendingResponseGuard {
        let request_id = self.next_request_id();
        let (sender, receiver) = new_unbounded();

        self.senders
            .borrow_mut()
            .insert(request_id, Rc::new(sender));

        PendingResponseGuard {
            request_id,
            receiver,
            pending_responses: self.senders.clone(),
        }
    }

    fn sender(&self, request_id: RequestId) -> Option<Rc<LocalSender<ChannelResponse>>> {
        self.senders.borrow().get(&request_id).cloned()
    }

    fn next_request_id(&self) -> RequestId {
        let mut next = self.next_request_id.borrow_mut();
        let request_id = RequestId(*next);
        *next = next.wrapping_add(1);
        request_id
    }
}

pub(super) struct PendingResponseGuard {
    request_id: RequestId,
    receiver: LocalReceiver<ChannelResponse>,
    pending_responses: PendingResponses,
}

impl PendingResponseGuard {
    pub(super) fn request_id(&self) -> RequestId {
        self.request_id
    }

    pub(super) async fn recv(&self) -> Option<ChannelResponse> {
        self.receiver.recv().await
    }

    pub(super) fn unregister(&self) {
        self.pending_responses.borrow_mut().remove(&self.request_id);
    }
}

impl Drop for PendingResponseGuard {
    fn drop(&mut self) {
        self.pending_responses.borrow_mut().remove(&self.request_id);
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_socket_worker(
    config: Config,
    state: State,
    opt_tls_config: Option<Arc<ArcSwap<RustlsConfig>>>,
    request_mesh_builder: MeshBuilder<ChannelRequest, Partial>,
    response_mesh_builder: MeshBuilder<ChannelResponse, Partial>,
    mut priv_droppers: Vec<PrivilegeDropper>,
    server_start_instant: ServerStartInstant,
    worker_index: usize,
) -> anyhow::Result<()> {
    let config = Rc::new(config);

    let tcp_listeners = {
        let opt_listener_ipv4 = if config.network.use_ipv4 {
            let priv_dropper = priv_droppers
                .pop()
                .ok_or(anyhow::anyhow!("no enough priv droppers"))?;
            let socket =
                create_tcp_listener(&config, priv_dropper, config.network.address_ipv4.into())
                    .context("create tcp listener")?;

            Some(socket)
        } else {
            None
        };
        let opt_listener_ipv6 = if config.network.use_ipv6 {
            let priv_dropper = priv_droppers
                .pop()
                .ok_or(anyhow::anyhow!("no enough priv droppers"))?;
            let socket =
                create_tcp_listener(&config, priv_dropper, config.network.address_ipv6.into())
                    .context("create tcp listener")?;

            Some(socket)
        } else {
            None
        };

        [opt_listener_ipv4, opt_listener_ipv6]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
    };

    let (request_senders, _) = request_mesh_builder
        .join(Role::Producer)
        .await
        .map_err(|err| anyhow::anyhow!("join request mesh: {:#}", err))?;
    let request_senders = Rc::new(request_senders);
    let (_, response_receivers) = response_mesh_builder
        .join(Role::Consumer)
        .await
        .map_err(|err| anyhow::anyhow!("join response mesh: {:#}", err))?;
    let response_consumer_id = ConsumerId(
        response_receivers
            .consumer_id()
            .ok_or(anyhow::anyhow!("response mesh did not assign consumer id"))?,
    );

    let registry = PendingResponseRegistry::new();
    let response_pumps = spawn_response_pumps(registry.clone(), response_receivers);
    let socket_worker_state = SocketWorkerState {
        request_senders,
        registry,
        static_index: state.static_index.clone(),
        worker_index,
        response_consumer_id,
    };

    let connection_handles = Rc::new(RefCell::new(DenseSlotMap::with_key()));

    TimerActionRepeat::repeat(enclose!((config, connection_handles) move || {
        clean_connections(
            config.clone(),
            connection_handles.clone(),
            server_start_instant,
        )
    }));

    let tasks = tcp_listeners
        .into_iter()
        .map(|tcp_listener| {
            let listener_state = ListenerState {
                config: config.clone(),
                access_list: state.access_list.clone(),
                opt_tls_config: opt_tls_config.clone(),
                server_start_instant,
                connection_handles: connection_handles.clone(),
                socket_worker_state: socket_worker_state.clone(),
            };

            spawn_local(listener_state.accept_connections(tcp_listener))
        })
        .collect::<Vec<_>>();

    for task in tasks {
        task.await;
    }

    for task in response_pumps {
        task.await;
    }

    Ok(())
}

fn spawn_response_pumps(
    registry: PendingResponseRegistry,
    mut response_receivers: Receivers<ChannelResponse>,
) -> Vec<glommio::task::JoinHandle<()>> {
    response_receivers
        .streams()
        .into_iter()
        .map(|(_, mut receiver)| {
            let registry = registry.clone();

            spawn_local(async move {
                while let Some(response) = receiver.next().await {
                    let request_id = match &response {
                        ChannelResponse::Announce { request_id, .. }
                        | ChannelResponse::Scrape { request_id, .. } => *request_id,
                    };

                    if let Some(sender) = registry.sender(request_id) {
                        if sender.try_send(response).is_err() {
                            ::log::debug!(
                                "dropped response for closed pending request {:?}",
                                request_id
                            );
                        }
                    } else {
                        ::log::debug!("dropped late response for request {:?}", request_id);
                    }
                }
            })
            .detach()
        })
        .collect()
}

#[derive(Clone)]
struct ListenerState {
    config: Rc<Config>,
    access_list: Arc<ArcSwapAny<Arc<AccessList>>>,
    opt_tls_config: Option<Arc<ArcSwap<RustlsConfig>>>,
    server_start_instant: ServerStartInstant,
    connection_handles: Rc<RefCell<DenseSlotMap<ConnectionId, ConnectionHandle>>>,
    socket_worker_state: SocketWorkerState,
}

impl ListenerState {
    async fn accept_connections(self, listener: TcpListener) {
        let mut incoming = listener.incoming();

        while let Some(stream) = incoming.next().await {
            match stream {
                Ok(stream) => {
                    let opt_valid_until = ValidUntil::new(
                        self.server_start_instant,
                        self.config.cleaning.max_connection_idle,
                    );

                    let valid_until = if let Some(valid_until) = opt_valid_until {
                        Rc::new(RefCell::new(valid_until))
                    } else {
                        ::log::warn!("clock monotonicity error, not establishing this connection");

                        spawn_local(async move {
                            let _ = stream.shutdown(std::net::Shutdown::Both).await;
                        })
                        .detach();

                        continue;
                    };

                    let (close_conn_sender, close_conn_receiver) = new_bounded(1);

                    let connection_id =
                        self.connection_handles
                            .borrow_mut()
                            .insert(ConnectionHandle {
                                close_conn_sender,
                                valid_until: valid_until.clone(),
                            });

                    spawn_local(self.clone().handle_connection(
                        close_conn_receiver,
                        valid_until,
                        connection_id,
                        stream,
                    ))
                    .detach();
                }
                Err(err) => {
                    ::log::error!("accept connection: {:?}", err);
                }
            }
        }
    }

    async fn handle_connection(
        self,
        close_conn_receiver: LocalReceiver<()>,
        valid_until: Rc<RefCell<ValidUntil>>,
        connection_id: ConnectionId,
        stream: TcpStream,
    ) {
        #[cfg(feature = "metrics")]
        let active_connections_gauge = ::metrics::gauge!(
            "aquatic_active_connections",
            "worker_index" => self.socket_worker_state.worker_index().to_string(),
        );

        #[cfg(feature = "metrics")]
        active_connections_gauge.increment(1.0);

        let f1 = async {
            run_connection(
                self.config,
                self.access_list,
                self.socket_worker_state,
                self.server_start_instant,
                self.opt_tls_config,
                valid_until.clone(),
                stream,
            )
            .await
        };
        let f2 = async {
            close_conn_receiver.recv().await;

            Err(ConnectionError::Inactive)
        };

        let result = race(f1, f2).await;

        #[cfg(feature = "metrics")]
        active_connections_gauge.decrement(1.0);

        match result {
            Ok(()) => (),
            Err(
                err @ (ConnectionError::ResponseBufferWrite(_)
                | ConnectionError::ResponseBufferFull
                | ConnectionError::ResponseReceiverClosed
                | ConnectionError::InternalResponseTimeout
                | ConnectionError::UnexpectedInternalResponse),
            ) => {
                ::log::error!("connection closed: {:#}", err);
            }
            Err(
                err @ (ConnectionError::RequestBufferFull | ConnectionError::RequestReadTimeout),
            ) => {
                ::log::info!("connection closed: {:#}", err);
            }
            Err(err) => {
                ::log::debug!("connection closed: {:#}", err);
            }
        }

        self.connection_handles.borrow_mut().remove(connection_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_response_guard_unregisters_on_drop() {
        let registry = PendingResponseRegistry::new();
        let guard = registry.register();
        let request_id = guard.request_id();

        assert!(registry.sender(request_id).is_some());

        drop(guard);

        assert!(registry.sender(request_id).is_none());
    }

    #[test]
    fn request_ids_increment_per_socket_worker() {
        let registry = PendingResponseRegistry::new();

        assert_eq!(registry.next_request_id(), RequestId(0));
        assert_eq!(registry.next_request_id(), RequestId(1));
    }

    #[test]
    fn socket_worker_state_keeps_response_consumer_id_separate() {
        let request_mesh_builder = MeshBuilder::<ChannelRequest, Partial>::partial(2, 1);
        let response_mesh_builder = MeshBuilder::<ChannelResponse, Partial>::partial(2, 1);

        let socket = LocalExecutorBuilder::default().spawn(enclose!((
            request_mesh_builder,
            response_mesh_builder
        ) move || async move {
            let (request_senders, _) = request_mesh_builder
                .join(Role::Producer)
                .await
                .unwrap();
            let (_, response_receivers) = response_mesh_builder
                .join(Role::Consumer)
                .await
                .unwrap();
            let response_consumer_id = ConsumerId(response_receivers.consumer_id().unwrap());
            let worker_index = response_consumer_id.0 + 1;
            let state = SocketWorkerState {
                request_senders: Rc::new(request_senders),
                registry: PendingResponseRegistry::new(),
                static_index: Arc::new(ArcSwap::from_pointee(StaticIndex::from_bytes(b""))),
                worker_index,
                response_consumer_id,
            };

            assert_eq!(state.worker_index(), worker_index);
            assert_eq!(state.response_consumer_id(), response_consumer_id);
        }));

        let swarm = LocalExecutorBuilder::default().spawn(enclose!((
            request_mesh_builder,
            response_mesh_builder
        ) move || async move {
            let _ = request_mesh_builder.join(Role::Consumer).await.unwrap();
            let _ = response_mesh_builder.join(Role::Producer).await.unwrap();
        }));

        socket.unwrap().join().unwrap();
        swarm.unwrap().join().unwrap();
    }
}

async fn clean_connections(
    config: Rc<Config>,
    connection_slab: Rc<RefCell<DenseSlotMap<ConnectionId, ConnectionHandle>>>,
    server_start_instant: ServerStartInstant,
) -> Option<Duration> {
    if let Some(now) = server_start_instant.seconds_elapsed() {
        connection_slab.borrow_mut().retain(|_, handle| {
            if handle.valid_until.borrow().valid(now) {
                true
            } else {
                let _ = handle.close_conn_sender.try_send(());

                false
            }
        });
    } else {
        ::log::warn!("clock monotonicity failure, could not clean torrents and peers");
    }

    Some(Duration::from_secs(
        config.cleaning.connection_cleaning_interval,
    ))
}

fn create_tcp_listener(
    config: &Config,
    priv_dropper: PrivilegeDropper,
    address: SocketAddr,
) -> anyhow::Result<TcpListener> {
    let socket = if address.is_ipv4() {
        socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?
    } else {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;

        if config.network.set_only_ipv6 {
            socket
                .set_only_v6(true)
                .with_context(|| "socket: set only ipv6")?;
        }

        socket
    };

    socket
        .set_reuse_port(true)
        .with_context(|| "socket: set reuse port")?;

    socket
        .bind(&address.into())
        .with_context(|| format!("socket: bind to {}", address))?;

    socket
        .listen(config.network.tcp_backlog)
        .with_context(|| format!("socket: listen on {}", address))?;

    priv_dropper.after_socket_creation()?;

    Ok(unsafe { TcpListener::from_raw_fd(socket.into_raw_fd()) })
}

#[cfg(feature = "metrics")]
fn peer_addr_to_ip_version_str(addr: &CanonicalSocketAddr) -> &'static str {
    if addr.is_ipv4() {
        "4"
    } else {
        "6"
    }
}
