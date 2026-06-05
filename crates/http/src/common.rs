use std::sync::Arc;

use aquatic_common::access_list::AccessListArcSwap;
use aquatic_common::CanonicalSocketAddr;

pub use aquatic_common::ValidUntil;

use aquatic_http_protocol::{
    request::{AnnounceRequest, ScrapeRequest},
    response::{AnnounceResponse, ScrapeResponse},
};
use slotmap::new_key_type;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct RequestId(pub u64);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ConsumerId(pub usize);

new_key_type! {
    pub struct ConnectionId;
}

#[derive(Debug)]
pub enum ChannelRequest {
    Announce {
        request_id: RequestId,
        response_consumer_id: ConsumerId,
        request: AnnounceRequest,
        peer_addr: CanonicalSocketAddr,
    },
    Scrape {
        request_id: RequestId,
        response_consumer_id: ConsumerId,
        request: ScrapeRequest,
        peer_addr: CanonicalSocketAddr,
    },
}

#[derive(Debug)]
pub enum ChannelResponse {
    Announce {
        request_id: RequestId,
        response: AnnounceResponse,
    },
    Scrape {
        request_id: RequestId,
        response: ScrapeResponse,
    },
}

#[derive(Default, Clone)]
pub struct State {
    pub access_list: Arc<AccessListArcSwap>,
}
