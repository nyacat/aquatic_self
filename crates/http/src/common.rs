use std::{fs, path::PathBuf, sync::Arc};

use aquatic_common::access_list::AccessListArcSwap;
use aquatic_common::CanonicalSocketAddr;
use arc_swap::{ArcSwap, Cache};

pub use aquatic_common::ValidUntil;

use crate::config::StaticIndexConfig;

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
pub struct StaticIndex {
    body: Arc<[u8]>,
}

impl StaticIndex {
    pub fn create_from_path(path: &PathBuf) -> anyhow::Result<Self> {
        let body = fs::read(path)?;

        Ok(Self { body: body.into() })
    }

    #[cfg(test)]
    pub fn from_bytes(body: &[u8]) -> Self {
        Self { body: body.into() }
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

pub trait StaticIndexUpdate {
    fn update(&self, config: &StaticIndexConfig) -> anyhow::Result<()>;
}

pub type StaticIndexArcSwap = ArcSwap<StaticIndex>;
pub type StaticIndexCache = Cache<Arc<StaticIndexArcSwap>, Arc<StaticIndex>>;

impl StaticIndexUpdate for StaticIndexArcSwap {
    fn update(&self, config: &StaticIndexConfig) -> anyhow::Result<()> {
        self.store(Arc::new(StaticIndex::create_from_path(&config.path)?));

        Ok(())
    }
}

pub fn create_static_index_cache(arc_swap: &Arc<StaticIndexArcSwap>) -> StaticIndexCache {
    Cache::from(Arc::clone(arc_swap))
}

pub fn update_static_index(
    config: &StaticIndexConfig,
    static_index: &Arc<StaticIndexArcSwap>,
) -> anyhow::Result<()> {
    match static_index.update(config) {
        Ok(()) => {
            ::log::info!("Static index updated")
        }
        Err(err) => {
            ::log::error!("Updating static index failed: {:#}", err);

            return Err(err);
        }
    }

    Ok(())
}

#[derive(Default, Clone)]
pub struct State {
    pub access_list: Arc<AccessListArcSwap>,
    pub static_index: Arc<StaticIndexArcSwap>,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn static_index_loads_file_contents() {
        let mut dir = std::env::temp_dir();
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        dir.push(format!("aquatic-http-static-index-test-{suffix}"));

        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("index.html");

        fs::write(&path, b"<!doctype html><title>ok</title>").unwrap();

        let static_index = StaticIndex::create_from_path(&path).unwrap();

        assert_eq!(static_index.body(), b"<!doctype html><title>ok</title>");

        fs::remove_dir_all(dir).unwrap();
    }
}
