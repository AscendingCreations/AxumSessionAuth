use crate::{AuthUser, Authentication};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use std::{
    fmt,
    marker::{PhantomData, Send, Sync},
    sync::Arc,
};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AuthCache<D, Pool>
where
    D: Authentication<D, Pool> + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
{
    pub(crate) last_expiry_sweep: Arc<RwLock<DateTime<Utc>>>,
    pub(crate) inner: Arc<DashMap<i64, AuthUser<D, Pool>>>,
    pub phantom: PhantomData<Pool>,
}

impl<D, Pool> std::fmt::Debug for AuthCache<D, Pool>
where
    D: Authentication<D, Pool> + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthCache")
            .field("last_expiry_sweep", &self.last_expiry_sweep)
            .finish()
    }
}

impl<D, Pool> AuthCache<D, Pool>
where
    D: Authentication<D, Pool> + Clone + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
{
    pub fn new(last_expiry_sweep: DateTime<Utc>) -> Self {
        Self {
            last_expiry_sweep: Arc::new(RwLock::new(last_expiry_sweep)),
            inner: Arc::new(DashMap::default()),
            phantom: Default::default(),
        }
    }
}
