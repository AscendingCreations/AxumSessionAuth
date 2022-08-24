use crate::{AuthUser, Authentication};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fmt,
    hash::Hash,
    marker::{PhantomData, Send, Sync},
    sync::Arc,
};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AuthCache<User, Type, Pool>
where
    User: Authentication<User, Type, Pool> + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
{
    pub(crate) last_expiry_sweep: Arc<RwLock<DateTime<Utc>>>,
    pub(crate) inner: Arc<DashMap<Type, AuthUser<User, Type, Pool>>>,
    pub phantom: PhantomData<Pool>,
}

impl<User, Type, Pool> std::fmt::Debug for AuthCache<User, Type, Pool>
where
    User: Authentication<User, Type, Pool> + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthCache")
            .field("last_expiry_sweep", &self.last_expiry_sweep)
            .finish()
    }
}

impl<User, Type, Pool> AuthCache<User, Type, Pool>
where
    User: Authentication<User, Type, Pool> + Clone + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
{
    pub fn new(last_expiry_sweep: DateTime<Utc>) -> Self {
        Self {
            last_expiry_sweep: Arc::new(RwLock::new(last_expiry_sweep)),
            inner: Arc::new(DashMap::default()),
            phantom: Default::default(),
        }
    }
}
