use crate::{AuthCache, Authentication, AxumAuthConfig};
use axum_database_sessions::AxumDatabasePool;
use chrono::Duration;
use chrono::Utc;
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt, hash::Hash, marker::PhantomData};

#[derive(Clone)]
pub struct AuthManager<User, Type, Session, Pool>
where
    User: Authentication<User, Type, Pool> + Clone + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
    Session: AxumDatabasePool + Clone + fmt::Debug + Sync + Send + 'static,
{
    pub(crate) pool: Option<Pool>,
    pub(crate) config: AxumAuthConfig<Type>,
    pub(crate) cache: AuthCache<User, Type, Pool>,
    pub phantom_session: PhantomData<Session>,
}

impl<User, Type, Session, Pool> AuthManager<User, Type, Session, Pool>
where
    User: Authentication<User, Type, Pool> + Clone + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
    Session: AxumDatabasePool + Clone + fmt::Debug + Sync + Send + 'static,
{
    pub fn new(pool: Option<Pool>, config: AxumAuthConfig<Type>) -> Self {
        Self {
            pool,
            config,
            cache: AuthCache::<User, Type, Pool>::new(Utc::now() + Duration::hours(1)),
            phantom_session: PhantomData::default(),
        }
    }
}

impl<User, Type, Session, Pool> fmt::Debug for AuthManager<User, Type, Session, Pool>
where
    User: Authentication<User, Type, Pool> + Clone + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
    Session: AxumDatabasePool + Clone + fmt::Debug + Sync + Send + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthSessionManager")
            .field("pool", &self.pool)
            .field("config", &self.config)
            .finish()
    }
}
