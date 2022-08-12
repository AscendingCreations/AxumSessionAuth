use crate::{AuthCache, AuthSessionService, Authentication, AxumAuthConfig};
use axum_database_sessions::AxumDatabasePool;
use chrono::{Duration, Utc};
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt, hash::Hash, marker::PhantomData};
use tower_layer::Layer;

/// Layer used to generate an AuthSessionService.
///
#[derive(Clone, Debug)]
pub struct AuthSessionLayer<User, Type, Session, Pool>
where
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
{
    pub(crate) pool: Option<Pool>,
    pub(crate) config: AxumAuthConfig<Type>,
    pub phantom_user: PhantomData<User>,
    pub phantom_session: PhantomData<Session>,
    pub phantom_type: PhantomData<Type>,
}

impl<User, Type, Session, Pool> AuthSessionLayer<User, Type, Session, Pool>
where
    User: Authentication<User, Type, Pool> + Clone + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
    Session: AxumDatabasePool + Clone + Sync + Send + 'static,
{
    /// Used to generate an AuthSessionLayer with will call Towers layer() to generate a AuthSessionService.
    ///
    /// contains an Optional axum_session_database Pool for Sqlx database lookups against Right tokens.
    ///
    /// # Examples
    /// ```rust no_run
    ///    let layer = AuthSessionLayer::new(None);
    /// ```
    ///
    pub fn new(pool: Option<Pool>) -> Self {
        Self {
            pool,
            config: AxumAuthConfig::default(),
            phantom_user: PhantomData::default(),
            phantom_session: PhantomData::default(),
            phantom_type: PhantomData::default(),
        }
    }

    #[must_use]
    pub fn with_config(mut self, config: AxumAuthConfig<Type>) -> Self {
        self.config = config;
        self
    }
}

impl<S, User, Type, Session, Pool> Layer<S> for AuthSessionLayer<User, Type, Session, Pool>
where
    User: Authentication<User, Type, Pool> + Clone + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
    Session: AxumDatabasePool + Clone + fmt::Debug + Sync + Send + 'static,
{
    type Service = AuthSessionService<S, User, Type, Session, Pool>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthSessionService {
            pool: self.pool.clone(),
            config: self.config.clone(),
            cache: AuthCache::<User, Type, Pool>::new(Utc::now() + Duration::hours(1)),
            inner,
            phantom_session: PhantomData::default(),
        }
    }
}
