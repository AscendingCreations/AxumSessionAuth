use crate::{AuthCache, AuthConfig, AuthSessionService, Authentication};
use axum_session::DatabasePool;
use chrono::{Duration, Utc};
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt, hash::Hash, marker::PhantomData};
use tower_layer::Layer;

/// Layer used to generate an AuthSessionService.
///
#[derive(Clone, Debug)]
pub struct AuthSessionLayer<User, Type, Sess, Pool>
where
    User: Authentication<User, Type, Pool> + Clone + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
{
    pub(crate) pool: Option<Pool>,
    pub(crate) config: AuthConfig<Type>,
    pub(crate) cache: AuthCache<User, Type, Pool>,
    pub phantom_user: PhantomData<User>,
    pub phantom_session: PhantomData<Sess>,
    pub phantom_type: PhantomData<Type>,
}

impl<User, Type, Sess, Pool> AuthSessionLayer<User, Type, Sess, Pool>
where
    User: Authentication<User, Type, Pool> + Clone + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
    Sess: DatabasePool + Clone + Sync + Send + 'static,
{
    /// Used to generate an AuthSessionLayer with will call Towers layer() to generate a AuthSessionService.
    ///
    /// contains an Optional axum_session_database Pool for Sqlx database lookups against Right tokens.
    ///
    /// # Examples
    /// ```rust no_run ignore
    ///    let layer = AuthSessionLayer::<User, i64, Sess, Pool>::new(None);
    /// ```
    ///
    pub fn new(pool: Option<Pool>) -> Self {
        Self {
            pool,
            config: AuthConfig::default(),
            cache: AuthCache::<User, Type, Pool>::new(
                Utc::now() + Duration::try_hours(1).unwrap_or_default(),
            ),
            phantom_user: PhantomData,
            phantom_session: PhantomData,
            phantom_type: PhantomData,
        }
    }

    #[must_use]
    pub fn with_config(mut self, config: AuthConfig<Type>) -> Self {
        self.config = config;
        self
    }
}

impl<S, User, Type, Sess, Pool> Layer<S> for AuthSessionLayer<User, Type, Sess, Pool>
where
    User: Authentication<User, Type, Pool> + Clone + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
    Sess: DatabasePool + Clone + fmt::Debug + Sync + Send + 'static,
{
    type Service = AuthSessionService<S, User, Type, Sess, Pool>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthSessionService {
            pool: self.pool.clone(),
            config: self.config.clone(),
            cache: self.cache.clone(),
            inner,
            phantom_session: PhantomData,
        }
    }
}
