use crate::{AuthCache, AuthSessionService, Authentication, AxumAuthConfig};
use axum_database_sessions::AxumDatabasePool;
use chrono::{Duration, Utc};
use std::fmt;
use std::marker::PhantomData;
use tower_layer::Layer;

/// Layer used to generate an AuthSessionService.
///
#[derive(Clone, Debug)]
pub struct AuthSessionLayer<D, Session, Pool> {
    pub(crate) pool: Option<Pool>,
    pub(crate) config: AxumAuthConfig,
    pub phantom_user: PhantomData<D>,
    pub phantom_session: PhantomData<Session>,
}

impl<D, Session, Pool> AuthSessionLayer<D, Session, Pool>
where
    D: Authentication<D, Pool> + Clone + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
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
        }
    }

    #[must_use]
    pub fn with_config(mut self, config: AxumAuthConfig) -> Self {
        self.config = config;
        self
    }
}

impl<S, D, Session, Pool> Layer<S> for AuthSessionLayer<D, Session, Pool>
where
    D: Authentication<D, Pool> + Clone + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Session: AxumDatabasePool + Clone + fmt::Debug + Sync + Send + 'static,
{
    type Service = AuthSessionService<S, D, Session, Pool>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthSessionService {
            pool: self.pool.clone(),
            config: self.config.clone(),
            cache: AuthCache::<D, Pool>::new(Utc::now() + Duration::hours(1)),
            inner,
            phantom_session: PhantomData::default(),
        }
    }
}
