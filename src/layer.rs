use crate::{AuthSessionService, Authentication};
use axum_database_sessions::AxumDatabasePool;
use std::marker::PhantomData;
use tower_layer::Layer;

/// Layer used to generate an AuthSessionService.
///
#[derive(Clone, Debug)]
pub struct AuthSessionLayer<D, Session, Pool> {
    pub(crate) pool: Option<Pool>,
    pub(crate) anonymous_user_id: Option<i64>,
    pub phantom: PhantomData<D>,
}

impl<D, Session, Pool> AuthSessionLayer<D, Session, Pool>
where
    D: Authentication<D, Pool> + Clone + Send,
    Pool: Clone,
{
    /// Used to generate an AuthSessionLayer with will call Towers layer() to generate a AuthSessionService.
    ///
    /// contains an Optional axum_session_database Pool for Sqlx database lookups against Right tokens.
    ///
    /// # Examples
    /// ```rust no_run
    ///    let layer = AuthSessionLayer::new(None, Some(1));
    /// ```
    ///
    pub fn new(pool: Option<Pool>, anonymous_user_id: Option<i64>) -> Self {
        Self {
            pool,
            anonymous_user_id,
            phantom: PhantomData::default(),
        }
    }
}

impl<S, D, Session, Pool> Layer<S> for AuthSessionLayer<D, Session, Pool>
where
    D: Authentication<D, Pool> + Clone + Send,
    Pool: Clone,
{
    type Service = AuthSessionService<S, D, Session, Pool>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthSessionService {
            pool: self.pool.clone(),
            anonymous_user_id: self.anonymous_user_id,
            inner,
            phantom_user: PhantomData::default(),
            phantom_session: PhantomData::default(),
        }
    }
}
