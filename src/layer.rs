use crate::{AuthSessionService, Authentication};
use axum_database_sessions::AxumDatabasePool;
use std::marker::PhantomData;
use tower_layer::Layer;

/// Layer used to generate an AuthSessionService.
///
#[derive(Clone, Debug)]
pub struct AuthSessionLayer<D> {
    pub(crate) poll: Option<AxumDatabasePool>,
    pub(crate) anonymous_user_id: Option<i64>,
    pub phantom: PhantomData<D>,
}

impl<D> AuthSessionLayer<D>
where
    D: Authentication<D> + Clone + Send,
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
    pub fn new(poll: Option<AxumDatabasePool>, anonymous_user_id: Option<i64>) -> Self {
        Self {
            poll,
            anonymous_user_id,
            phantom: PhantomData::default(),
        }
    }
}

impl<S, D> Layer<S> for AuthSessionLayer<D>
where
    D: Authentication<D> + Clone + Send,
{
    type Service = AuthSessionService<S, D>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthSessionService {
            poll: self.poll.clone(),
            anonymous_user_id: self.anonymous_user_id,
            inner,
            phantom: PhantomData::default(),
        }
    }
}
