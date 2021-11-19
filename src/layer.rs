use crate::{AuthSessionManager, Authentication};
use sqlx::postgres::PgPool;
use std::marker::PhantomData;
use tower_layer::Layer;

/// Used to create and store the Extensions Data.
#[derive(Clone, Debug)]
pub struct AuthSessionLayer<D> {
    pub(crate) poll: Option<PgPool>,
    pub(crate) anonymous_user_id: Option<i64>,
    phantom: PhantomData<D>,
}

impl<D> AuthSessionLayer<D>
where
    D: 'static + Sync + Send + Authentication<D>,
{
    /// Creates a Extension so it can be accessed Directly within Requests.
    pub fn new(poll: Option<PgPool>, anonymous_user_id: Option<i64>) -> Self {
        Self {
            poll,
            anonymous_user_id,
            phantom: PhantomData,
        }
    }
}

impl<S, D> Layer<S> for AuthSessionLayer<D>
where
    D: 'static + Sync + Send + Authentication<D>,
{
    type Service = AuthSessionManager<S, D>;

    ///This is called as soon as the session layer is placed within .layer of axum.
    fn layer(&self, service: S) -> Self::Service {
        AuthSessionManager::new(service, self.poll.clone(), self.anonymous_user_id.clone())
    }
}
