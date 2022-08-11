use crate::Authentication;
use chrono::{DateTime, Utc};
use std::{
    fmt,
    marker::PhantomData,
    marker::{Send, Sync},
};
/// AuthSession that is generated when a user is routed via Axum
///
/// Contains the loaded user data, ID and an AxumSession.
///
#[derive(Debug, Clone)]
pub(crate) struct AuthUser<D, Pool>
where
    D: Authentication<D, Pool> + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
{
    pub current_user: Option<D>,
    pub expires: DateTime<Utc>,
    pub phantom: PhantomData<Pool>,
}
