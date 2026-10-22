use crate::Authentication;
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt, hash::Hash, marker::PhantomData};
use time::OffsetDateTime;

/// AuthSession that is generated when a user is routed via Axum
///
/// Contains the loaded user data, ID and an AxumSession.
///
#[derive(Debug, Clone)]
pub(crate) struct AuthUser<User, Type, Pool>
where
    User: Authentication<User, Type, Pool> + Send,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
{
    pub current_user: Option<User>,
    pub expires: OffsetDateTime,
    pub phantom_pool: PhantomData<Pool>,
    pub phantom_type: PhantomData<Type>,
}
