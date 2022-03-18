use axum_core::extract::{FromRequest, RequestParts};
use axum_database_sessions::{AxumDatabasePool, AxumSession};
use chrono::{DateTime, Utc};
use http::{self, StatusCode};

#[derive(Clone, Debug)]
pub struct AuthStore<D> {
    pub(crate) poll: Option<AxumDatabasePool>,
    pub(crate) anonymous_user_id: Option<i64>,
    /// locked Hashmap containing UserID and their session data
    pub inner: Arc<RwLock<HashMap<u64, Mutex<AuthSession<D>>>>>,
    //move this to creation on layer.
    pub last_expiry_sweep: Arc<RwLock<DateTime<Utc>>>,
}
