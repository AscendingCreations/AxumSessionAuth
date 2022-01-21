use axum::AddExtensionLayer;
use axum_sqlx_sessions::SqlxDatabasePool;

/// Used to create and store the Extensions Data.
#[derive(Clone, Debug)]
pub struct AuthSessionLayer {
    pub(crate) poll: Option<SqlxDatabasePool>,
    pub(crate) anonymous_user_id: Option<i64>,
}

impl AuthSessionLayer {
    /// Creates a Extension so it can be accessed Directly within Requests.
    pub fn new(poll: Option<SqlxDatabasePool>, anonymous_user_id: Option<i64>) -> AddExtensionLayer<Self> {
        AddExtensionLayer::new(Self {
            poll,
            anonymous_user_id,
        })
    }
}
