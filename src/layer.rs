use axum::AddExtensionLayer;
use axum_database_sessions::AxumDatabasePool;

/// Used to create and store the Extensions Data.
#[derive(Clone, Debug)]
pub struct AuthSessionLayer {
    pub(crate) poll: Option<AxumDatabasePool>,
    pub(crate) anonymous_user_id: Option<i64>,
}

impl AuthSessionLayer {
    /// Creates a Extension so it can be accessed Directly within Requests.
    pub fn new(
        poll: Option<AxumDatabasePool>,
        anonymous_user_id: Option<i64>,
    ) -> AddExtensionLayer<Self> {
        AddExtensionLayer::new(Self {
            poll,
            anonymous_user_id,
        })
    }
}
