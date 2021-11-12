use axum::AddExtensionLayer;
use sqlx::postgres::PgPool;

/// Session layer struct used for starting the Manager when a user comes on board.
#[derive(Clone, Debug)]
pub struct AuthSessionLayer {
    pub(crate) poll: Option<PgPool>,
    pub(crate) anonymous_user_id: Option<i64>,
}

impl AuthSessionLayer {
    /// Creates the SQLx Session Layer.
    pub fn new(poll: Option<PgPool>, anonymous_user_id: Option<i64>) -> AddExtensionLayer<Self> {
        AddExtensionLayer::new(Self {
            poll,
            anonymous_user_id,
        })
    }
}
