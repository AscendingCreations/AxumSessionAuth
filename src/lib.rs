#![doc = include_str!("../README.md")]
//Todo: Support more databases and expand the Tokio/RLS or RustRLS Selections for SQLx
mod auth;
///This Library Requires that Tower_Cookies and AxumSQLxSessions is used as an active layer.
mod layer;
mod session;

pub use auth::{Auth, HasPermission, Rights};
pub use layer::AuthSessionLayer;
pub use session::{AuthSession, Authentication};
