#![doc = include_str!("../README.md")]

mod auth;
///This Library Requires that AxumDatabaseSessions is used as an active layer.
mod layer;
mod service;
mod session;

pub use auth::{Auth, HasPermission, Rights};
pub use layer::AuthSessionLayer;
pub use service::AuthSessionService;
pub use session::{AuthSession, Authentication};
