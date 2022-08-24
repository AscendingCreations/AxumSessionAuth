#![doc = include_str!("../README.md")]
///This Library Requires that AxumDatabaseSessions is used as an active layer.
///
mod auth;
mod cache;
mod config;
mod layer;
mod service;
mod session;
mod user;

pub use auth::{Auth, HasPermission, Rights};
pub use cache::AuthCache;
pub use config::AxumAuthConfig;
pub use layer::AuthSessionLayer;
pub use service::AuthSessionService;
pub use session::{AuthSession, Authentication};
pub(crate) use user::AuthUser;

pub use axum_database_sessions::databases::*;
