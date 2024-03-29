#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
///This Library Requires that DatabaseSessions is used as an active layer.
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
pub use config::AuthConfig;
pub use layer::AuthSessionLayer;
pub use service::AuthSessionService;
pub use session::{AuthSession, Authentication};

#[cfg(feature = "advanced")]
pub use session::AuthStatus;

pub(crate) use user::AuthUser;

pub use axum_session::databases::*;
