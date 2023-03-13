use crate::AuthCache;
use anyhow::Error;
use async_trait::async_trait;
use axum_core::extract::FromRequestParts;
use axum_session::{DatabasePool, Session};
use http::{self, request::Parts, StatusCode};
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt, hash::Hash, marker::PhantomData};

/// AuthSession that is generated when a user is routed via Axum
///
/// Contains the loaded user data, ID and an Session.
///
#[derive(Debug, Clone)]
pub struct AuthSession<User, Type, Sess, Pool>
where
    User: Authentication<User, Type, Pool> + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
    Sess: DatabasePool + Clone + fmt::Debug + Sync + Send + 'static,
{
    pub id: Type,
    pub current_user: Option<User>,
    pub session: Session<Sess>,
    pub(crate) cache: AuthCache<User, Type, Pool>,
    pub phantom: PhantomData<Pool>,
}

#[async_trait]
pub trait Authentication<User, Type, Pool>
where
    User: Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
{
    async fn load_user(userid: Type, pool: Option<&Pool>) -> Result<User, Error>;
    fn is_authenticated(&self) -> bool;
    fn is_active(&self) -> bool;
    fn is_anonymous(&self) -> bool;
}

#[async_trait]
impl<S, User, Type, Sess, Pool> FromRequestParts<S> for AuthSession<User, Type, Sess, Pool>
where
    User: Authentication<User, Type, Pool> + Clone + Send + Sync + 'static,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
    Sess: DatabasePool + Clone + fmt::Debug + Sync + Send + 'static,
    S: Send + Sync,
{
    type Rejection = (http::StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthSession<User, Type, Sess, Pool>>()
            .cloned()
            .ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Can't extract AuthSession. Is `AuthSessionLayer` enabled?",
            ))
    }
}

impl<User, Type, Sess, Pool> AuthSession<User, Type, Sess, Pool>
where
    User: Authentication<User, Type, Pool> + Clone + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
    Sess: DatabasePool + Clone + fmt::Debug + Sync + Send + 'static,
{
    /// Checks if the user is Authenticated
    ///
    /// # Examples
    /// ```rust no_run
    ///  auth.is_authenticated();
    /// ```
    ///
    pub fn is_authenticated(&self) -> bool {
        match &self.current_user {
            Some(n) => n.is_authenticated(),
            None => false,
        }
    }

    /// Checks if the user is Active
    ///
    /// # Examples
    /// ```rust no_run
    ///  auth.is_active();
    /// ```
    ///
    pub fn is_active(&self) -> bool {
        match &self.current_user {
            Some(n) => n.is_active(),
            None => false,
        }
    }

    /// Checks if the user is Anonymous
    ///
    /// # Examples
    /// ```rust no_run
    ///  auth.is_anonymous();
    /// ```
    ///
    pub fn is_anonymous(&self) -> bool {
        match &self.current_user {
            Some(n) => n.is_anonymous(),
            None => true,
        }
    }

    /// Sets the Session Data to be saved for Long Term
    ///
    /// # Examples
    /// ```rust no_run
    ///  auth.remember_user(true);
    /// ```
    ///
    pub fn remember_user(&self, remember_me: bool) {
        self.session.set_longterm(remember_me);
    }

    /// Sets the user id into the Session so it can auto login the user upon Axum request.
    ///
    /// # Examples
    /// ```rust no_run
    ///  auth.login_user(user.id);
    /// ```
    ///
    pub fn login_user(&self, id: Type) {
        self.session.set("user_auth_session_id", id);
        self.session.renew();
    }

    /// Tells the system to clear the user so they get reloaded upon next Axum request.
    ///
    /// # Examples
    /// ```rust no_run
    ///  auth.cache_clear_user(user.id);
    /// ```
    ///
    pub fn cache_clear_user(&self, id: Type) {
        let _ = self.cache.inner.remove(&id);
    }

    /// Emptys the cache to force reload of all users.
    ///
    /// # Examples
    /// ```rust no_run
    ///  auth.cache_clear_all();
    /// ```
    ///
    pub fn cache_clear_all(&self) {
        self.cache.inner.clear();
    }

    /// Removes the user id from the Session preventing the system from auto login unless guest id is set.
    ///
    /// # Examples
    /// ```rust no_run
    ///  auth.logout_user();
    /// ```
    ///
    pub fn logout_user(&self) {
        self.session.remove("user_auth_session_id");
        self.session.renew();
    }
}
