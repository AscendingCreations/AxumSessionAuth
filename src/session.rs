#[cfg(feature = "advanced")]
use crate::AuthUser;
use crate::{AuthCache, AuthConfig};
use anyhow::Error;
use async_trait::async_trait;
use axum_core::extract::FromRequestParts;
use axum_session::{DatabasePool, Session};
#[cfg(feature = "advanced")]
use chrono::Utc;
use http::{self, request::Parts, StatusCode};
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt, hash::Hash};

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
    #[allow(dead_code)]
    pub(crate) pool: Option<Pool>,
    #[allow(dead_code)]
    pub(crate) config: AuthConfig<Type>,
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
        self.session.set(&self.config.session_id, id);
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
        self.session.remove(&self.config.session_id);
        self.session.renew();
    }

    /// Used to check if a long living AuthSession is still logged in,
    /// if the user logged out or if the user switched account id's during
    /// the last request the AuthSession was created from. This does not check
    /// if the session itself is not the same or reloaded.
    ///
    /// # Examples
    /// ```rust no_run
    ///  auth.is_logged_in();
    /// ```
    ///
    #[cfg(feature = "advanced")]
    pub fn is_logged_in(&mut self) -> AuthStatus {
        if let Some(id) = self.session.get::<Type>(&self.config.session_id) {
            if id == self.id {
                if (self.config.cache && self.cache.inner.contains_key(&self.id))
                    || !self.config.cache
                {
                    AuthStatus::LoggedIn
                } else {
                    AuthStatus::StaleUser
                }
            } else {
                AuthStatus::DifferentID
            }
        } else {
            AuthStatus::LoggedOut
        }
    }

    /// Reloads the user data into current user and cache.
    ///
    /// # Examples
    /// ```rust no_run
    ///  auth.reload_user().await;
    /// ```
    ///
    #[cfg(feature = "advanced")]
    pub async fn reload_user(&mut self) {
        let current_user = User::load_user(self.id.clone(), self.pool.as_ref())
            .await
            .ok();

        if self.config.cache {
            let user = if let Some((_id, mut user)) = self.cache.inner.remove(&self.id) {
                user.expires = Utc::now() + self.config.max_age;
                user.current_user = current_user.clone();
                user
            } else {
                AuthUser::<User, Type, Pool> {
                    current_user: current_user.clone(),
                    expires: Utc::now() + self.config.max_age,
                    phantom_pool: Default::default(),
                    phantom_type: Default::default(),
                }
            };

            self.cache.inner.insert(self.id.clone(), user);
        }

        self.current_user = current_user;
    }

    /// Updates the users expiration time so a request will not
    /// remove them from the cache.
    ///
    /// THIS WILL NOT RELOAD THE USERS DATA
    ///
    /// # Examples
    /// ```rust no_run
    ///  auth.update_user_expiration();
    /// ```
    ///
    #[cfg(feature = "advanced")]
    pub fn update_user_expiration(&mut self) {
        if self.config.cache {
            if let Some(mut user) = self.cache.inner.get_mut(&self.id) {
                user.expires = Utc::now() + self.config.max_age;
            }
        }
    }

    /// Updates the users id to what is currently in the session.
    /// if the session doesnt exist or the id was removed it does nothing.
    ///
    /// THIS WILL NOT RELOAD THE USERS DATA
    ///
    /// # Examples
    /// ```rust no_run
    ///  auth.sync_user_id();
    /// ```
    ///
    #[cfg(feature = "advanced")]
    pub fn sync_user_id(&mut self) {
        if let Some(id) = self.session.get::<Type>(&self.config.session_id) {
            self.id = id.clone();
        }
    }
}

/// Used to display how the users Auth data is compared to what
/// a AuthSessions Data was set as. To ensure nothing changed.
///
/// # Examples
/// ```rust no_run
///  auth.is_logged_in();
/// ```
///
#[cfg(feature = "advanced")]
pub enum AuthStatus {
    /// If the user id did not change and is logged in
    LoggedIn,
    /// If the users id did not match or got changed internally
    /// by another request.
    DifferentID,
    /// the user is logged out.
    LoggedOut,
    /// The user account was removed from cache
    /// so it needs reloading.
    StaleUser,
}
