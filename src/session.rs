use crate::{AuthCache, AuthManager, AuthUser};
use anyhow::Error;
use async_trait::async_trait;
use axum_core::extract::{FromRef, FromRequestParts};
use axum_database_sessions::{AxumDatabasePool, AxumSession, AxumSessionStore};
use chrono::Utc;
use http::{self, request::Parts};
use serde::{de::DeserializeOwned, Serialize};
use std::{convert::Infallible, fmt, hash::Hash, marker::PhantomData};

/// AuthSession that is generated when a user is routed via Axum
///
/// Contains the loaded user data, ID and an AxumSession.
///
#[derive(Debug, Clone)]
pub struct AuthSession<User, Type, Session, Pool>
where
    User: Authentication<User, Type, Pool> + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
    Session: AxumDatabasePool + Clone + fmt::Debug + Sync + Send + 'static,
{
    pub id: Type,
    pub current_user: Option<User>,
    pub session: AxumSession<Session>,
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
impl<S, User, Type, Session, Pool> FromRequestParts<S> for AuthSession<User, Type, Session, Pool>
where
    User: Authentication<User, Type, Pool> + Clone + Send + Sync + 'static,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
    Session: AxumDatabasePool + Clone + fmt::Debug + Sync + Send + 'static,
    S: Send + Sync,
    AxumSessionStore<Session>: FromRef<S>,
    AuthManager<User, Type, Session, Pool>: FromRef<S>,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let axum_session = AxumSession::<Session>::from_request_parts(parts, state).await?;
        let manager = AuthManager::<User, Type, Session, Pool>::from_ref(state);

        let id = axum_session
            .get::<Type>(&manager.config.session_id)
            .await
            .map_or(manager.config.anonymous_user_id, Some)
            .unwrap_or_else(|| Type::default());

        let current_user = if id != Type::default() {
            if manager.config.cache {
                if let Some(mut user) = manager.cache.inner.get_mut(&id) {
                    user.expires = Utc::now() + manager.config.max_age;
                    user.current_user.clone()
                } else {
                    let current_user = User::load_user(id.clone(), manager.pool.as_ref())
                        .await
                        .ok();
                    let user = AuthUser::<User, Type, Pool> {
                        current_user: current_user.clone(),
                        expires: Utc::now() + manager.config.max_age,
                        phantom_pool: Default::default(),
                        phantom_type: Default::default(),
                    };

                    manager.cache.inner.insert(id.clone(), user);
                    current_user
                }
            } else {
                User::load_user(id.clone(), manager.pool.as_ref())
                    .await
                    .ok()
            }
        } else {
            None
        };

        // Lets clean up the cache now that we did all our user stuff.
        if manager.config.cache {
            let last_sweep = { *manager.cache.last_expiry_sweep.read().await };

            if last_sweep <= Utc::now() {
                manager.cache.inner.retain(|_k, v| v.expires > Utc::now());
                *manager.cache.last_expiry_sweep.write().await =
                    Utc::now() + manager.config.max_age;
            }
        }

        Ok(AuthSession {
            id,
            current_user,
            cache: manager.cache.clone(),
            session: axum_session,
            phantom: PhantomData::default(),
        })
    }
}

impl<User, Type, Session, Pool> AuthSession<User, Type, Session, Pool>
where
    User: Authentication<User, Type, Pool> + Clone + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
    Session: AxumDatabasePool + Clone + fmt::Debug + Sync + Send + 'static,
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

    /// Sets the AxumSession Data to be saved for Long Term
    ///
    /// # Examples
    /// ```rust no_run
    ///  auth.remember_user(true).await;
    /// ```
    ///
    pub async fn remember_user(&self, remember_me: bool) {
        self.session.set_longterm(remember_me).await;
    }

    /// Sets the user id into the Session so it can auto login the user upon Axum request.
    ///
    /// # Examples
    /// ```rust no_run
    ///  auth.login_user(user.id).await;
    /// ```
    ///
    pub async fn login_user(&self, id: i64) {
        let value = self.session.get::<i64>("user_auth_session_id").await;

        if value != Some(id) {
            self.session.set("user_auth_session_id", id).await;
        }
    }

    /// Tells the system to clear the user so they get reloaded upon next Axum request.
    ///
    /// # Examples
    /// ```rust no_run
    ///  auth.cache_clear_user(user.id).await;
    /// ```
    ///
    pub async fn cache_clear_user(&self, id: Type) {
        let _ = self.cache.inner.remove(&id);
    }

    /// Emptys the cache to force reload of all users.
    ///
    /// # Examples
    /// ```rust no_run
    ///  auth.cache_clear_all().await;
    /// ```
    ///
    pub async fn cache_clear_all(&self) {
        self.cache.inner.clear();
    }

    /// Removes the user id from the Session preventing the system from auto login unless guest id is set.
    ///
    /// # Examples
    /// ```rust no_run
    ///  auth.logout_user().await;
    /// ```
    ///
    pub async fn logout_user(&self) {
        self.session.remove("user_auth_session_id").await;
    }

    /// runs session Finalize to update the database.
    /// Hoping to remove this if async impl IntoResponse/Parts is implemented for axum.
    /// # Examples
    /// ```rust no_run
    ///  auth.finalize().await;
    /// ```
    ///
    pub async fn finalize(&self) {
        self.session.finalize().await;
    }
}
