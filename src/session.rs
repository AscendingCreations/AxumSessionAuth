use anyhow::Error;
use async_trait::async_trait;
use axum_core::extract::{FromRequest, RequestParts};
use axum_database_sessions::{AxumDatabasePool, AxumSession};
use http::{self, StatusCode};
use std::marker::PhantomData;

/// AuthSession that is generated when a user is routed via Axum
///
/// Contains the loaded user data, ID and an AxumSession.
///
#[derive(Debug, Clone)]
pub struct AuthSession<D, Session, Pool>
where
    D: Authentication<D> + Send,
    Pool: Clone,
{
    pub id: u64,
    pub current_user: Option<D>,
    pub session: AxumSession<Session>,
    pub phantom: PhantomData<Pool>,
}

#[async_trait]
pub trait Authentication<D, Pool>
where
    D: Send,
    Pool: Clone,
{
    async fn load_user(userid: i64, pool: Option<&Pool>) -> Result<D, Error>;
    fn is_authenticated(&self) -> bool;
    fn is_active(&self) -> bool;
    fn is_anonymous(&self) -> bool;
}

/// this gets SQLxSession from the extensions and checks if any Authentication for users Exists
/// If it Exists then it will Load the User use load_user, Otherwise it will return the
/// AuthSession struct with current_user set to None or Guest if the Guest ID was set in AuthSessionLayer.
#[async_trait]
impl<B, D, Session, Pool> FromRequest<B> for AuthSession<D, Session, Pool>
where
    B: Send,
    D: Authentication<D, Pool> + Clone + Send + Sync + 'static,
    Pool: Clone,
{
    type Rejection = (http::StatusCode, &'static str);
    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let extensions = req.extensions();
        extensions
            .get::<AuthSession<D, Session, Pool>>()
            .cloned()
            .ok_or((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Can't extract AuthSession. Is `AuthSessionLayer` enabled?",
            ))
    }
}

impl<D, Session, Pool> AuthSession<D, Session, Pool>
where
    D: Authentication<D, Pool> + Clone + Send,
    Pool: Clone,
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
}
