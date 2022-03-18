use crate::AuthSessionLayer;
use anyhow::Error;
use async_trait::async_trait;
use axum_core::extract::{FromRequest, RequestParts};
use axum_database_sessions::{AxumDatabasePool, AxumSession};
use chrono::{DateTime, Utc};
use http::{self, StatusCode};

///This is the AuthSession that is generated when a user is routed to a page that Needs one
/// It is used to load the user from there SqlxSession stored ID.
#[derive(Debug, Clone)]
pub struct AuthSession<D> {
    pub id: u64,
    pub current_user: Option<D>,
    pub(crate) session: AxumSession,
    pub expires: DateTime<Utc>,
}

#[async_trait]
pub trait Authentication<D> {
    async fn load_user(userid: i64, pool: Option<&AxumDatabasePool>) -> Result<D, Error>;
    fn is_authenticated(&self) -> bool;
    fn is_active(&self) -> bool;
    fn is_anonymous(&self) -> bool;
}

/// this gets SQLxSession from the extensions and checks if any Authentication for users Exists
/// If it Exists then it will Load the User use load_user, Otherwise it will return the
/// AuthSession struct with current_user set to None or Guest if the Guest ID was set in AuthSessionLayer.
#[async_trait]
impl<B, D> FromRequest<B> for AuthSession<D>
where
    B: Send,
    D: Authentication<D>,
{
    type Rejection = (http::StatusCode, &'static str);

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let extensions = req.extensions().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Can't extract SQLxSession: extensions has been taken by another extractor",
        ))?;
        let session = extensions.get::<AxumSession>().cloned().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Can't extract SQLxSession. Is `SQLxSessionLayer` enabled?",
        ))?;
        let authlayer = extensions.get::<AuthSessionLayer>().cloned().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Can't extract AuthSessionLayer. Is `AuthSessionLayer` enabled?",
        ))?;

        let current_id = if let Some(id) = session.get::<i64>("user_auth_session_id").await {
            Some(id)
        } else {
            authlayer.anonymous_user_id
        };

        let current_user = {
            match current_id {
                None => None,
                Some(uid) => {
                    if let Some(poll) = &authlayer.poll {
                        D::load_user(uid, Some(poll)).await.ok()
                    } else {
                        D::load_user(uid, None).await.ok()
                    }
                }
            }
        };

        Ok(AuthSession {
            id: 0,
            current_user,
            session,
            expires: Utc::now(),
        })
    }
}

impl<D> AuthSession<D>
where
    D: Authentication<D>,
{
    /// Use this to check if the user is Authenticated
    pub fn is_authenticated(&self) -> bool {
        match &self.current_user {
            Some(n) => n.is_authenticated(),
            None => false,
        }
    }

    /// Use this to check if the user is Active
    pub fn is_active(&self) -> bool {
        match &self.current_user {
            Some(n) => n.is_active(),
            None => false,
        }
    }

    /// Use this to check if the user is Anonymous
    pub fn is_anonymous(&self) -> bool {
        match &self.current_user {
            Some(n) => n.is_anonymous(),
            None => true,
        }
    }

    /// Use this to Set the user id into the Session so it can auto login the user on request.
    pub async fn login_user(&self, id: i64) {
        let value = self.session.get::<i64>("user_auth_session_id").await;

        if value != Some(id) {
            self.session.set("user_auth_session_id", id).await;
        }
    }

    /// Use this to remove the users id from session. Forcing them to login as anonymous.
    pub async fn logout_user(&self) {
        self.session.remove("user_auth_session_id").await;
    }
}
