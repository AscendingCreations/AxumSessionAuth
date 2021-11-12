use crate::AuthSessionLayer;
pub use anyhow::Error;
use axum::{
    async_trait,
    extract::{FromRequest, RequestParts},
    http::{self, StatusCode},
};
use axum_sqlx_sessions::SQLxSession;
use sqlx::pool::PoolConnection;

///This is the Session that is generated when a user is routed to a page that Needs one
/// It is used to Save and load session data similar to how it is done on python.
#[derive(Debug, Clone)]
pub struct AuthSession<D> {
    pub current_user: Option<D>,
    pub(crate) session: SQLxSession,
}

#[async_trait]
pub trait Authentication<D> {
    async fn load_user(
        userid: i64,
        pool: Option<&mut PoolConnection<sqlx::Postgres>>,
    ) -> Result<D, Error>;
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
        let session = extensions.get::<SQLxSession>().cloned().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Can't extract SQLxSession. Is `SQLxSessionLayer` enabled?",
        ))?;
        let authlayer = extensions.get::<AuthSessionLayer>().cloned().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Can't extract AuthSessionLayer. Is `AuthSessionLayer` enabled?",
        ))?;

        let current_id = if let Some(id) = session.get::<i64>("user_auth_session_id") {
            Some(id)
        } else {
            authlayer.anonymous_user_id
        };

        let current_user = {
            match current_id {
                None => None,
                Some(uid) => {
                    if let Some(poll) = &authlayer.poll {
                        let mut guard = poll.acquire().await.map_err(|_| {
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Can't extract AuthSessionLayer. Is `AuthSessionLayer` enabled?",
                            )
                        })?;

                        match D::load_user(uid, Some(&mut guard)).await {
                            Ok(user) => Some(user),
                            Err(_) => None,
                        }
                    } else {
                        match D::load_user(uid, None).await {
                            Ok(user) => Some(user),
                            Err(_) => None,
                        }
                    }
                }
            }
        };

        Ok(AuthSession {
            current_user,
            session,
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

    /// Use this to Set the user login into the Session so it can auto login the user on request.
    pub fn login_user(&self, id: i64) {
        let value = self.session.get::<i64>("user_auth_session_id");

        if value != Some(id) {
            self.session.set("user_auth_session_id", id);
        }
    }

    /// Use this to remove the users login. Forcing them to login as anonymous.
    pub fn logout_user(&self) {
        self.session.remove("user_auth_session_id");
    }
}
