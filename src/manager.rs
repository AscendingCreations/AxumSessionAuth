use crate::future::ResponseFuture;
use crate::{AuthSession, Authentication};
use axum_sqlx_sessions::SQLxSession;
use futures::executor::block_on;
use http::{Request, Response};
use sqlx::postgres::PgPool;
use std::marker::PhantomData;
use std::task::{Context, Poll};
use tower_service::Service;

///This manages the other services that can be seen in inner and gives access to the SQLxSession.
#[derive(Clone, Debug)]
pub struct AuthSessionManager<S, D> {
    inner: S,
    pub(crate) poll: Option<PgPool>,
    pub(crate) anonymous_user_id: Option<i64>,
    phantom: PhantomData<D>,
}

impl<S, D> AuthSessionManager<S, D>
where
    D: 'static + Sync + Send + Authentication<D>,
{
    /// Create a new Authentication manager.
    pub fn new(inner: S, poll: Option<PgPool>, anonymous_user_id: Option<i64>) -> Self {
        Self {
            inner,
            poll,
            anonymous_user_id,
            phantom: PhantomData,
        }
    }
}

impl<ReqBody, ResBody, S, D> Service<Request<ReqBody>> for AuthSessionManager<S, D>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    D: 'static + Sync + Send + Authentication<D>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    ///lets the system know it is ready for the next step
    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    /// Is called on Request to generate any needed data and sets a future to be used on the Response
    /// This is where we will Generate the AuthSession for the end user
    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let session = req
            .extensions()
            .get::<SQLxSession>()
            .expect("`SQLxSession` extension missing");

        let current_id = if let Some(id) = session.get::<i64>("user_auth_session_id") {
            Some(id)
        } else {
            self.anonymous_user_id
        };

        let current_user = {
            match current_id {
                None => None,
                Some(uid) => {
                    if let Some(poll) = &self.poll {
                        let mut guard =
                            block_on(poll.acquire()).expect("Could not Aquire Database Poll");

                        match block_on(D::load_user(uid, Some(&mut guard))) {
                            Ok(user) => Some(user),
                            Err(_) => None,
                        }
                    } else {
                        match block_on(D::load_user(uid, None)) {
                            Ok(user) => Some(user),
                            Err(_) => None,
                        }
                    }
                }
            }
        };

        let auth = AuthSession {
            current_user,
            session: session.clone(),
        };

        req.extensions_mut().insert(auth);

        ResponseFuture {
            future: self.inner.call(req),
        }
    }
}
