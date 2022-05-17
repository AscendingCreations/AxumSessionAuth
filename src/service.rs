use crate::{AuthSession, Authentication};
use axum_core::{
    body::{self, BoxBody},
    response::Response,
    BoxError,
};
use axum_database_sessions::{AxumDatabasePool, AxumSession};
use bytes::Bytes;
use futures::future::BoxFuture;
use http::{self, Request, StatusCode};
use http_body::{Body as HttpBody, Full};
use std::{
    boxed::Box,
    convert::Infallible,
    fmt,
    marker::PhantomData,
    task::{Context, Poll},
};
use tower_service::Service;

#[derive(Clone)]
pub struct AuthSessionService<S, D>
where
    D: Authentication<D> + Send,
{
    pub(crate) poll: Option<AxumDatabasePool>,
    pub(crate) anonymous_user_id: Option<i64>,
    pub(crate) inner: S,
    pub phantom: PhantomData<D>,
}

impl<S, D, ReqBody, ResBody> Service<Request<ReqBody>> for AuthSessionService<S, D>
where
    D: Authentication<D> + Clone + Send + Sync + 'static,
    S: Service<Request<ReqBody>, Response = Response<ResBody>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    Infallible: From<<S as Service<Request<ReqBody>>>::Error>,
    ResBody: HttpBody<Data = Bytes> + Send + 'static,
    ResBody::Error: Into<BoxError>,
{
    type Response = Response<BoxBody>;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let poll = self.poll.clone();
        let anon_id = self.anonymous_user_id;
        let not_ready_inner = self.inner.clone();
        let mut ready_inner = std::mem::replace(&mut self.inner, not_ready_inner);

        Box::pin(async move {
            let axum_session = match req.extensions().get::<AxumSession>().cloned() {
                Some(session) => session,
                None => {
                    return Ok(Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(body::boxed(Full::from("401 Unauthorized")))
                        .unwrap());
                }
            };

            let id = axum_session
                .get::<i64>("user_auth_session_id")
                .await
                .map_or(anon_id, Some)
                .unwrap_or(0);

            let session = AuthSession {
                id: id as u64,
                current_user: if id > 0 {
                    D::load_user(id, poll.as_ref()).await.ok()
                } else {
                    None
                },
                session: axum_session,
            };

            //Sets a clone of the Store in the Extensions for Direct usage and sets the Session for Direct usage
            req.extensions_mut().insert(session.clone());

            Ok(ready_inner.call(req).await?.map(body::boxed))
        })
    }
}

impl<S, D> fmt::Debug for AuthSessionService<S, D>
where
    S: fmt::Debug,
    D: Authentication<D> + fmt::Debug + Clone + Send,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthSessionService")
            .field("poll", &self.poll)
            .field("Anon ID", &self.anonymous_user_id)
            .field("inner", &self.inner)
            .finish()
    }
}
