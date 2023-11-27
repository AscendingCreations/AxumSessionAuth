use crate::{AuthCache, AuthConfig, AuthSession, AuthUser, Authentication};
use axum_core::{
    body::Body,
    response::{IntoResponse, Response},
    BoxError,
};
use axum_session::{DatabasePool, Session};
use bytes::Bytes;
use chrono::Utc;
use futures::future::BoxFuture;
use http::{self, Request, StatusCode};
use http_body::Body as HttpBody;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    boxed::Box,
    convert::Infallible,
    fmt,
    hash::Hash,
    marker::PhantomData,
    task::{Context, Poll},
};
use tower_service::Service;

#[derive(Clone)]
pub struct AuthSessionService<S, User, Type, Sess, Pool>
where
    User: Authentication<User, Type, Pool> + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
    Sess: DatabasePool + Clone + fmt::Debug + Sync + Send + 'static,
{
    pub(crate) pool: Option<Pool>,
    pub(crate) config: AuthConfig<Type>,
    pub(crate) cache: AuthCache<User, Type, Pool>,
    pub(crate) inner: S,
    pub phantom_session: PhantomData<Sess>,
}

impl<S, User, Type, Sess, Pool, ReqBody, ResBody> Service<Request<ReqBody>>
    for AuthSessionService<S, User, Type, Sess, Pool>
where
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
    Sess: DatabasePool + Clone + fmt::Debug + Sync + Send + 'static,
    User: Authentication<User, Type, Pool> + Clone + Send + Sync + 'static,
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
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let pool = self.pool.clone();
        let config = self.config.clone();
        let cache = self.cache.clone();
        let not_ready_inner = self.inner.clone();
        let mut ready_inner = std::mem::replace(&mut self.inner, not_ready_inner);

        Box::pin(async move {
            let axum_session = match req.extensions().get::<Session<Sess>>().cloned() {
                Some(session) => session,
                None => {
                    return Ok(Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(Body::from("401 Unauthorized"))
                        .unwrap());
                }
            };

            let id = axum_session
                .get::<Type>(&config.session_id)
                .map_or(config.anonymous_user_id.clone(), Some)
                .unwrap_or_else(|| Type::default());

            let current_user = if id != Type::default() {
                if config.cache {
                    if let Some(mut user) = cache.inner.get_mut(&id) {
                        user.expires = Utc::now() + config.max_age;
                        user.current_user.clone()
                    } else {
                        let current_user = User::load_user(id.clone(), pool.as_ref()).await.ok();
                        let user = AuthUser::<User, Type, Pool> {
                            current_user: current_user.clone(),
                            expires: Utc::now() + config.max_age,
                            phantom_pool: Default::default(),
                            phantom_type: Default::default(),
                        };

                        cache.inner.insert(id.clone(), user);
                        current_user
                    }
                } else {
                    User::load_user(id.clone(), pool.as_ref()).await.ok()
                }
            } else {
                None
            };

            // Lets clean up the cache now that we did all our user stuff.
            if config.cache {
                let last_sweep = { *cache.last_expiry_sweep.read().await };

                if last_sweep <= Utc::now() {
                    cache.inner.retain(|_k, v| v.expires > Utc::now());
                    *cache.last_expiry_sweep.write().await = Utc::now() + config.max_age;
                }
            }

            let session = AuthSession {
                id,
                current_user,
                cache,
                session: axum_session,
                pool,
                config,
            };

            // Sets a clone of the Store in the Extensions for Direct usage and sets the Session for Direct usage
            req.extensions_mut().insert(session);

            Ok(ready_inner.call(req).await?.into_response())
        })
    }
}

impl<S, User, Type, Sess, Pool> fmt::Debug for AuthSessionService<S, User, Type, Sess, Pool>
where
    S: fmt::Debug,
    User: Authentication<User, Type, Pool> + fmt::Debug + Clone + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
    Sess: DatabasePool + Clone + fmt::Debug + Sync + Send + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthSessionService")
            .field("pool", &self.pool)
            .field("config", &self.config)
            .field("inner", &self.inner)
            .finish()
    }
}
