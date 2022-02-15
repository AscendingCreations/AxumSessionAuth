# axum_session_auth

Library to Provide a User Authentication and privilege Token Checks. It requires the Axum_Database_Sessions library and Tower_cookies library.
This library will help by making it so User ID or authorizations are not stored on the Client side but rather on the Server side.
The Authorization is linked by the Clients Serverside Session ID which is stored on the Client side.

You must choose only one of ['postgres', 'mysql', 'sqlite'] features to use this library.

[![https://crates.io/crates/axum_session_auth](https://img.shields.io/badge/crates.io-v0.2.0-blue)](https://crates.io/crates/axum_session_auth)
[![Docs](https://docs.rs/axum_session_auth/badge.svg)](https://docs.rs/axum_session_auth)

# Example

```rust
use sqlx::{ConnectOptions, postgres::{PgPoolOptions, PgConnectOptions}};
use std::net::SocketAddr;
use axum_database_sessions::{AxumSession, AxumSessionConfig, AxumSessionLayer, AxumDatabasePool};
use axum_session_auth::{AuthSession, AuthSessionLayer, Authentication};
use axum::{
    Router,
    routing::get,
};

#[tokio::main]
async fn main() {
    # async {
    let poll = connect_to_database().await.unwrap();

    let session_config = AxumSessionConfig::default()
        .with_database("test")
        .with_table_name("test_table");

    // build our application with some routes
    let app = Router::new()
        .route("/greet/:name", get(greet))
        .layer(tower_cookies::CookieManagerLayer::new())
        .layer(AxumSessionLayer::new(session_config, poll.clone().into()))
        .layer(AuthSessionLayer::new(Some(poll.clone().into()), Some(1)))

    // run it
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
    # };
}

//we can get the Method to compare with what Methods we allow. Useful if thius supports multiple methods.
//When called auth is loaded in the background for you.
async fn greet(method: Method, session: AxumSession, auth: AuthSession<User>) -> &'static str {
    let mut count: usize = session.get("count").unwrap_or(0);
    count += 1;
    session.set("count", count);

    if let Some(cur_user) = current_user {
        if !Auth::<User>::build(&[Method::Get], false)
            .requires(Rights::none(&[
                Rights::Permission("Token::UseAdmin".into()),
                Rights::Permission("Token::ModifyPerms".into()),
            ]))
            .validate(&cur_user, &method, None)
            .await
        {
            return format!("No Permissions! for {}", cur_user.username)[];
        }

        let username = if !auth.is_authenticated() {
            //Set the user ID of the User to the Session so it can be Auto Loaded the next load or redirect
            auth.login_user(2);
            "".to_string()
        } else {
            //if the user is loaded and is Authenticated then we can use it.
            if let Some(user) = auth.current_user {
                user.username.clone()
            } else {
                "".to_string()
            }
        };

        format!("{}-{}", username, count)[..]
    } else {
        if !auth.is_authenticated() {
            //Set the user ID of the User to the Session so it can be Auto Loaded the next load or redirect
            auth.login_user(2);
            //redirect here after login if we did indeed login.
        }

        "No Permissions!"
    }
}

#[derive(Debug)]
pub struct User {
    pub id: i32,
    pub anonymous: bool,
    pub username: String,
}

//This is only used if you want to use Token based Authentication checks
#[async_trait]
impl HasPermission for User {
    async fn has(&self, perm: &String, pool: &Option<&AxumDatabasePool>) -> bool {
        match &perm[..] {
            "Token::UseAdmin" => true,
            "Token::ModifyUser" => true,
            _ => false,
        }
    }
}

#[async_trait]
impl Authentication<User> for User {
    async fn load_user(userid: i64, _pool: Option<&AxumDatabasePool>) -> Result<User> {
        Ok(User {
            id: userid,
            anonymous: true,
            username: "Guest".to_string(),
        })
    }

    fn is_authenticated(&self) -> bool {
        !self.anonymous
    }

    fn is_active(&self) -> bool {
        !self.anonymous
    }

    fn is_anonymous(&self) -> bool {
        self.anonymous
    }
}

async fn connect_to_database() -> anyhow::Result<sqlx::Pool<sqlx::Postgres>> {
    // ...
    # unimplemented!()
}
```
