<h1 align="center">
 Axum Session Auth
</h1>

Library to Provide a User Authentication and privilege Token Checks. It requires the Axum_Session library.
This library will help by making it so User ID or authorizations are not stored on the Client side but rather on the Server side.
The Authorization is linked by the Clients Serverside Session ID which is stored on the Client side. Formally known as Axum Sessions Auth

[![https://crates.io/crates/axum_session_auth](https://img.shields.io/crates/v/axum_session_auth?style=plastic)](https://crates.io/crates/axum_session_auth)
[![Docs](https://docs.rs/axum_session_auth/badge.svg)](https://docs.rs/axum_session_auth)

- Wraps `axum_session` for data management serverside.
- Right Management API
- Auto load of user Data upon Page loads.
- User Data cache to Avoid Repeated Database calls when not needed.

# Help

If you need help with this library or have suggestions please go to our [Discord Group](https://discord.gg/gVXNDwpS3Z)

## Install

 Sessions Authentication uses [`tokio`] runtime and ['axum_session'];

[`tokio`]: https://github.com/tokio-rs/tokio
[`native-tls`]: https://crates.io/crates/native-tls
[`rustls`]: https://crates.io/crates/rustls
[`sqlx`]: https://crates.io/crates/sqlx
[`axum_session`]: https://crates.io/crates/axum_session

```toml
# Cargo.toml
[dependencies]
# Postgres + rustls
axum_session_auth = { version = "0.1.0", features = [ "postgres-rustls" ] }
```

#### Cargo Feature Flags
`default`: [`postgres-rustls`]

`sqlite-rustls`: `Sqlx` support for the self-contained [SQLite](https://sqlite.org/) database engine and `rustls`.

`sqlite-native`: `Sqlx` support for the self-contained [SQLite](https://sqlite.org/) database engine and `native-tls`.

`postgres-rustls`: `Sqlx` support for the Postgres database server and `rustls`.

`postgres-native`: `Sqlx` support for the Postgres database server and `native-tls`.

`mysql-rustls`: `Sqlx` support for the MySQL/MariaDB database server and `rustls`.

`mysql-native`: `Sqlx` support for the MySQL/MariaDB database server and `native-tls`.

`redis-db`:  `redis 0.21.5` session support.

# Example

```rust
use sqlx::{PgPool, ConnectOptions, postgres::{PgPoolOptions, PgConnectOptions}};
use std::net::SocketAddr;
use axum_session::{SessionPgPool, Session, SessionConfig, SessionLayer, DatabasePool};
use axum_session_auth::{AuthSession, AuthSessionLayer, Authentication, AuthConfig};
use axum::{
    Router,
    routing::get,
};

#[tokio::main]
async fn main() {
    # async {
    let poll = connect_to_database().await.unwrap();

    let session_config = SessionConfig::default()
        .with_database("test")
        .with_table_name("test_table");
    let auth_config = AuthConfig::<i64>::default().with_anonymous_user_id(Some(1));
    let session_store = SessionStore::<SessionPgPool>::new(Some(poll.clone().into()), session_config);

    // Build our application with some routes
    let app = Router::new()
        .route("/greet/:name", get(greet))
        .layer(SessionLayer::new(session_store))
        .layer(AuthSessionLayer::<User, i64, SessionPgPool, PgPool>::new(Some(poll)).with_config(auth_config));

    // Run it
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
    # };
}

// We can get the Method to compare with what Methods we allow. Useful if this supports multiple methods.
// When called auth is loaded in the background for you.
async fn greet(method: Method, auth: AuthSession<User, i64, SessionPgPool, PgPool>) -> &'static str {
    let mut count: usize = session.get("count").unwrap_or(0);
    count += 1;

    // Session is Also included with Auth so no need to require it in the function arguments if your using
    // AuthSession.
    auth.session.set("count", count);

    // If for some reason you needed to update your Users Permissions or data then you will want to clear the user cache if it is enabled.
    // The user Cache is enabled by default. To clear simply use.
    auth.cache_clear_user(1).await;
    //or to clear all for a large update
    auth.cache_clear_all().await;

    if let Some(cur_user) = current_user {
        if !Auth::<User, i64, PgPool>::build([Method::Get], false)
            .requires(Rights::none([
                Rights::permission("Token::UseAdmin"),
                Rights::permission("Token::ModifyPerms"),
            ]))
            .validate(&cur_user, &method, None)
            .await
        {
            return format!("No Permissions! for {}", cur_user.username)[];
        }

        let username = if !auth.is_authenticated() {
            // Set the user ID of the User to the Session so it can be Auto Loaded the next load or redirect
            auth.login_user(2);
            "".to_string()
        } else {
            // If the user is loaded and is Authenticated then we can use it.
            if let Some(user) = auth.current_user {
                user.username.clone()
            } else {
                "".to_string()
            }
        };

        format!("{}-{}", username, count)[..]
    } else {
        if !auth.is_authenticated() {
            // Set the user ID of the User to the Session so it can be Auto Loaded the next load or redirect
            auth.login_user(2);
            // Set the session to be long term. Good for Remember me type instances.
            auth.remember_user(true);
            // Redirect here after login if we did indeed login.
        }

        "No Permissions!"
    }
}

#[derive(Clone, Debug)]
pub struct User {
    pub id: i32,
    pub anonymous: bool,
    pub username: String,
}

// This is only used if you want to use Token based Authentication checks
#[async_trait]
impl HasPermission<PgPool> for User {
    async fn has(&self, perm: &String, _pool: &Option<&PgPool>) -> bool {
        match &perm[..] {
            "Token::UseAdmin" => true,
            "Token::ModifyUser" => true,
            _ => false,
        }
    }
}

#[async_trait]
impl Authentication<User, i64, PgPool> for User {
    async fn load_user(userid: i64, _pool: Option<&PgPool>) -> Result<User> {
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