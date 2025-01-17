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
[`axum_session`]: https://crates.io/crates/axum_session

```toml
# Cargo.toml
[dependencies]
# Postgres + rustls
axum_session_auth = { version = "0.16.0" }
axum_session_sqlx = { version = "0.5.0" }
```

#### Cargo Feature Flags

| Features                      | Description                                                                                    |
| ----------------------------- | ---------------------------------------------------------------------------------------------- |
| `advanced`                    | Enable functions allowing more direct control over the sessions.                               |
| `rest_mode`                   | Disables Cookie Handlering In place of Header only usage for Rest API Requests and Responses.  |
| `key-store`                   | Enabled the optional key storage. Will increase ram usage based on Fastbloom settings.         |


| Database Crate                                                                      | Persistent | Description                                                 |
| ----------------------------------------------------------------------------------- | ---------- | ----------------------------------------------------------- |
| [`axum_session_sqlx`](https://crates.io/crates/axum_session_sqlx)                   | Yes        | Sqlx session store                                          |
| [`axum_session_surreal`](https://crates.io/crates/axum_session_surreal)             | Yes        | Surreal session store                                       |
| [`axum_session_mongo`](https://crates.io/crates/axum_session_mongo)                 | Yes        | Mongo session store                                         |
| [`axum_session_redispool`](https://crates.io/crates/axum_session_redispool)        | Yes        | RedisPool session store                                     |


# Example

```rust
use sqlx::{PgPool, ConnectOptions, postgres::{PgPoolOptions, PgConnectOptions}};
use std::net::SocketAddr;
use axum_session::{Session, SessionConfig, SessionLayer, DatabasePool};
use axum_session_auth::{AuthSession, AuthSessionLayer, Authentication, AuthConfig, HasPermission};
use axum_session_sqlx::SessionPgPool;
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

// We can obtain the method to compare with the methods we allow, which is useful if this supports multiple methods.
// When called, auth is loaded in the background for you.
async fn greet(method: Method, auth: AuthSession<User, i64, SessionPgPool, PgPool>) -> &'static str {
    let mut count: usize = auth.session.get("count").unwrap_or(0);

    // We will get the user if not, then a guest which should be our default.
    let current_user = auth.current_user.clone().unwrap_or_default();
    count += 1;

    // Session is also included with Auth so there's no need to require it in the function arguments if you're using AuthSession.
    auth.session.set("count", count);

    // If, for some reason, you needed to update your user's permissions
    // or data that is cached, then you will want to clear the user cache if it is enabled.
    // The user Cache is enabled by default. To clear, simply use:
    auth.cache_clear_user(1).await;
    // To clear all cached user data for a large update:
    auth.cache_clear_all().await;

    // This is our Auth Permission Builder and Rights Checker. We build it with methods to check for permissions.
    // In this case, if the page is loaded using Method::Get, it will proceed successfully. However, if Method::Post is used, it will fail with the "no Permissions!" error.
    // The boolean value "false" is used to determine whether authentication is required. When set to true, it triggers the function is_authenticated().
    if !Auth::<User, i64, PgPool>::build([Method::Get], false)
        // We prepare which rights we accept or deny from guests or other users.
        .requires(Rights::none([
            Rights::permission("Token::UseAdmin"),
            Rights::permission("Token::ModifyPerms"),
        ]))
        // We then validate the current user and method. We also pass our database along for database permissions checking if required; otherwise, None.
        .validate(&current_user, &method, None)
        .await
    {
        // We return a "No Permissions" message if validation fails for any reason.
        return format!("No Permissions! for {}", current_user.username)[];
    }

    // Since we had the is_authenticated set to false Above we will instead use it to log in our Guest user.
    if !auth.is_authenticated() {
        // Set the user ID of the User to the Session so it can be Auto Loaded the next load or redirect
        auth.login_user(2);
        // Set the session to be long term. Good for Remember me type instances.
        auth.remember_user(true);
        // We don't currently know the username until the next page access.
        // so Normally we would Redirect here after login if we did indeed log in.
        // But in this case we will just let the user know to reload the page for the example.
        "You have Logged in! Please Refresh the page to display the username and counter."
    } else {

        // Upon page reload, if the user possesses all necessary permissions, the method is accurate, and they are logged in,
        // their username and a count that increments with each page refresh will be displayed.
        format!("{}-{}", current_user.username, count)[..]
    };
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
    // This is run when the user has logged in and has not yet been Cached in the system.
    // Once ran it will load and cache the user.
    async fn load_user(userid: i64, _pool: Option<&PgPool>) -> Result<User> {
        Ok(User {
            id: userid,
            anonymous: true,
            username: "Guest".to_string(),
        })
    }

    // This function is used internally to determine if they are logged in or not.
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
