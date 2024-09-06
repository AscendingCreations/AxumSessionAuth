use async_trait::async_trait;
use axum::{http::Method, routing::get, Router};
use axum_session::{SessionConfig, SessionLayer, SessionStore};
use axum_session_auth::*;
use axum_session_sqlx::SessionSqlitePool;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::sync::Arc;
use std::{collections::HashSet, str::FromStr};
use tokio::net::TcpListener;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i32,
    pub anonymous: bool,
    pub username: String,
    pub permissions: HashSet<String>,
}

impl Default for User {
    fn default() -> Self {
        let mut permissions = HashSet::new();

        permissions.insert("Category::View".to_owned());

        Self {
            id: 1,
            anonymous: true,
            username: "Guest".into(),
            permissions,
        }
    }
}

// We place our Type within a Arc<> so we can send it across async threads.
type NullPool = Arc<Option<()>>;

#[async_trait]
impl Authentication<User, i64, NullPool> for User {
    async fn load_user(userid: i64, _pool: Option<&NullPool>) -> Result<User, anyhow::Error> {
        if userid == 1 {
            Ok(User::default())
        } else {
            let mut permissions = HashSet::new();

            permissions.insert("Category::View".to_owned());

            Ok(User {
                id: 2,
                anonymous: false,
                username: "Test".to_owned(),
                permissions,
            })
        }
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

#[async_trait]
impl HasPermission<NullPool> for User {
    async fn has(&self, perm: &str, _pool: &Option<&NullPool>) -> bool {
        self.permissions.contains(perm)
    }
}

#[tokio::main]
async fn main() {
    let pool = connect_to_database().await;

    //This Defaults as normal Cookies.
    //To enable Private cookies for integrity, and authenticity please check the next Example.
    let session_config = SessionConfig::default().with_table_name("test_table");
    let auth_config = AuthConfig::<i64>::default().with_anonymous_user_id(Some(1));

    // create SessionStore and initiate the database tables
    let session_store =
        SessionStore::<SessionSqlitePool>::new(Some(pool.clone().into()), session_config)
            .await
            .unwrap();

    // We create are NullPool here just for Sessions Auth.
    let nullpool = Arc::new(Option::None);

    // build our application with some routes
    let app = Router::new()
        .route("/", get(greet))
        .route("/greet", get(greet))
        .route("/login", get(login))
        .route("/perm", get(perm))
        .layer(
            AuthSessionLayer::<User, i64, SessionSqlitePool, NullPool>::new(Some(nullpool))
                .with_config(auth_config),
        )
        .layer(SessionLayer::new(session_store));

    // run it
    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn greet(auth: AuthSession<User, i64, SessionSqlitePool, NullPool>) -> String {
    format!(
        "Hello {}, Try logging in via /login or testing permissions via /perm",
        auth.current_user.unwrap().username
    )
}

async fn login(auth: AuthSession<User, i64, SessionSqlitePool, NullPool>) -> String {
    auth.login_user(2);
    "You are logged in as a User please try /perm to check permissions".to_owned()
}

async fn perm(method: Method, auth: AuthSession<User, i64, SessionSqlitePool, NullPool>) -> String {
    let current_user = auth.current_user.clone().unwrap_or_default();

    //lets check permissions only and not worry about if they are anon or not
    if !Auth::<User, i64, NullPool>::build([Method::GET], false)
        .requires(Rights::any([
            Rights::permission("Category::View"),
            Rights::permission("Admin::View"),
        ]))
        .validate(&current_user, &method, None)
        .await
    {
        return format!(
            "User {}, Does not have permissions needed to view this page please login",
            current_user.username
        );
    }

    format!(
        "User has Permissions needed. Here are the Users permissions: {:?}",
        current_user.permissions
    )
}

async fn connect_to_database() -> SqlitePool {
    let connect_opts = SqliteConnectOptions::from_str("sqlite::memory:").unwrap();

    SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(connect_opts)
        .await
        .unwrap()
}
