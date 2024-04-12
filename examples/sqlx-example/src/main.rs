use async_trait::async_trait;
use axum::{http::Method, routing::get, Router};
use axum_session::{SessionConfig, SessionLayer, SessionStore};
use axum_session_auth::*;
use axum_session_sqlx::SessionSqlitePool;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::{collections::HashSet, str::FromStr};
use tokio::net::TcpListener;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: i32,
    pub anonymous: bool,
    pub username: String,
    pub permissions: HashSet<String>,
}

#[derive(sqlx::FromRow, Clone)]
pub struct SqlPermissionTokens {
    pub token: String,
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

#[async_trait]
impl Authentication<User, i64, SqlitePool> for User {
    async fn load_user(userid: i64, pool: Option<&SqlitePool>) -> Result<User, anyhow::Error> {
        let pool = pool.unwrap();

        User::get_user(userid, pool)
            .await
            .ok_or_else(|| anyhow::anyhow!("Could not load user"))
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
impl HasPermission<SqlitePool> for User {
    async fn has(&self, perm: &str, _pool: &Option<&SqlitePool>) -> bool {
        self.permissions.contains(perm)
    }
}

impl User {
    pub async fn get_user(id: i64, pool: &SqlitePool) -> Option<Self> {
        let sqluser = sqlx::query_as::<_, SqlUser>("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .ok()?;

        //lets just get all the tokens the user can use, we will only use the full permissions if modifing them.
        let sql_user_perms = sqlx::query_as::<_, SqlPermissionTokens>(
            "SELECT token FROM user_permissions WHERE user_id = $1;",
        )
        .bind(id)
        .fetch_all(pool)
        .await
        .ok()?;

        Some(sqluser.into_user(Some(sql_user_perms)))
    }

    pub async fn create_user_tables(pool: &SqlitePool) {
        sqlx::query(
            r#"
                CREATE TABLE IF NOT EXISTS users (
                    "id" INTEGER PRIMARY KEY,
                    "anonymous" BOOLEAN NOT NULL,
                    "username" VARCHAR(256) NOT NULL
                )
            "#,
        )
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
                CREATE TABLE IF NOT EXISTS user_permissions (
                    "user_id" INTEGER NOT NULL,
                    "token" VARCHAR(256) NOT NULL
                )
        "#,
        )
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
                INSERT INTO users
                    (id, anonymous, username) SELECT 1, true, 'Guest'
                ON CONFLICT(id) DO UPDATE SET
                    anonymous = EXCLUDED.anonymous,
                    username = EXCLUDED.username
            "#,
        )
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
                INSERT INTO users
                    (id, anonymous, username) SELECT 2, false, 'Test'
                ON CONFLICT(id) DO UPDATE SET
                    anonymous = EXCLUDED.anonymous,
                    username = EXCLUDED.username
            "#,
        )
        .execute(pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
                INSERT INTO user_permissions
                    (user_id, token) SELECT 2, 'Category::View'
            "#,
        )
        .execute(pool)
        .await
        .unwrap();
    }
}

#[derive(sqlx::FromRow, Clone)]
pub struct SqlUser {
    pub id: i32,
    pub anonymous: bool,
    pub username: String,
}

impl SqlUser {
    pub fn into_user(self, sql_user_perms: Option<Vec<SqlPermissionTokens>>) -> User {
        User {
            id: self.id,
            anonymous: self.anonymous,
            username: self.username,
            permissions: if let Some(user_perms) = sql_user_perms {
                user_perms
                    .into_iter()
                    .map(|x| x.token)
                    .collect::<HashSet<String>>()
            } else {
                HashSet::<String>::new()
            },
        }
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

    User::create_user_tables(&pool).await;

    // build our application with some routes
    let app = Router::new()
        .route("/", get(greet))
        .route("/greet", get(greet))
        .route("/login", get(login))
        .route("/perm", get(perm))
        .layer(
            AuthSessionLayer::<User, i64, SessionSqlitePool, SqlitePool>::new(Some(pool))
                .with_config(auth_config),
        )
        .layer(SessionLayer::new(session_store));

    // run it
    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn greet(auth: AuthSession<User, i64, SessionSqlitePool, SqlitePool>) -> String {
    format!(
        "Hello {}, Try logging in via /login or testing permissions via /perm",
        auth.current_user.unwrap().username
    )
}

async fn login(auth: AuthSession<User, i64, SessionSqlitePool, SqlitePool>) -> String {
    auth.login_user(2);
    "You are logged in as a User please try /perm to check permissions".to_owned()
}

async fn perm(
    method: Method,
    auth: AuthSession<User, i64, SessionSqlitePool, SqlitePool>,
) -> String {
    let current_user = auth.current_user.clone().unwrap_or_default();

    //lets check permissions only and not worry about if they are anon or not
    if !Auth::<User, i64, SqlitePool>::build([Method::GET], false)
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
