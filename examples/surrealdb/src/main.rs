use async_trait::async_trait;
use axum::{http::Method, routing::get, Router};
use axum_session::{SessionConfig, SessionLayer, SessionStore, SessionSurrealPool};
use axum_session_auth::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tokio::net::TcpListener;

use surrealdb::{
    engine::any::{connect, Any},
    opt::auth::Root,
    Surreal,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub user_id: i32,
    pub anonymous: bool,
    pub username: String,
    #[serde(skip)]
    pub permissions: HashSet<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SqlPermissionTokens {
    pub token: String,
}

impl Default for User {
    fn default() -> Self {
        let mut permissions = HashSet::new();

        permissions.insert("Category::View".to_owned());

        Self {
            user_id: 1,
            anonymous: true,
            username: "Guest".into(),
            permissions,
        }
    }
}

#[async_trait]
impl Authentication<User, i64, Surreal<Any>> for User {
    async fn load_user(userid: i64, pool: Option<&Surreal<Any>>) -> Result<User, anyhow::Error> {
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
impl HasPermission<Surreal<Any>> for User {
    async fn has(&self, perm: &str, _pool: &Option<&Surreal<Any>>) -> bool {
        self.permissions.contains(perm)
    }
}

impl User {
    pub async fn get_user(id: i64, pool: &Surreal<Any>) -> Option<Self> {
        let sqluser: Option<SqlUser> = pool
            .query("SELECT username, user_id, anonymous FROM users where user_id = $user_id")
            .bind(("user_id", id))
            .await
            .unwrap()
            .take(0)
            .unwrap();

        //lets just get all the tokens the user can use, we will only use the full permissions if modifing them.
        let sql_user_perms: Vec<SqlPermissionTokens> = pool
            .query("SELECT token FROM user_permissions where user_id = $user_id")
            .bind(("user_id", id))
            .await
            .unwrap()
            .take(0)
            .unwrap();

        Some(sqluser.unwrap().into_user(Some(sql_user_perms)))
    }

    pub async fn create_user_tables(pool: &Surreal<Any>) {
        pool.query(
            "   DEFINE TABLE users SCHEMAFULL; 
                DEFINE FIELD username ON TABLE users TYPE string;
                DEFINE FIELD anonymous ON TABLE users TYPE bool;
                DEFINE FIELD user_id ON TABLE users TYPE int;
            ",
        )
        .await
        .unwrap();

        pool.query(
            "   DEFINE TABLE user_permissions SCHEMAFULL; 
                DEFINE FIELD token ON TABLE user_permissions TYPE string;
                DEFINE FIELD user_id ON TABLE user_permissions TYPE int;
            ",
        )
        .await
        .unwrap();

        pool.query(
            "INSERT INTO users (username, anonymous, user_id) VALUES ('Guest', true, 1), ('Test', false, 2);"
        ).await.unwrap();

        pool.query("INSERT INTO user_permissions (token, user_id) VALUES  ('Category::View', 2);")
            .await
            .unwrap();
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SqlUser {
    pub user_id: i32,
    pub anonymous: bool,
    pub username: String,
}

impl SqlUser {
    pub fn into_user(self, sql_user_perms: Option<Vec<SqlPermissionTokens>>) -> User {
        User {
            user_id: self.user_id,
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
    let db = connect("ws://localhost:8080").await.unwrap();

    // sign in as our account.
    db.signin(Root {
        username: "root",
        password: "root",
    })
    .await
    .unwrap();

    // Set the database and namespace we will function within.
    db.use_ns("test").use_db("test").await.unwrap();

    //This Defaults as normal Cookies.
    //To enable Private cookies for integrity, and authenticity please check the next Example.
    let session_config = SessionConfig::default().with_table_name("test_table");
    let auth_config = AuthConfig::<i64>::default().with_anonymous_user_id(Some(1));

    // create SessionStore and initiate the database tables
    let session_store: SessionStore<SessionSurrealPool<Any>> =
        SessionStore::new(Some(db.clone().into()), session_config)
            .await
            .unwrap();

    User::create_user_tables(&db).await;

    // build our application with some routes
    let app = Router::new()
        .route("/", get(greet))
        .route("/greet", get(greet))
        .route("/login", get(login))
        .route("/perm", get(perm))
        .layer(
            AuthSessionLayer::<User, i64, SessionSurrealPool<Any>, Surreal<Any>>::new(Some(db))
                .with_config(auth_config),
        )
        .layer(SessionLayer::new(session_store));

    // run it
    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn greet(auth: AuthSession<User, i64, SessionSurrealPool<Any>, Surreal<Any>>) -> String {
    format!(
        "Hello {}, Try logging in via /login or testing permissions via /perm",
        auth.current_user.unwrap().username
    )
}

async fn login(auth: AuthSession<User, i64, SessionSurrealPool<Any>, Surreal<Any>>) -> String {
    auth.login_user(2);
    "You are logged in as a User please try /perm to check permissions".to_owned()
}

async fn perm(
    method: Method,
    auth: AuthSession<User, i64, SessionSurrealPool<Any>, Surreal<Any>>,
) -> String {
    let current_user = auth.current_user.clone().unwrap_or_default();

    //lets check permissions only and not worry about if they are anon or not
    if !Auth::<User, i64, Surreal<Any>>::build([Method::GET], false)
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
