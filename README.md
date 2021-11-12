# Axum_Sqlx_Sessions

Library to Provide a Postgresql Session management layer. You must also include Tower_cookies in order to use this Library.

[![https://crates.io/crates/axum_sqlx_sessions](https://img.shields.io/badge/crates.io-v0.1.0-blue)](https://crates.io/crates/axum_sqlx_sessions)
[![Docs](https://docs.rs/axum_sqlx_sessions/badge.svg)](https://docs.rs/axum_sqlx_sessions)

# Example

```
pub fn init_pool(config: &ServerConfig) -> anyhow::Result<sqlx::Pool<sqlx::Postgres>> {
    let mut connect_opts = PgConnectOptions::new();
    connect_opts.log_statements(LevelFilter::Debug);
    connect_opts = connect_opts.database(&config.pgsql_database[..]);
    connect_opts = connect_opts.username(&config.pgsql_user[..]);
    connect_opts = connect_opts.password(&config.pgsql_password[..]);
    connect_opts = connect_opts.host(&config.pgsql_host[..]);
    connect_opts = connect_opts.port(config.pgsql_port);

    let pool = block_on(
        PgPoolOptions::new()
            .max_connections(5)
            .connect_with(connect_opts),
    )?;

    Ok(pool)
}

#[tokio::main]
async fn main() {
    // Set the RUST_LOG, if it hasn't been explicitly defined
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "example_templates=debug,tower_http=debug")
    }
    tracing_subscriber::fmt::init();

    let config = //load your config here.
    let poll = init_pool(&config).unwrap();

    let session_config = SqlxSessionConfig::default()
        .with_database("test")
        .with_table_name("test_table");

    // build our application with some routes
    let app = Router::new()
        .route("/greet/:name", get(greet))
        .layer(tower_cookies::CookieManagerLayer::new())
        .layer(SqlxSessionLayer::new(session_config, poll.clone()))

    // run it
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn greet(session: SQLxSession) -> &'static str {
    let mut count: usize = session.get("count").unwrap_or(0);
    count += 1;
    session.set("count", count);

    count.to_string()[..]
}

```
