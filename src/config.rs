use chrono::Duration;
use std::borrow::Cow;

/// Configuration for how the Auth service is used.
///
/// # Examples
/// ```rust
/// use axum_sessions_auth::AxumAuthConfig;
///
/// let config = AxumAuthConfig::default();
/// ```
///
#[derive(Clone)]
pub struct AxumAuthConfig {
    /// Allows caching of Users, Must tell the database to reload user when a change is made when cached.
    pub(crate) cache: bool,
    /// The anonymous user id for logging unlogged users into a default guest like account. ID 0 is None
    pub(crate) anonymous_user_id: Option<i64>,
    /// Session Id for the User ID storage.
    pub(crate) session_id: Cow<'static, str>,
    /// Age the cache is allowed to live for if no visits are made.
    pub(crate) max_age: Duration,
}

impl std::fmt::Debug for AxumAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AxumAuthConfig")
            .field("cache", &self.cache)
            .field("anonymous_user_id", &self.anonymous_user_id)
            .field("session_id", &self.session_id)
            .field("max_age", &self.max_age)
            .finish()
    }
}

impl AxumAuthConfig {
    /// Creates [`Default`] configuration of [`AxumAuthConfig`].
    /// This is equivalent to the [`AxumAuthConfig::default()`].
    #[inline]
    pub fn new() -> Self {
        Default::default()
    }
    /// Sets the auth session to cache the users data for faster reload.
    /// if set to true and you update a users Data you must also trigger
    /// the reload of the user to reload the new changes on their next request.
    ///
    /// # Examples
    /// ```rust
    /// use axum_sessions_auth::AxumAuthConfig;
    ///
    /// let config = AxumAuthConfig::default().set_cache(true);
    /// ```
    ///
    #[must_use]
    pub fn set_cache(mut self, cache: bool) -> Self {
        self.cache = cache;
        self
    }

    /// Set the auto logged in user ID if the user making the request is not logged in yet.
    /// Do not use ID 0 as this stands for the default Return when no user is loaded.
    ///
    /// # Examples
    /// ```rust
    /// use axum_sessions_auth::AxumAuthConfig;
    ///
    /// let config = AxumAuthConfig::default().with_anonymous_user_id(Some(0));
    /// ```
    ///
    #[must_use]
    pub fn with_anonymous_user_id(mut self, id: Option<i64>) -> Self {
        self.anonymous_user_id = id;
        self
    }

    /// Set's the auth session's max_age (expiration time).
    ///
    /// This is used to deturmine how long a User Account is cached per last request
    ///
    /// # Examples
    /// ```rust
    /// use axum_sessions_auth::AxumAuthConfig;
    /// use chrono::Duration;
    ///
    /// let config = AxumAuthConfig::default().with_max_age(Some(Duration::days(2)));
    /// ```
    ///
    #[must_use]
    pub fn with_max_age(mut self, time: Duration) -> Self {
        self.max_age = time;
        self
    }

    /// Set's the auth session's token for session storage.
    ///
    /// # Examples
    /// ```rust
    /// use axum_sessions_auth::AxumAuthConfig;
    ///
    /// let config = AxumAuthConfig::default().with_session_id("www.helpme.com".to_string());
    /// ```
    ///
    #[must_use]
    pub fn with_session_id(mut self, session_id: impl Into<Cow<'static, str>>) -> Self {
        self.session_id = session_id.into();
        self
    }
}

impl Default for AxumAuthConfig {
    fn default() -> Self {
        Self {
            /// Set to a 6 hour default in Database Session stores unloading.
            cache: true,
            session_id: "user_auth_session_id".into(),
            max_age: Duration::hours(6),
            anonymous_user_id: None,
        }
    }
}
