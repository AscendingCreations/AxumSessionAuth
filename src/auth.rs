use crate::Authentication;
use async_recursion::async_recursion;
use async_trait::async_trait;
use axum_database_sessions::AxumDatabasePool;
use http::Method;
use std::marker::PhantomData;

/// Trait is used to check their Permissions via Tokens.
///
/// Uses a optional Database for SQL Token Checks too.
///
#[async_trait]
pub trait HasPermission {
    async fn has(&self, perm: &str, pool: &Option<&AxumDatabasePool>) -> bool;
}

/// Rights enumeration used for building Permissions checks against has() .
///
#[derive(Clone)]
pub enum Rights {
    /// All Rights must Exist
    All(Box<[Rights]>),
    /// Only one Right needs to Exist
    Any(Box<[Rights]>),
    /// Can not contain Any of these Rights
    NoneOf(Box<[Rights]>),
    /// Token to Check for. Recrusivly stores within other Rights.
    Permission(String),
    None,
}

impl Rights {
    /// Shortcut Implementation to add Rights check for Rights::All.
    ///
    pub fn all(rights: impl IntoIterator<Item = Rights>) -> Rights {
        Rights::All(rights.into_iter().collect())
    }

    /// Shortcut Implementation to add Rights check for Rights::Any.
    ///
    pub fn any(rights: impl IntoIterator<Item = Rights>) -> Rights {
        Rights::Any(rights.into_iter().collect())
    }

    /// Shortcut Implementation to add Rights check for Rights::NoneOf.
    ///
    pub fn none(rights: impl IntoIterator<Item = Rights>) -> Rights {
        Rights::NoneOf(rights.into_iter().collect())
    }

    /// Shortcut Implementation to add Permission for Rights::Permission.
    ///
    pub fn permission(permission: impl Into<String>) -> Rights {
        Rights::Permission(permission.into())
    }

    /// Evaluates all Rights based on the Rights enumeration patterns.
    ///
    #[async_recursion()]
    pub async fn evaluate(
        &self,
        user: &(dyn HasPermission + Sync),
        db: &Option<&AxumDatabasePool>,
    ) -> bool {
        match self {
            Self::All(rights) => {
                let mut all = true;
                for r in rights.iter() {
                    if !r.evaluate(user, db).await {
                        all = false;
                        break;
                    }
                }

                all
            }
            Self::Any(rights) => {
                let mut all = false;
                for r in rights.iter() {
                    if r.evaluate(user, db).await {
                        all = true;
                        break;
                    }
                }

                all
            }
            Self::NoneOf(rights) => !{
                let mut all = false;
                for r in rights.iter() {
                    if r.evaluate(user, db).await {
                        all = true;
                        break;
                    }
                }

                all
            },
            Self::Permission(perm) => user.has(perm, db).await,
            Self::None => false,
        }
    }
}

/// Authentication Structure.
///
/// All Rights, Methods and Authenticated Checks go thru this.
///
/// # Examples
/// ```rust no_run
/// if !Auth::<User>::build([Method::POST], true)
///     .requires(Rights::all([
///         Rights::permission("admin:view"),
///         Rights::permission("form:editreports"),
///     ]))
///     .validate(&current_user, &state.method, None)
///     .await
/// {
///     return handler_404(state).await.into_response();
/// }
/// ```
///
pub struct Auth<D>
where
    D: Authentication<D> + HasPermission + Send,
{
    pub rights: Rights,
    pub auth_required: bool,
    pub methods: Vec<Method>,
    phantom: PhantomData<D>,
}

impl<D> Auth<D>
where
    D: Authentication<D> + HasPermission + Sync + Send,
{
    /// Authentication Structure Builder.
    ///
    /// # Examples
    /// ```rust no_run
    /// if !Auth::<User>::build([Method::POST], true)
    ///     .requires(Rights::all([
    ///         Rights::permission("admin:view"),
    ///         Rights::permission("form:editreports"),
    ///     ]))
    ///     .validate(&current_user, &state.method, None)
    ///     .await
    /// {
    ///     return handler_404(state).await.into_response();
    /// }
    /// ```
    ///
    pub fn build(methods: impl IntoIterator<Item = Method>, auth_req: bool) -> Auth<D> {
        Auth::<D> {
            rights: Rights::None,
            auth_required: auth_req,
            methods: methods.into_iter().collect(),
            phantom: PhantomData,
        }
    }

    /// Adds Rights Requirements for Lookup.
    ///
    /// # Examples
    /// ```rust no_run
    /// if !Auth::<User>::build([Method::POST], true)
    ///     .requires(Rights::all([
    ///         Rights::permission("admin:view"),
    ///         Rights::permission("form:editreports"),
    ///     ]))
    ///     .validate(&current_user, &state.method, None)
    ///     .await
    /// {
    ///     return handler_404(state).await.into_response();
    /// }
    /// ```
    ///
    pub fn requires(&mut self, rights: Rights) -> &mut Self {
        self.rights = rights;
        self
    }

    /// Validates if the Methods MAtch, Rights Exist or do not and If the user is Authenticated.
    ///
    /// Contains an Optional axum_session_database Pool for User auto loading.
    ///
    /// # Examples
    /// ```rust no_run
    /// if !Auth::<User>::build([Method::POST], true)
    ///     .requires(Rights::all([
    ///         Rights::permission("admin:view"),
    ///         Rights::permission("form:editreports"),
    ///     ]))
    ///     .validate(&current_user, &state.method, None)
    ///     .await
    /// {
    ///     return handler_404(state).await.into_response();
    /// }
    /// ```
    ///
    pub async fn validate(&self, user: &D, method: &Method, db: Option<&AxumDatabasePool>) -> bool
    where
        D: HasPermission + Authentication<D>,
    {
        if self.auth_required && !user.is_authenticated() {
            return false;
        }

        if self.methods.iter().any(|r| r == method) {
            self.rights.evaluate(user, &db).await
        } else {
            false
        }
    }
}
