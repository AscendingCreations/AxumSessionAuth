use crate::Authentication;
use async_recursion::async_recursion;
use async_trait::async_trait;
use http::Method;
use serde::{de::DeserializeOwned, Serialize};
use std::{fmt, hash::Hash, marker::PhantomData};

/// Trait is used to check their Permissions via Tokens.
///
/// Uses a optional Database for SQL Token Checks too.
///
#[async_trait]
pub trait HasPermission<Pool>
where
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
{
    async fn has(&self, perm: &str, pool: &Option<&Pool>) -> bool;
}

/// Rights enumeration used for building Permissions checks against has() .
///
#[derive(Clone, Default)]
pub enum Rights {
    /// All Rights must Exist
    All(Box<[Rights]>),
    /// Only one Right needs to Exist
    Any(Box<[Rights]>),
    /// Can not contain Any of these Rights
    NoneOf(Box<[Rights]>),
    /// Token to Check for. Recrusivly stores within other Rights.
    Permission(String),
    #[default]
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
    pub async fn evaluate<Pool>(
        &self,
        user: &(dyn HasPermission<Pool> + Sync),
        db: &Option<&Pool>,
    ) -> bool
    where
        Pool: Clone + Send + Sync + fmt::Debug + 'static,
    {
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
/// if !Auth::<User, i64, Pool>::build([Method::POST], true)
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
pub struct Auth<User, Type, Pool>
where
    User: Authentication<User, Type, Pool> + HasPermission<Pool> + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
{
    pub rights: Rights,
    pub auth_required: bool,
    pub methods: Vec<Method>,
    phantom_user: PhantomData<User>,
    phantom_pool: PhantomData<Pool>,
    phantom_type: PhantomData<Type>,
}

impl<User, Type, Pool> Auth<User, Type, Pool>
where
    User: Authentication<User, Type, Pool> + HasPermission<Pool> + Sync + Send,
    Pool: Clone + Send + Sync + fmt::Debug + 'static,
    Type: Eq + Default + Clone + Send + Sync + Hash + Serialize + DeserializeOwned + 'static,
{
    /// Authentication Structure Builder.
    ///
    /// # Examples
    /// ```rust no_run
    /// if !Auth::<User, i64, Pool>::build([Method::POST], true)
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
    pub fn build(
        methods: impl IntoIterator<Item = Method>,
        auth_req: bool,
    ) -> Auth<User, Type, Pool> {
        Auth::<User, Type, Pool> {
            rights: Rights::None,
            auth_required: auth_req,
            methods: methods.into_iter().collect(),
            phantom_user: Default::default(),
            phantom_pool: Default::default(),
            phantom_type: Default::default(),
        }
    }

    /// Adds Rights Requirements for Lookup.
    ///
    /// # Examples
    /// ```rust no_run
    /// if !Auth::<User, i64, Pool>::build([Method::POST], true)
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
    /// if !Auth::<User, i64, Pool>::build([Method::POST], true)
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
    pub async fn validate(&self, user: &User, method: &Method, db: Option<&Pool>) -> bool
    where
        User: HasPermission<Pool> + Authentication<User, Type, Pool>,
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
