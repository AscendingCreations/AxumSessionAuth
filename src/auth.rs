use crate::Authentication;
use async_recursion::async_recursion;
use async_trait::async_trait;
use http::Method;
use axum_database_sessions::AxumDatabasePool;
use std::marker::PhantomData;

///Trait is used to check their Permissions via Tokens. uses a optional Database for SQL Token Checks too.
#[async_trait]
pub trait HasPermission {
    async fn has(&self, perm: &str, pool: &Option<&AxumDatabasePool>) -> bool;
}

///The Type of Rights a user needs will parse through these to check each point.
#[derive(Clone)]
pub enum Rights {
    /// All Rights must Exist
    All(Box<[Rights]>),
    /// Only one Right needs to Exist
    Any(Box<[Rights]>),
    ///Can not contain Any of these Rights
    NoneOf(Box<[Rights]>),
    ///Token to Check for. Recrusivly stores within other Rights.
    Permission(String),
    None,
}

impl Rights {
    pub fn all(data: &[Rights]) -> Rights {
        Rights::All(data.iter().cloned().collect())
    }

    pub fn any(data: &[Rights]) -> Rights {
        Rights::Any(data.iter().cloned().collect())
    }

    pub fn none(data: &[Rights]) -> Rights {
        Rights::NoneOf(data.iter().cloned().collect())
    }

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
            Self::Permission(perm) => user.has(&perm[..], db).await,
            Self::None => false,
        }
    }
}

pub struct Auth<D>
where
    D: Authentication<D> + HasPermission,
{
    pub rights: Rights,
    pub auth_required: bool,
    pub methods: Vec<Method>,
    phantom: PhantomData<D>,
}

impl<D> Auth<D>
where
    D: Authentication<D> + HasPermission + Sync,
{
    pub fn build(methods: &[Method], auth_req: bool) -> Auth<D> {
        Auth::<D> {
            rights: Rights::None,
            auth_required: auth_req,
            methods: methods.to_vec(),
            phantom: PhantomData,
        }
    }

    pub fn requires(&mut self, rights: Rights) -> &mut Self {
        self.rights = rights;
        self
    }

    pub async fn validate(
        &self,
        user: &D,
        method: &Method,
        db: Option<&AxumDatabasePool>,
    ) -> bool
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
