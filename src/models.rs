#[cfg(feature = "email")]
pub(crate) mod email;
#[cfg(feature = "oauth")]
pub(crate) mod oauth;
pub(crate) mod prelude;

use std::fmt::Display;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum Allow {
    Never,
    OnSelf,
    OnEither,
}

pub trait LoginSession: Send + Sync + Sized {
    fn get_id(&self) -> Uuid;
    fn get_user_id(&self) -> Uuid;
    fn get_method(&self) -> LoginMethod;
}

pub trait User: Send + Sync + Sized {
    fn get_id(&self) -> Uuid;
    #[cfg(feature = "password")]
    fn get_password_hash(&self) -> Option<String>;
}

pub trait UserpCookies {
    fn add(&mut self, key: &str, value: &str);
    fn get(&self, key: &str) -> Option<String>;
    fn remove(&mut self, key: &str);
    fn list_encoded(&self) -> Vec<String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginMethod {
    #[cfg(feature = "password")]
    Password,
    #[cfg(all(feature = "password", feature = "email"))]
    PasswordReset { address: String },
    #[cfg(feature = "email")]
    Email { address: String },
    #[cfg(feature = "oauth")]
    OAuth { token_id: Uuid },
}

impl Display for LoginMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{self:#?}"))
    }
}
