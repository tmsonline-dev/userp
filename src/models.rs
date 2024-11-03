#[cfg(feature = "client-email")]
pub mod email;
#[cfg(feature = "client-oauth-callbacks")]
pub mod oauth;
pub mod prelude;

use serde::{Deserialize, Serialize};
use std::fmt::Display;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Copy)]
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
    #[cfg(feature = "client-password")]
    fn get_password_hash(&self) -> Option<String>;
}

pub trait UserpCookies {
    fn add(&mut self, key: &str, value: &str);
    fn get(&self, key: &str) -> Option<String>;
    fn remove(&mut self, key: &str);
    fn list_encoded(&self) -> Vec<String>;
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum LoginMethod {
    #[cfg(feature = "client-password")]
    Password,
    #[cfg(all(feature = "client-password", feature = "client-email"))]
    PasswordReset { address: String },
    #[cfg(feature = "client-email")]
    Email { address: String },
    #[cfg(feature = "client-oauth-callbacks")]
    OAuth { token_id: Uuid },
}

impl Display for LoginMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{self:#?}"))
    }
}
