#[cfg(feature = "email")]
pub mod email;
#[cfg(feature = "oauth-callbacks")]
pub mod oauth;

use userp_client::models::LoginMethod;
use uuid::Uuid;

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
