mod store;

use crate::enums::LoginMethod;
use uuid::Uuid;

pub use store::UserpStore;

pub trait LoginSession: Send + Sync {
    fn get_id(&self) -> Uuid;
    fn get_user_id(&self) -> Uuid;
    fn get_method(&self) -> LoginMethod;
}

pub trait User: Send + Sync {
    fn get_id(&self) -> Uuid;
    #[cfg(feature = "password")]
    fn get_allow_password_login(&self) -> bool;
}

pub trait UserpCookies {
    fn add(&mut self, key: &str, value: &str);
    fn get(&self, key: &str) -> Option<String>;
    fn remove(&mut self, key: &str);
    fn list_encoded(&self) -> Vec<String>;
}
