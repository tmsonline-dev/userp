use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

#[derive(Clone)]
pub struct UnmatchedOAuthToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
    pub provider_name: String,
    pub provider_user_id: String,
    pub provider_user_raw: Value,
}

pub trait OAuthToken: Send + Sync {
    fn get_id(&self) -> Uuid;
    fn get_user_id(&self) -> Uuid;
    fn get_provider_name(&self) -> &str;
    fn get_refresh_token(&self) -> &Option<String>;
}

#[derive(Debug, Clone)]
pub struct OAuthProviderUser {
    pub id: String,
    pub raw: Value,
}
