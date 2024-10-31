use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MyRoutes {
    pub account: String,
    pub log_in: String,
    pub log_out: String,
    pub sign_up: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MyUser {
    pub id: Uuid,
    pub password_hash: Option<String>,
    pub emails: Vec<MyUserEmail>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MyUserEmail {
    pub user_id: Uuid,
    pub email: String,
    pub verified: bool,
    pub allow_link_login: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MyLoginSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub method: String,
    pub oauth_token_id: Option<Uuid>,
    pub email_address: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MyEmailChallenge {
    pub address: String,
    pub code: String,
    pub next: Option<String>,
    pub expires: DateTime<Utc>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[allow(unused)]
pub struct MyOAuthToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider_name: String,
    pub provider_user_id: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
}
