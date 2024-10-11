use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct IdForm {
    pub id: Uuid,
}

#[derive(Serialize, Deserialize)]
pub struct NewPasswordForm {
    pub new_password: String,
}

#[derive(Serialize, Deserialize)]
pub struct EmailPasswordNextForm {
    pub email: String,
    pub password: String,
    pub next: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailNextForm {
    pub email: String,
    pub next: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct EmailForm {
    pub email: String,
}

#[derive(Serialize, Deserialize)]
pub struct ProviderNextForm {
    pub provider: String,
    pub next: Option<String>,
}
