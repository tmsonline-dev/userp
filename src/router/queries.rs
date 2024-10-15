use oauth2::{AuthorizationCode, CsrfToken};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct CodeQuery {
    pub code: String,
}

#[derive(Deserialize)]
pub struct NextMessageErrorQuery {
    pub next: Option<String>,
    pub message: Option<String>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct AddressMessageSentErrorQuery {
    pub address: Option<String>,
    pub message: Option<String>,
    pub sent: Option<bool>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct CodeStateQuery {
    pub code: AuthorizationCode,
    pub state: CsrfToken,
}

#[derive(Deserialize)]
pub struct ProviderPath {
    pub provider: String,
}
