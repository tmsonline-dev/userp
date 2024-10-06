use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordLoginForm {
    pub email: String,
    pub password: String,
    pub next: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailLoginForm {
    pub email: String,
    pub next: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailResetForm {
    pub email: String,
    pub next: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct PasswordSignUpForm {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct EmailSignUpForm {
    pub email: String,
}

#[derive(Serialize, Deserialize)]
pub struct EmailVerifyForm {
    pub email: String,
}

#[derive(Serialize, Deserialize)]
pub struct ChangePasswordForm {
    pub new_password: String,
}

#[derive(Serialize, Deserialize)]
pub struct OauthLoginForm {
    pub provider: String,
    pub next: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct OauthSignUpForm {
    pub provider: String,
    pub next: Option<String>,
}
