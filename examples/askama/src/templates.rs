use askama::Template;
use axum_user::{LoginSession, OAuthProviderNames, OAuthToken};

use crate::MyUserEmail;

#[derive(Template)]
#[template(path = "email-verified.html")]
pub struct EmailVerifiedTemplate {
    pub address: String,
}

#[derive(Template)]
#[template(path = "reset-password.html")]
pub struct ResetPasswordTemplate;

#[derive(Template)]
#[template(path = "send-reset-password.html")]
pub struct SendResetPasswordTemplate {
    pub sent: bool,
    pub address: Option<String>,
}

#[derive(Template)]
#[template(path = "user.html")]
pub struct UserTemplate {
    pub name: String,
    pub message: Option<String>,
    pub error: Option<String>,
    pub sessions: Vec<LoginSession>,
    pub has_password: bool,
    pub emails: Vec<MyUserEmail>,
    pub oauth_tokens: Vec<OAuthToken>,
    pub oauth_providers: Vec<OAuthProviderNames>,
}

#[derive(Template)]
#[template(path = "email-sent.html")]
pub struct EmailSentTemplate {
    pub address: String,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub next: Option<String>,
    pub message: Option<String>,
    pub error: Option<String>,
    pub oauth_providers: Vec<OAuthProviderNames>,
}

#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {
    pub name: Option<String>,
}

#[derive(Template)]
#[template(path = "signup.html")]
pub struct SignupTemplate {
    pub next: Option<String>,
    pub message: Option<String>,
    pub error: Option<String>,
    pub oauth_providers: Vec<OAuthProviderNames>,
}
