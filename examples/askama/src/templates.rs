use askama::Template;
use axum_user::OAuthProviderNames;

use crate::{MyLoginSession, MyOAuthToken, MyUserEmail};

#[derive(Template)]
#[template(path = "reset-password.html")]
pub struct ResetPasswordTemplate;

#[derive(Template)]
#[template(path = "send-reset-password.html")]
pub struct SendResetPasswordTemplate {
    pub sent: bool,
    pub address: Option<String>,
    pub error: Option<String>,
    pub message: Option<String>,
}

#[derive(Template)]
#[template(path = "user.html")]
pub struct UserTemplate {
    pub name: String,
    pub message: Option<String>,
    pub error: Option<String>,
    pub sessions: Vec<MyLoginSession>,
    pub has_password: bool,
    pub emails: Vec<MyUserEmail>,
    pub oauth_tokens: Vec<MyOAuthToken>,
    pub oauth_providers: Vec<OAuthProviderNames>,
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
