use askama::Template;
use axum_user::{LoginSession, OAuthToken};

use crate::MyUserEmail;

#[derive(Template)]
#[template(path = "user.html")]
pub struct UserTemplate {
    pub name: String,
    pub message: Option<String>,
    pub error: Option<String>,
    pub sessions: Vec<LoginSession>,
    pub password: bool,
    pub emails: Vec<MyUserEmail>,
    pub oauth_tokens: Vec<OAuthToken>,
}

#[derive(Template)]
#[template(path = "email-sent.html")]
pub struct EmailSentTemplate {
    pub address: String,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub message: Option<String>,
    pub next: Option<String>,
}

#[derive(Template)]
#[template(path = "index.html")]
pub struct IndexTemplate {
    pub name: Option<String>,
}

#[derive(Template)]
#[template(path = "signup.html")]
pub struct SignupTemplate {
    pub error: Option<String>,
}
