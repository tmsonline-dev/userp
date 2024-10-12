use crate::{provider::OAuthProvider, LoginMethod, LoginSession, OAuthToken, UserEmail};
use askama::Template;
use std::sync::Arc;
use uuid::Uuid;

pub struct TemplateLoginSession {
    pub id: Uuid,
    pub method: LoginMethod,
}

impl<T: LoginSession> From<T> for TemplateLoginSession {
    fn from(value: T) -> Self {
        TemplateLoginSession {
            id: value.get_id(),
            method: value.get_method(),
        }
    }
}

pub struct TemplateUserEmail {
    email: String,
    verified: bool,
    allow_link_login: bool,
}

impl<T: UserEmail> From<T> for TemplateUserEmail {
    fn from(value: T) -> Self {
        Self {
            email: value.address(),
            verified: value.verified(),
            allow_link_login: value.allow_link_login(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TemplateOAuthToken {
    pub id: Uuid,
    pub provider_name: String,
}

impl<T: OAuthToken> From<T> for TemplateOAuthToken {
    fn from(value: T) -> Self {
        Self {
            id: value.id(),
            provider_name: value.provider_name(),
        }
    }
}

pub struct TemplateOAuthProvider {
    pub name: String,
    pub display_name: String,
}

impl From<&Arc<dyn OAuthProvider>> for TemplateOAuthProvider {
    fn from(value: &Arc<dyn OAuthProvider>) -> Self {
        Self {
            name: value.name(),
            display_name: value.display_name(),
        }
    }
}

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
    pub message: Option<String>,
    pub error: Option<String>,
    pub sessions: Vec<TemplateLoginSession>,
    pub has_password: bool,
    pub emails: Vec<TemplateUserEmail>,
    pub oauth_tokens: Vec<TemplateOAuthToken>,
    pub oauth_providers: Vec<TemplateOAuthProvider>,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub next: Option<String>,
    pub message: Option<String>,
    pub error: Option<String>,
    pub oauth_providers: Vec<TemplateOAuthProvider>,
}

#[derive(Template)]
#[template(path = "signup.html")]
pub struct SignupTemplate {
    pub next: Option<String>,
    pub message: Option<String>,
    pub error: Option<String>,
    pub oauth_providers: Vec<TemplateOAuthProvider>,
}
