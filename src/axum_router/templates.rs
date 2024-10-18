use crate::{provider::OAuthProvider, LoginMethod, LoginSession, OAuthToken, Routes, UserEmail};
use askama::Template;
use std::sync::Arc;
use uuid::Uuid;

pub struct TemplateLoginSession<'a> {
    pub id: Uuid,
    pub method: &'a LoginMethod,
}

impl<'a, T: LoginSession> From<&'a T> for TemplateLoginSession<'a> {
    fn from(value: &'a T) -> Self {
        TemplateLoginSession {
            id: value.get_id(),
            method: value.get_method(),
        }
    }
}

pub struct TemplateUserEmail<'a> {
    email: &'a str,
    verified: bool,
    allow_link_login: bool,
}

impl<'a, T: UserEmail> From<&'a T> for TemplateUserEmail<'a> {
    fn from(value: &'a T) -> Self {
        Self {
            email: value.get_address(),
            verified: value.get_verified(),
            allow_link_login: value.get_allow_link_login(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TemplateOAuthToken<'a> {
    pub id: Uuid,
    pub provider_name: &'a str,
}

impl<'a, T: OAuthToken> From<&'a T> for TemplateOAuthToken<'a> {
    fn from(value: &'a T) -> Self {
        Self {
            id: value.id(),
            provider_name: value.provider_name(),
        }
    }
}

pub struct TemplateOAuthProvider<'a> {
    pub name: &'a str,
    pub display_name: &'a str,
}

impl<'a> From<&'a Arc<dyn OAuthProvider>> for TemplateOAuthProvider<'a> {
    fn from(value: &'a Arc<dyn OAuthProvider>) -> Self {
        Self {
            name: value.name(),
            display_name: value.display_name(),
        }
    }
}

#[derive(Template)]
#[template(path = "reset-password.html")]
pub struct ResetPasswordTemplate<'a> {
    pub routes: Routes<&'a str>,
}

#[derive(Template)]
#[template(path = "send-reset-password.html")]
pub struct SendResetPasswordTemplate<'a> {
    pub sent: bool,
    pub address: Option<&'a str>,
    pub error: Option<&'a str>,
    pub message: Option<&'a str>,
    pub routes: Routes<&'a str>,
}

#[derive(Template)]
#[template(path = "user.html")]
pub struct UserTemplate<'a> {
    pub message: Option<&'a str>,
    pub error: Option<&'a str>,
    pub sessions: Vec<TemplateLoginSession<'a>>,
    pub has_password: bool,
    pub emails: Vec<TemplateUserEmail<'a>>,
    pub oauth_tokens: Vec<TemplateOAuthToken<'a>>,
    pub oauth_providers: Vec<TemplateOAuthProvider<'a>>,
    pub routes: Routes<&'a str>,
}

#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate<'a> {
    pub next: Option<&'a str>,
    pub message: Option<&'a str>,
    pub error: Option<&'a str>,
    pub oauth_providers: &'a [TemplateOAuthProvider<'a>],
    pub routes: Routes<&'a str>,
}

#[derive(Template)]
#[template(path = "signup.html")]
pub struct SignupTemplate<'a> {
    pub next: Option<&'a str>,
    pub message: Option<&'a str>,
    pub error: Option<&'a str>,
    pub oauth_providers: &'a [TemplateOAuthProvider<'a>],
    pub routes: Routes<&'a str>,
}
