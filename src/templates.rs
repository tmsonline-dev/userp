use askama::Template;
// TODO: add actix-askama
#[cfg(feature = "axum-askama")]
use askama_axum::IntoResponse;
use std::sync::Arc;
use uuid::Uuid;

#[cfg(feature = "email")]
use crate::UserEmail;
#[cfg(feature = "oauth")]
use crate::{provider::OAuthProvider, OAuthToken};
use crate::{Allow, LoginMethod, LoginSession, Routes, Userp, UserpStore};

pub struct TemplateLoginSession {
    pub id: Uuid,
    pub method: LoginMethod,
}

impl<T: LoginSession> From<&T> for TemplateLoginSession {
    fn from(value: &T) -> Self {
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

#[cfg(feature = "email")]
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

#[cfg(feature = "oauth")]
impl<'a, T: OAuthToken> From<&'a T> for TemplateOAuthToken<'a> {
    fn from(value: &'a T) -> Self {
        Self {
            id: value.get_id(),
            provider_name: value.get_provider_name(),
        }
    }
}

pub struct TemplateOAuthProvider<'a> {
    pub name: &'a str,
    pub display_name: &'a str,
}

#[cfg(feature = "oauth")]
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
    pub sessions: Vec<TemplateLoginSession>,
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
    pub show_password: bool,
    pub show_email: bool,
    pub show_oauth: bool,
}

impl LoginTemplate<'_> {
    pub fn response_from<S: UserpStore>(
        auth: &Userp<S>,
        next: Option<&str>,
        message: Option<&str>,
        error: Option<&str>,
    ) -> impl IntoResponse {
        #[cfg(feature = "oauth")]
        let oauth_providers = auth.oauth_login_providers();

        LoginTemplate {
            next,
            message,
            error,
            routes: auth.routes.as_ref().into(),
            #[cfg(feature = "password")]
            show_password: auth.pass.allow_login.as_ref().unwrap_or(&auth.allow_login)
                != &Allow::Never,
            #[cfg(not(feature = "password"))]
            show_password: false,
            #[cfg(feature = "email")]
            show_email: auth.email.allow_login.as_ref().unwrap_or(&auth.allow_login)
                != &Allow::Never,
            #[cfg(not(feature = "email"))]
            show_email: false,
            #[cfg(feature = "oauth")]
            show_oauth: !oauth_providers.is_empty()
                && auth.oauth.allow_login.as_ref().unwrap_or(&auth.allow_login) != &Allow::Never,
            #[cfg(feature = "oauth")]
            oauth_providers: oauth_providers
                .into_iter()
                .map(|p| p.into())
                .collect::<Vec<_>>()
                .as_ref(),
            #[cfg(not(feature = "oauth"))]
            show_oauth: false,
            #[cfg(not(feature = "oauth"))]
            oauth_providers: &vec![],
        }
        .into_response()
    }
}

#[derive(Template)]
#[template(path = "signup.html")]
pub struct SignupTemplate<'a> {
    pub next: Option<&'a str>,
    pub message: Option<&'a str>,
    pub error: Option<&'a str>,
    pub oauth_providers: &'a [TemplateOAuthProvider<'a>],
    pub routes: Routes<&'a str>,
    pub show_password: bool,
    pub show_email: bool,
    pub show_oauth: bool,
}

impl SignupTemplate<'_> {
    pub fn response_from<S: UserpStore>(
        auth: &Userp<S>,
        next: Option<&str>,
        message: Option<&str>,
        error: Option<&str>,
    ) -> impl IntoResponse {
        #[cfg(feature = "oauth")]
        let oauth_providers = auth.oauth_signup_providers();

        SignupTemplate {
            next,
            message,
            error,
            routes: auth.routes.as_ref().into(),
            #[cfg(feature = "password")]
            show_password: auth
                .pass
                .allow_signup
                .as_ref()
                .unwrap_or(&auth.allow_signup)
                != &Allow::Never,
            #[cfg(not(feature = "password"))]
            show_password: false,
            #[cfg(feature = "email")]
            show_email: auth
                .email
                .allow_signup
                .as_ref()
                .unwrap_or(&auth.allow_signup)
                != &Allow::Never,
            #[cfg(not(feature = "email"))]
            show_email: false,
            #[cfg(feature = "oauth")]
            show_oauth: !oauth_providers.is_empty()
                && auth
                    .oauth
                    .allow_signup
                    .as_ref()
                    .unwrap_or(&auth.allow_signup)
                    != &Allow::Never,
            #[cfg(feature = "oauth")]
            oauth_providers: oauth_providers
                .into_iter()
                .map(|p| p.into())
                .collect::<Vec<_>>()
                .as_ref(),
            #[cfg(not(feature = "oauth"))]
            show_oauth: false,
            #[cfg(not(feature = "oauth"))]
            oauth_providers: &vec![],
        }
        .into_response()
    }
}
