mod link;
mod login;
pub mod provider;
mod refresh;
mod signup;

pub use link::*;
pub use login::*;
pub use refresh::*;
pub use signup::*;

use self::provider::OAuthProvider;
use super::{Allow, AxumUser, AxumUserStore, User};
use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::{DateTime, Utc};
use oauth2::{basic::BasicTokenType, EmptyExtraTokenFields, StandardTokenResponse};
pub use oauth2::{AuthorizationCode, CsrfToken, RedirectUrl, TokenResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{fmt::Display, sync::Arc};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

pub use provider::custom::*;
pub use provider::with_user_callback::*;
pub use provider::*;

const OAUTH_DATA_KEY: &str = "axum-user-state";

#[derive(Clone)]
pub struct OAuthProviderUser {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub email_verified: bool,
}

pub enum RefreshInitResult {
    Redirect(Url),
    Ok,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum OAuthFlow {
    LogIn {
        next: Option<String>,
    },
    SignUp {
        next: Option<String>,
    },
    Link {
        user_id: Uuid,
        next: Option<String>,
    },
    Refresh {
        token_id: Uuid,
        next: Option<String>,
    },
}

impl Display for OAuthFlow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            OAuthFlow::LogIn { .. } => "LogIn",
            OAuthFlow::SignUp { .. } => "SignUp",
            OAuthFlow::Link { .. } => "Link",
            OAuthFlow::Refresh { .. } => "Refresh",
        })
    }
}

#[derive(Clone)]
pub struct OAuthConfig {
    pub allow_login: Option<Allow>,
    pub allow_signup: Option<Allow>,
    pub allow_linking: bool,
    pub login_path: String,
    pub link_path: String,
    pub signup_path: String,
    pub refresh_path: String,
    pub base_url: Url,
    pub providers: OAuthProviders,
}

#[derive(Debug, Clone)]
pub struct OAuthPaths {
    pub login: &'static str,
    pub link: &'static str,
    pub signup: &'static str,
    pub refresh: &'static str,
}

impl OAuthConfig {
    pub fn new(base_url: Url, paths: OAuthPaths) -> Self {
        Self {
            base_url,
            allow_login: None,
            allow_signup: None,
            allow_linking: true,
            login_path: paths.login.to_string(),
            link_path: paths.link.to_string(),
            signup_path: paths.signup.to_string(),
            refresh_path: paths.refresh.to_string(),
            providers: Default::default(),
        }
    }

    pub fn with_client(mut self, client: impl OAuthProvider + 'static) -> Self {
        self.providers.0.push(Arc::new(client));
        self
    }

    pub fn with_allow_signup(mut self, allow_signup: Allow) -> Self {
        self.allow_signup = Some(allow_signup);
        self
    }

    pub fn with_allow_login(mut self, allow_login: Allow) -> Self {
        self.allow_login = Some(allow_login);
        self
    }

    pub fn with_allow_linking(mut self, allow_linking: bool) -> Self {
        self.allow_linking = allow_linking;
        self
    }
}

#[derive(Clone, Default)]
pub struct OAuthProviders(pub(super) Vec<Arc<dyn OAuthProvider>>);

impl OAuthProviders {
    pub fn get(&self, name: &str) -> Option<&Arc<dyn OAuthProvider>> {
        self.0.iter().find(|c| c.name() == name)
    }
}

#[derive(Clone)]
pub struct UnmatchedOAuthToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
    pub provider_name: String,
    pub provider_user: OAuthProviderUser,
}

impl UnmatchedOAuthToken {
    pub fn from_standard_token_response(
        token_response: StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
        provider_name: String,
        provider_user: OAuthProviderUser,
    ) -> Self {
        Self {
            access_token: token_response.access_token().secret().into(),
            refresh_token: token_response.refresh_token().map(|rt| rt.secret().into()),
            expires: token_response.expires_in().map(|d| Utc::now() + d),
            scopes: token_response
                .scopes()
                .map(|scopes| scopes.iter().map(|s| s.to_string()).collect())
                .unwrap_or_default(),
            provider_name,
            provider_user,
        }
    }
}

pub trait OAuthToken: Send + Sync {
    fn id(&self) -> Uuid;
    fn user_id(&self) -> Uuid;
    fn provider_name(&self) -> String;
    fn provider_user_id(&self) -> String;
    fn access_token(&self) -> String;
    fn refresh_token(&self) -> Option<String>;
    fn expires(&self) -> Option<DateTime<Utc>>;
    fn scopes(&self) -> Vec<String>;
}

#[derive(Error, Debug)]
pub enum OAuthCallbackError {
    #[error("No provider found with name: '{0}'")]
    NoProvider(String),
    #[error("No oauth flow & state data cookie found")]
    NoOAuthDataCookie,
    #[error("Misformed OAuthData: {0}")]
    MisformedOAuthData(#[from] serde_json::Error),
    #[error("CSRF tokens didn't match")]
    CsrfMismatch,
    #[error(transparent)]
    ExchangeAuthorizationCodeError(#[from] anyhow::Error),
}

#[derive(Error, Debug)]
pub enum OAuthGenericCallbackError<StoreError: std::error::Error> {
    #[error(transparent)]
    Callback(#[from] OAuthCallbackError),
    #[error(transparent)]
    Signup(#[from] OAuthSignupCallbackError<StoreError>),
    #[error(transparent)]
    Login(#[from] OAuthLoginCallbackError<StoreError>),
    #[error(transparent)]
    Link(#[from] OAuthLinkCallbackError<StoreError>),
    #[error(transparent)]
    Refresh(#[from] OAuthRefreshCallbackError<StoreError>),
}

impl<S: AxumUserStore> AxumUser<S> {
    fn redirect_uri(&self, path: String, provider_name: &str) -> RedirectUrl {
        let path = if path.ends_with('/') {
            path
        } else {
            format!("{path}/")
        };

        RedirectUrl::from_url(
            self.oauth
                .base_url
                .join(path.as_str())
                .unwrap()
                .join(provider_name)
                .unwrap(),
        )
    }

    async fn oauth_init(
        mut self,
        path: String,
        provider: Arc<dyn OAuthProvider>,
        oauth_flow: OAuthFlow,
    ) -> (Self, Url) {
        let (auth_url, csrf_state) = provider.get_authorization_url_and_state(
            self.redirect_uri(path, &provider.name()),
            provider.scopes(),
        );

        self.jar = self.jar.add(
            Cookie::build((OAUTH_DATA_KEY, json!((csrf_state, oauth_flow)).to_string()))
                .path("/")
                .same_site(SameSite::Lax)
                .secure(self.https_only)
                .http_only(true)
                .build(),
        );

        (self, auth_url)
    }

    async fn oauth_callback_inner(
        &self,
        provider_name: String,
        code: AuthorizationCode,
        csrf_token: CsrfToken,
        path: String,
    ) -> Result<(UnmatchedOAuthToken, OAuthFlow, Arc<dyn OAuthProvider>), OAuthCallbackError> {
        let provider = self
            .oauth
            .providers
            .get(&provider_name)
            .ok_or(OAuthCallbackError::NoProvider(provider_name.clone()))?;

        let oauth_data = self
            .jar
            .get(OAUTH_DATA_KEY)
            .ok_or(OAuthCallbackError::NoOAuthDataCookie)?;

        let (prev_csrf_token, oauth_flow) =
            serde_json::from_str::<(CsrfToken, OAuthFlow)>(oauth_data.value())?;

        if csrf_token.secret() != prev_csrf_token.secret() {
            return Err(OAuthCallbackError::CsrfMismatch);
        }

        let unmatched_token = provider
            .exchange_authorization_code(
                provider.name(),
                self.redirect_uri(path, &provider_name),
                code,
            )
            .await?;

        Ok((unmatched_token, oauth_flow, provider.clone()))
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn oauth_generic_callback(
        self,
        provider_name: String,
        code: AuthorizationCode,
        state: CsrfToken,
    ) -> Result<(Self, Option<String>), OAuthGenericCallbackError<S::Error>> {
        let (unmatched_token, flow, provider) = self
            .oauth_callback_inner(
                provider_name.clone(),
                code,
                state,
                self.oauth.signup_path.clone(),
            )
            .await?;

        Ok(match &flow {
            OAuthFlow::LogIn { .. } => {
                self.oauth_login_callback_inner(provider, unmatched_token, flow)
                    .await?
            }
            OAuthFlow::SignUp { .. } => {
                self.oauth_signup_callback_inner(provider, unmatched_token, flow)
                    .await?
            }
            OAuthFlow::Link { .. } => {
                let next = self
                    .oauth_link_callback_inner(provider, unmatched_token, flow)
                    .await?;

                (self, next)
            }
            OAuthFlow::Refresh { .. } => {
                let next = self
                    .oauth_refresh_callback_inner(unmatched_token, flow)
                    .await?;

                (self, next)
            }
        })
    }
}
