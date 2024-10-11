pub mod provider;

use self::provider::OAuthProvider;
use super::{Allow, AxumUser, AxumUserStore, LoginMethod, UserTrait};
use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::{DateTime, Utc};
use oauth2::{basic::BasicTokenType, EmptyExtraTokenFields, StandardTokenResponse};
pub use oauth2::{AuthorizationCode, CsrfToken, RedirectUrl, RefreshToken, TokenResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{fmt::Display, sync::Arc};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

pub use provider::custom::*;
pub use provider::with_user_callback::*;
pub use provider::*;

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

const OAUTH_DATA_KEY: &str = "axum-user-state";

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

pub trait OAuthToken {
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
pub enum OAuthLoginCallbackError {
    #[error(transparent)]
    OAuthCallbackError(#[from] OAuthCallbackError),
    #[error("Failed creating a user or token")]
    UserTokenCreationError,
    #[error("Expected a login flow, got {0}")]
    UnexpectedFlow(OAuthFlow),
    #[error("No matching user found")]
    NoUser,
}

#[derive(Error, Debug)]
pub enum OAuthGenericCallbackError {
    #[error(transparent)]
    Callback(#[from] OAuthCallbackError),
    #[error(transparent)]
    Signup(#[from] OAuthSignupCallbackError),
    #[error(transparent)]
    Login(#[from] OAuthLoginCallbackError),
    #[error(transparent)]
    Link(#[from] OAuthLinkCallbackError),
    #[error(transparent)]
    Refresh(#[from] OAuthRefreshCallbackError),
}

#[derive(Error, Debug)]
pub enum OAuthSignupCallbackError {
    #[error(transparent)]
    OAuthCallbackError(#[from] OAuthCallbackError),
    #[error("No matching user found")]
    NoUser,
    #[error("Expected a login flow, got {0}")]
    UnexpectedFlow(OAuthFlow),
    #[error("Failed creating user or token")]
    UserTokenCreationError,
}

#[derive(Error, Debug)]
pub enum OAuthLinkCallbackError {
    #[error(transparent)]
    OAuthCallbackError(#[from] OAuthCallbackError),
    #[error("Expected a login flow, got {0}")]
    UnexpectedFlow(OAuthFlow),
}

#[derive(Error, Debug)]
pub enum OAuthRefreshCallbackError {
    #[error(transparent)]
    OAuthCallbackError(#[from] OAuthCallbackError),
    #[error("Expected a login flow, got {0}")]
    UnexpectedFlow(OAuthFlow),
    #[error("Previous token not found")]
    TokenNotFound,
}

pub struct OAuthProviderNames {
    pub name: String,
    pub display_name: String,
}

impl From<&Arc<dyn OAuthProvider>> for OAuthProviderNames {
    fn from(value: &Arc<dyn OAuthProvider>) -> Self {
        Self {
            name: value.name(),
            display_name: value.display_name(),
        }
    }
}

#[derive(Debug, Error)]
pub enum OAuthInitError {}

#[derive(Debug, Error)]
pub enum OAuthRefreshInitError {
    #[error("Refresh not allowed")]
    NotAllowed,
    #[error("No provider found with name: {0}")]
    ProviderNotFound(String),
    #[error(transparent)]
    ExchangeError(#[from] anyhow::Error),
    #[error(transparent)]
    OAuthInitError(#[from] OAuthInitError),
}
#[derive(Debug, Error)]
pub enum OAuthLoginInitError {
    #[error("Login not allowed")]
    NotAllowed,
    #[error("No provider found with name: {0}")]
    ProviderNotFound(String),
    #[error(transparent)]
    OAuthInitError(#[from] OAuthInitError),
}
#[derive(Debug, Error)]
pub enum OAuthSignupInitError {
    #[error("Signup not allowed")]
    NotAllowed,
    #[error("No provider found with name: {0}")]
    ProviderNotFound(String),
    #[error(transparent)]
    OAuthInitError(#[from] OAuthInitError),
}
#[derive(Debug, Error)]
pub enum OAuthLinkInitError {
    #[error("Linking not allowed")]
    NotAllowed,
    #[error("No provider found with name: {0}")]
    ProviderNotFound(String),
    #[error("No user found or not logged in")]
    NoUser,
    #[error(transparent)]
    OAuthInitError(#[from] OAuthInitError),
}

impl<S: AxumUserStore> AxumUser<S> {
    pub fn oauth_login_providers(&self) -> Vec<OAuthProviderNames> {
        self.oauth
            .providers
            .0
            .iter()
            .filter_map(|provider| {
                if provider
                    .allow_login()
                    .as_ref()
                    .unwrap_or(self.oauth.allow_login.as_ref().unwrap_or(&self.allow_login))
                    != &Allow::Never
                {
                    Some(provider.into())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn oauth_signup_providers(&self) -> Vec<OAuthProviderNames> {
        self.oauth
            .providers
            .0
            .iter()
            .filter_map(|provider| {
                if provider.allow_signup().as_ref().unwrap_or(
                    self.oauth
                        .allow_signup
                        .as_ref()
                        .unwrap_or(&self.allow_signup),
                ) != &Allow::Never
                {
                    Some(provider.into())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn oauth_link_providers(&self) -> Vec<OAuthProviderNames> {
        self.oauth
            .providers
            .0
            .iter()
            .filter_map(|provider| {
                if provider.allow_linking().unwrap_or(self.oauth.allow_linking) {
                    Some(provider.into())
                } else {
                    None
                }
            })
            .collect()
    }

    pub async fn oauth_refresh_init(
        self,
        token: S::OAuthToken,
        next: Option<String>,
    ) -> Result<(Self, RefreshInitResult), OAuthRefreshInitError> {
        let provider = self
            .oauth
            .providers
            .get(&token.provider_name())
            .ok_or(OAuthRefreshInitError::ProviderNotFound(
                token.provider_name(),
            ))
            .cloned()?;

        if let Some(refresh_token) = token.refresh_token() {
            let res = provider
                .exchange_refresh_token(
                    provider.name(),
                    self.redirect_uri(self.oauth.refresh_path.clone(), &provider.name()),
                    RefreshToken::new(refresh_token),
                )
                .await?;

            let _ = self.store.update_oauth_token(token, res).await;

            Ok((self, RefreshInitResult::Ok))
        } else {
            let path = self.oauth.refresh_path.clone();
            let (new_self, url) = self
                .oauth_init(
                    path,
                    provider,
                    OAuthFlow::Refresh {
                        token_id: token.id(),
                        next,
                    },
                )
                .await?;

            Ok((new_self, RefreshInitResult::Redirect(url)))
        }
    }

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
    ) -> Result<(Self, Url), OAuthInitError> {
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

        Ok((self, auth_url))
    }

    pub async fn oauth_login_init(
        self,
        provider_name: String,
        next: Option<String>,
    ) -> Result<(Self, Url), OAuthLoginInitError> {
        let provider = self
            .oauth
            .providers
            .get(&provider_name)
            .cloned()
            .ok_or(OAuthLoginInitError::ProviderNotFound(provider_name.clone()))?;

        if provider
            .allow_login()
            .as_ref()
            .unwrap_or(self.oauth.allow_login.as_ref().unwrap_or(&self.allow_login))
            == &Allow::Never
        {
            return Err(OAuthLoginInitError::NotAllowed);
        };

        let path = self.oauth.login_path.clone();

        Ok(self
            .oauth_init(path, provider, OAuthFlow::LogIn { next })
            .await?)
    }

    pub async fn oauth_signup_init(
        self,
        provider_name: String,
        next: Option<String>,
    ) -> Result<(Self, Url), OAuthSignupInitError> {
        let provider = self.oauth.providers.get(&provider_name).cloned().ok_or(
            OAuthSignupInitError::ProviderNotFound(provider_name.clone()),
        )?;

        if provider.allow_signup().as_ref().unwrap_or(
            self.oauth
                .allow_signup
                .as_ref()
                .unwrap_or(&self.allow_signup),
        ) == &Allow::Never
        {
            return Err(OAuthSignupInitError::NotAllowed);
        };

        let path = self.oauth.signup_path.clone();

        Ok(self
            .oauth_init(path, provider, OAuthFlow::SignUp { next })
            .await?)
    }

    pub async fn oauth_link_init(
        self,
        provider_name: String,
        next: Option<String>,
    ) -> Result<(Self, Url), OAuthLinkInitError> {
        let user = self.user().await.ok_or(OAuthLinkInitError::NoUser)?;

        let provider = self
            .oauth
            .providers
            .get(&provider_name)
            .cloned()
            .ok_or(OAuthLinkInitError::ProviderNotFound(provider_name.clone()))?;

        if !provider
            .allow_linking()
            .as_ref()
            .unwrap_or(&self.oauth.allow_linking)
        {
            return Err(OAuthLinkInitError::NotAllowed);
        };

        let path = self.oauth.link_path.clone();

        Ok(self
            .oauth_init(
                path,
                provider,
                OAuthFlow::Link {
                    next,
                    user_id: user.get_id(),
                },
            )
            .await?)
    }

    async fn oauth_callback_inner(
        &self,
        provider_name: String,
        code: AuthorizationCode,
        csrf_token: CsrfToken,
        path: String,
    ) -> Result<(UnmatchedOAuthToken, OAuthFlow), OAuthCallbackError> {
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

        Ok((unmatched_token, oauth_flow))
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn oauth_login_callback(
        self,
        provider_name: String,
        code: AuthorizationCode,
        state: CsrfToken,
    ) -> Result<(Self, Option<String>), OAuthLoginCallbackError> {
        let (unmatched_token, flow) = self
            .oauth_callback_inner(
                provider_name.clone(),
                code,
                state,
                self.oauth.login_path.clone(),
            )
            .await?;

        self.oauth_login_callback_inner(provider_name, unmatched_token, flow)
            .await
    }

    async fn oauth_login_callback_inner(
        self,
        provider_name: String,
        unmatched_token: UnmatchedOAuthToken,
        flow: OAuthFlow,
    ) -> Result<(Self, Option<String>), OAuthLoginCallbackError> {
        let OAuthFlow::LogIn { next } = flow else {
            return Err(OAuthLoginCallbackError::UnexpectedFlow(flow));
        };

        let (user, token_id) = match self
            .store
            .get_user_by_oauth_provider_id(
                provider_name.clone(),
                unmatched_token.provider_user.id.clone(),
            )
            .await
        {
            Some((user, old_token)) => {
                let token = self
                    .store
                    .update_oauth_token(old_token, unmatched_token)
                    .await;

                (user, token.id())
            }
            None => {
                if self
                    .oauth
                    .allow_signup
                    .as_ref()
                    .unwrap_or(&self.allow_signup)
                    == &Allow::OnEither
                {
                    let (user, token) = self
                        .store
                        .create_oauth_user(unmatched_token)
                        .await
                        .ok_or(OAuthLoginCallbackError::UserTokenCreationError)?;

                    (user, token.id())
                } else {
                    return Err(OAuthLoginCallbackError::NoUser);
                }
            }
        };

        Ok((
            self.log_in(LoginMethod::OAuth { token_id }, user.get_id())
                .await,
            next,
        ))
    }

    pub async fn oauth_link_callback_inner(
        &self,
        unmatched_token: UnmatchedOAuthToken,
        flow: OAuthFlow,
    ) -> Result<Option<String>, OAuthLinkCallbackError> {
        let OAuthFlow::Link { user_id, next } = flow else {
            return Err(OAuthLinkCallbackError::UnexpectedFlow(flow));
        };

        self.store.link_oauth_token(user_id, unmatched_token).await;

        Ok(next)
    }

    pub async fn oauth_link_callback(
        &self,
        provider_name: String,
        code: AuthorizationCode,
        state: CsrfToken,
    ) -> Result<Option<String>, OAuthLinkCallbackError> {
        let (unmatched_token, flow) = self
            .oauth_callback_inner(
                provider_name.clone(),
                code,
                state,
                self.oauth.link_path.clone(),
            )
            .await?;

        self.oauth_link_callback_inner(unmatched_token, flow).await
    }

    async fn oauth_refresh_callback_inner(
        &self,
        unmatched_token: UnmatchedOAuthToken,
        flow: OAuthFlow,
    ) -> Result<Option<String>, OAuthRefreshCallbackError> {
        let OAuthFlow::Refresh { token_id, next } = flow else {
            return Err(OAuthRefreshCallbackError::UnexpectedFlow(flow));
        };

        let Some(old_token) = self.store.get_oauth_token(token_id).await else {
            return Err(OAuthRefreshCallbackError::TokenNotFound);
        };

        self.store
            .update_oauth_token(old_token, unmatched_token)
            .await;

        Ok(next)
    }

    pub async fn oauth_refresh_callback(
        &self,
        provider_name: String,
        code: AuthorizationCode,
        state: CsrfToken,
    ) -> Result<Option<String>, OAuthRefreshCallbackError> {
        let (unmatched_token, flow) = self
            .oauth_callback_inner(
                provider_name.clone(),
                code,
                state,
                self.oauth.refresh_path.clone(),
            )
            .await?;

        self.oauth_refresh_callback_inner(unmatched_token, flow)
            .await
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn oauth_generic_callback(
        self,
        provider_name: String,
        code: AuthorizationCode,
        state: CsrfToken,
    ) -> Result<(Self, Option<String>), OAuthGenericCallbackError> {
        let (unmatched_token, flow) = self
            .oauth_callback_inner(
                provider_name.clone(),
                code,
                state,
                self.oauth.signup_path.clone(),
            )
            .await?;

        Ok(match &flow {
            OAuthFlow::LogIn { .. } => {
                self.oauth_login_callback_inner(provider_name, unmatched_token, flow)
                    .await?
            }
            OAuthFlow::SignUp { .. } => {
                self.oauth_signup_callback_inner(provider_name, unmatched_token, flow)
                    .await?
            }
            OAuthFlow::Link { .. } => {
                let next = self
                    .oauth_link_callback_inner(unmatched_token, flow)
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

    async fn oauth_signup_callback_inner(
        self,
        provider_name: String,
        unmatched_token: UnmatchedOAuthToken,
        flow: OAuthFlow,
    ) -> Result<(Self, Option<String>), OAuthSignupCallbackError> {
        let OAuthFlow::LogIn { next } = flow else {
            return Err(OAuthSignupCallbackError::UnexpectedFlow(flow));
        };

        let (user, token_id) = match self.store.create_oauth_user(unmatched_token.clone()).await {
            Some((user, token)) => (user, token.id()),
            None => {
                if self
                    .oauth
                    .allow_signup
                    .as_ref()
                    .unwrap_or(&self.allow_signup)
                    == &Allow::OnEither
                {
                    let (user, old_token) = self
                        .store
                        .get_user_by_oauth_provider_id(
                            provider_name.clone(),
                            unmatched_token.provider_user.id.clone(),
                        )
                        .await
                        .ok_or(OAuthSignupCallbackError::NoUser)?;

                    let token = self
                        .store
                        .update_oauth_token(old_token, unmatched_token)
                        .await;

                    (user, token.id())
                } else {
                    return Err(OAuthSignupCallbackError::UserTokenCreationError);
                }
            }
        };

        Ok((
            self.log_in(LoginMethod::OAuth { token_id }, user.get_id())
                .await,
            next,
        ))
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn oauth_signup_callback(
        self,
        provider_name: String,
        code: AuthorizationCode,
        state: CsrfToken,
    ) -> Result<(Self, Option<String>), OAuthSignupCallbackError> {
        let (unmatched_token, flow) = self
            .oauth_callback_inner(
                provider_name.clone(),
                code,
                state,
                self.oauth.signup_path.clone(),
            )
            .await?;

        self.oauth_signup_callback_inner(provider_name, unmatched_token, flow)
            .await
    }
}
