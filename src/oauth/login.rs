use super::provider::OAuthProvider;
use super::{Allow, AxumUser, AxumUserStore, OAuthCallbackError, OAuthFlow};
use crate::{LoginMethod, OAuthToken, UnmatchedOAuthToken, User};
pub use oauth2::{AuthorizationCode, CsrfToken};
use std::sync::Arc;
use thiserror::Error;
use url::Url;

#[derive(Error, Debug)]
pub enum OAuthLoginError<StoreError: std::error::Error> {
    #[error("OAuth signup not allowed")]
    NotAllowed,
    #[error("No user found")]
    NoUser,
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[derive(Error, Debug)]
pub enum OAuthLoginCallbackError<StoreError: std::error::Error> {
    #[error(transparent)]
    OAuthCallbackError(#[from] OAuthCallbackError),
    #[error("Expected a login flow, got {0}")]
    UnexpectedFlow(OAuthFlow),
    #[error(transparent)]
    Login(#[from] OAuthLoginError<StoreError>),
    #[error(transparent)]
    Store(StoreError),
}

#[derive(Debug, Error)]
pub enum OAuthLoginInitError {
    #[error("Login not allowed")]
    NotAllowed,
    #[error("No provider found with name: {0}")]
    ProviderNotFound(String),
}

#[derive(Error, Debug)]
pub enum OAuthLinkCallbackError<StoreError: std::error::Error> {
    #[error(transparent)]
    OAuthCallbackError(#[from] OAuthCallbackError),
    #[error("Linking not allowed")]
    NotAllowed,
    #[error("Expected a login flow, got {0}")]
    UnexpectedFlow(OAuthFlow),
    #[error(transparent)]
    Store(StoreError),
}

impl<S: AxumUserStore> AxumUser<S> {
    pub fn oauth_login_providers(&self) -> Vec<&Arc<dyn OAuthProvider>> {
        self.oauth
            .providers
            .0
            .iter()
            .filter(|provider| {
                provider
                    .allow_login()
                    .as_ref()
                    .unwrap_or(self.oauth.allow_login.as_ref().unwrap_or(&self.allow_login))
                    != &Allow::Never
            })
            .collect()
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
            .await)
    }

    pub(crate) async fn oauth_login_callback_inner(
        self,
        provider: Arc<dyn OAuthProvider>,
        unmatched_token: UnmatchedOAuthToken,
        flow: OAuthFlow,
    ) -> Result<(Self, Option<String>), OAuthLoginCallbackError<S::Error>> {
        let OAuthFlow::LogIn { next } = flow else {
            return Err(OAuthLoginCallbackError::UnexpectedFlow(flow));
        };

        let (user, token) = self
            .store
            .oauth_login(
                unmatched_token,
                provider.allow_signup().as_ref().unwrap_or(
                    self.oauth
                        .allow_signup
                        .as_ref()
                        .unwrap_or(&self.allow_signup),
                ) == &Allow::OnEither,
            )
            .await?;

        Ok((
            self.log_in(
                LoginMethod::OAuth {
                    token_id: token.id(),
                },
                user.get_id(),
            )
            .await
            .map_err(OAuthLoginCallbackError::Store)?,
            next,
        ))
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn oauth_login_callback(
        self,
        provider_name: String,
        code: AuthorizationCode,
        state: CsrfToken,
    ) -> Result<(Self, Option<String>), OAuthLoginCallbackError<S::Error>> {
        let (unmatched_token, flow, provider) = self
            .oauth_callback_inner(
                provider_name.clone(),
                code,
                state,
                self.oauth.login_path.clone(),
            )
            .await?;

        self.oauth_login_callback_inner(provider, unmatched_token, flow)
            .await
    }
}
