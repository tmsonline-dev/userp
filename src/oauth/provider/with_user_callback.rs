use std::{future::Future, sync::Arc};

use super::{ExchangeResult, OAuthProvider, OAuthProviderBase};
use crate::{
    oauth::{OAuthProviderUser, UnmatchedOAuthToken},
    Allow,
};
use anyhow::Context;
use axum::async_trait;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthorizationCode, CsrfToken, RedirectUrl,
    RefreshToken, Scope, TokenResponse,
};
use url::Url;

pub type OAuthProviderUserResult = anyhow::Result<OAuthProviderUser>;

pub trait OAuthProviderBaseWithBasicClient: OAuthProviderBase + Send + Sync {
    fn get_oauth2_client(&self) -> BasicClient;
}

pub struct OAuthProviderBaseWithUserCallback<'a> {
    inner: Box<dyn OAuthProviderBaseWithBasicClient + 'a>,
    get_user: Box<dyn Fn(String) -> OAuthProviderUserResult + Send + Sync + 'a>,
    allow_signup: Option<Allow>,
    allow_login: Option<Allow>,
    allow_linking: Option<bool>,
}

impl<'a> OAuthProviderBaseWithUserCallback<'a> {
    pub fn new<Fut, F>(
        client: Box<dyn OAuthProviderBaseWithBasicClient + 'a>,
        ext_get_user: Arc<F>,
    ) -> Self
    where
        Fut: Future<Output = OAuthProviderUserResult> + Send + 'a,
        F: Fn(String) -> Fut + Send + Sync + 'a,
    {
        let get_user = Box::new(move |access_token: String| {
            let ext_get_user = ext_get_user.clone();
            let access_token = access_token.clone();

            tokio::task::block_in_place(move || {
                let access_token = access_token.clone();
                tokio::runtime::Handle::current()
                    .block_on(async move { ext_get_user(access_token).await })
            })
        });

        Self {
            get_user,
            allow_signup: client.allow_signup(),
            allow_login: client.allow_login(),
            allow_linking: client.allow_linking(),
            inner: client,
        }
    }

    pub fn with_allow_signup(mut self, allow_signup: Option<Allow>) -> Self {
        self.allow_signup = allow_signup;
        self
    }

    pub fn with_allow_login(mut self, allow_login: Option<Allow>) -> Self {
        self.allow_login = allow_login;
        self
    }

    pub fn with_allow_linking(mut self, allow_linking: Option<bool>) -> Self {
        self.allow_linking = allow_linking;
        self
    }
}

impl OAuthProviderBase for OAuthProviderBaseWithUserCallback<'_> {
    fn name(&self) -> String {
        self.inner.name()
    }

    fn display_name(&self) -> String {
        self.inner.display_name()
    }

    fn allow_signup(&self) -> Option<Allow> {
        self.inner.allow_signup()
    }

    fn allow_login(&self) -> Option<Allow> {
        self.inner.allow_login()
    }

    fn allow_linking(&self) -> Option<bool> {
        self.inner.allow_linking()
    }

    fn scopes(&self) -> Vec<Scope> {
        self.inner.scopes()
    }

    fn get_authorization_url_and_state(
        &self,
        base_redirect_url: RedirectUrl,
        scopes: Vec<Scope>,
    ) -> (Url, CsrfToken) {
        self.inner
            .get_authorization_url_and_state(base_redirect_url, scopes)
    }
}

#[async_trait]
impl OAuthProvider for OAuthProviderBaseWithUserCallback<'_> {
    async fn exchange_authorization_code(
        &self,
        provider_name: String,
        redirect_url: RedirectUrl,
        code: AuthorizationCode,
    ) -> ExchangeResult {
        let res = self
            .inner
            .get_oauth2_client()
            .set_redirect_uri(redirect_url)
            .exchange_code(code)
            .request_async(async_http_client)
            .await
            .context("Requesting authorization code exchange")?;

        let provider_user = (self.get_user)(res.access_token().secret().to_string())?;

        Ok(UnmatchedOAuthToken::from_standard_token_response(
            res,
            provider_name,
            provider_user,
        ))
    }

    async fn exchange_refresh_token(
        &self,
        provider_name: String,
        redirect_url: RedirectUrl,
        refresh_token: RefreshToken,
    ) -> ExchangeResult {
        let res = self
            .inner
            .get_oauth2_client()
            .set_redirect_uri(redirect_url)
            .exchange_refresh_token(&refresh_token)
            .request_async(async_http_client)
            .await
            .context("Requesting refresh token exchange")?;

        let provider_user = (self.get_user)(res.access_token().secret().to_string())?;

        Ok(UnmatchedOAuthToken::from_standard_token_response(
            res,
            provider_name,
            provider_user,
        ))
    }
}
