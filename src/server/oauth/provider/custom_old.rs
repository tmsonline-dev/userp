use std::{fmt::Display, future::Future};

use super::{ExchangeResult, OAuthProvider};
use crate::{
    config::Allow,
    oauth::{OAuthProviderUser, UnmatchedOAuthToken},
};
use anyhow::Context;
use async_trait::async_trait;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode, ClientId,
    ClientSecret, CsrfToken, RedirectUrl, RefreshToken, Scope, TokenResponse, TokenUrl,
};
use url::Url;

pub type OAuthProviderUserCallbackResult = anyhow::Result<OAuthProviderUser>;

pub struct OAuthCustomProvider<F, Fut>
where
    Fut: Future<Output = OAuthProviderUserCallbackResult> + Send + Sync + 'static,
    F: Fn(String) -> Fut + Send + Sync + 'static,
{
    client: BasicClient,
    name: String,
    display_name: String,
    scopes: Vec<Scope>,
    get_user: Box<F>,
    allow_signup: Option<Allow>,
    allow_login: Option<Allow>,
    allow_linking: Option<bool>,
}

impl<
        F: Fn(String) -> Fut + Send + Sync,
        Fut: Send + Sync + Future<Output = OAuthProviderUserCallbackResult>,
    > std::fmt::Debug for OAuthCustomProvider<F, Fut>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthProviderBaseWithUserCallback")
            .field("client", &self.client)
            .field("name", &self.name)
            .field("display_name", &self.display_name)
            .field("scopes", &self.scopes)
            .field("get_user", &"You dont want no part of this Dewey")
            .field("allow_signup", &self.allow_signup)
            .field("allow_login", &self.allow_login)
            .field("allow_linking", &self.allow_linking)
            .finish()
    }
}

impl<F, Fut> OAuthCustomProvider<F, Fut>
where
    Fut: Future<Output = OAuthProviderUserCallbackResult> + Send + Sync + 'static,
    F: Fn(String) -> Fut + Send + Sync + 'static,
{
    pub fn new_with_client_and_callback(
        name: impl Into<String>,
        display_name: impl Into<String>,
        scopes: &[impl Display],
        client: BasicClient,
        get_user: F,
    ) -> Result<OAuthCustomProvider<F, Fut>, anyhow::Error> {
        Ok(Self {
            allow_login: None,
            allow_signup: None,
            allow_linking: None,
            client,
            display_name: display_name.into(),
            scopes: scopes.iter().map(|s| Scope::new(s.to_string())).collect(),
            name: name.into(),
            get_user: Box::new(get_user),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_callback(
        name: impl Into<String>,
        display_name: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        auth_url: impl Into<String>,
        token_url: impl Into<String>,
        scopes: &[impl Display],
        get_user: F,
    ) -> Result<OAuthCustomProvider<F, Fut>, anyhow::Error> {
        let client = BasicClient::new(
            ClientId::new(client_id.into()),
            Some(ClientSecret::new(client_secret.into())),
            AuthUrl::from_url(Url::parse(&auth_url.into())?),
            Some(TokenUrl::from_url(Url::parse(&token_url.into())?)),
        );

        Self::new_with_client_and_callback(name, display_name, scopes, client, get_user)
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

#[async_trait]
impl<F, Fut> OAuthProvider for OAuthCustomProvider<F, Fut>
where
    Fut: Future<Output = OAuthProviderUserCallbackResult> + Send + Sync + 'static,
    F: Fn(String) -> Fut + Send + Sync + 'static,
{
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn display_name(&self) -> &str {
        self.display_name.as_str()
    }

    fn allow_signup(&self) -> Option<Allow> {
        self.allow_signup
    }

    fn allow_login(&self) -> Option<Allow> {
        self.allow_login
    }

    fn allow_linking(&self) -> Option<bool> {
        self.allow_linking
    }

    fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    fn get_authorization_url_and_state(
        &self,
        base_redirect_url: &RedirectUrl,
        scopes: &[Scope],
    ) -> (Url, CsrfToken) {
        self.client
            .clone()
            .set_redirect_uri(base_redirect_url.clone())
            .authorize_url(CsrfToken::new_random)
            .add_scopes(scopes.to_vec())
            .url()
    }

    async fn exchange_authorization_code(
        &self,
        provider_name: &str,
        redirect_url: &RedirectUrl,
        code: &AuthorizationCode,
    ) -> ExchangeResult {
        let res = self
            .client
            .clone()
            .set_redirect_uri(redirect_url.clone())
            .exchange_code(code.clone())
            .request_async(async_http_client)
            .await
            .context("Requesting authorization code exchange")?;

        let provider_user = (self.get_user)(res.access_token().secret().to_string()).await?;

        Ok(UnmatchedOAuthToken::from_standard_token_response(
            &res,
            provider_name,
            provider_user,
        ))
    }

    async fn exchange_refresh_token(
        &self,
        provider_name: &str,
        redirect_url: &RedirectUrl,
        refresh_token: &RefreshToken,
    ) -> ExchangeResult {
        let res = self
            .client
            .clone()
            .set_redirect_uri(redirect_url.clone())
            .exchange_refresh_token(refresh_token)
            .request_async(async_http_client)
            .await
            .context("Requesting refresh token exchange")?;

        let provider_user = (self.get_user)(res.access_token().secret().to_string()).await?;

        Ok(UnmatchedOAuthToken::from_standard_token_response(
            &res,
            provider_name,
            provider_user,
        ))
    }
}
