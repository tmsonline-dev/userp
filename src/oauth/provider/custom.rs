use crate::{provider::OAuthProviderBase, Allow};
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl,
};
use std::{fmt::Display, future::Future, sync::Arc};
use url::Url;

use super::with_user_callback::{
    OAuthProviderBaseWithBasicClient, OAuthProviderBaseWithUserCallback, OAuthProviderUserResult,
};

#[derive(Debug)]
pub struct CustomOAuthClient {
    client: BasicClient,
    name: String,
    display_name: String,
    allow_signup: Option<Allow>,
    allow_login: Option<Allow>,
    allow_linking: Option<bool>,
    scopes: Vec<Scope>,
}

impl CustomOAuthClient {
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_callback<'a, Fut, F>(
        name: impl Into<String>,
        display_name: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        auth_url: impl Into<String>,
        token_url: impl Into<String>,
        scopes: &[impl Display],
        get_user: F,
    ) -> Result<OAuthProviderBaseWithUserCallback<'a>, anyhow::Error>
    where
        Fut: Future<Output = OAuthProviderUserResult> + Send + 'a,
        F: Fn(String) -> Fut + Send + Sync + 'a,
    {
        let client = BasicClient::new(
            ClientId::new(client_id.into()),
            Some(ClientSecret::new(client_secret.into())),
            AuthUrl::from_url(Url::parse(&auth_url.into())?),
            Some(TokenUrl::from_url(Url::parse(&token_url.into())?)),
        );

        let self_client = Self {
            allow_login: None,
            allow_signup: None,
            allow_linking: None,
            client,
            display_name: display_name.into(),
            scopes: scopes.iter().map(|s| Scope::new(s.to_string())).collect(),
            name: name.into(),
        };

        Ok(OAuthProviderBaseWithUserCallback::new(
            Box::new(self_client),
            Arc::new(get_user),
        ))
    }
}

impl OAuthProviderBaseWithBasicClient for CustomOAuthClient {
    fn get_oauth2_client(&self) -> BasicClient {
        self.client.clone()
    }
}

impl OAuthProviderBase for CustomOAuthClient {
    fn name(&self) -> &str {
        self.name.as_str()
    }

    fn display_name(&self) -> &str {
        self.display_name.as_str()
    }

    fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    fn get_authorization_url_and_state(
        &self,
        redirect_url: &RedirectUrl,
        scopes: &[Scope],
    ) -> (Url, CsrfToken) {
        self.client
            .clone()
            .set_redirect_uri(redirect_url.clone())
            .authorize_url(CsrfToken::new_random)
            .add_scopes(scopes.to_vec())
            .url()
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
}
