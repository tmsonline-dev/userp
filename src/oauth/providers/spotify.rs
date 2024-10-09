use anyhow::{Context, Result};
use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, TokenUrl};
use serde_json::Value;
use url::Url;

use super::{
    super::{Allow, OAuthProviderUser},
    IncludedProvider,
};

pub struct SpotifyOAuthProvider {
    scopes: Vec<String>,
    client: BasicClient,
    allow_signup: Option<Allow>,
    allow_login: Option<Allow>,
    allow_linking: Option<bool>,
}

impl SpotifyOAuthProvider {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        let client = BasicClient::new(
            ClientId::new(client_id.into()),
            Some(ClientSecret::new(client_secret.into())),
            AuthUrl::from_url(Url::parse("https://accounts.spotify.com/authorize").unwrap()),
            Some(TokenUrl::from_url(
                Url::parse("https://accounts.spotify.com/api/token").unwrap(),
            )),
        );

        Self {
            scopes: vec!["user-read-email".into()],
            client,
            allow_signup: None,
            allow_login: None,
            allow_linking: None,
        }
    }
}

impl IncludedProvider for SpotifyOAuthProvider {
    fn with_allow_signup(mut self, allow_signup: Allow) -> Self {
        self.allow_signup = Some(allow_signup);
        self
    }

    fn with_allow_login(mut self, allow_login: Allow) -> Self {
        self.allow_login = Some(allow_login);
        self
    }

    fn with_allow_linking(mut self, allow_linking: bool) -> Self {
        self.allow_linking = Some(allow_linking);
        self
    }

    fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }
}

impl SpotifyOAuthProvider {
    async fn get_provider_user(&self, access_token: String) -> Result<OAuthProviderUser> {
        let client = reqwest::Client::new();

        let res = client
            .get("https://api.spotify.com/v1/me")
            .header("Accept", "application/json")
            .bearer_auth(access_token)
            .send()
            .await?
            .json::<Value>()
            .await?;

        let id = res
            .as_object()
            .and_then(|obj| obj.get("id").and_then(|id| id.as_str()))
            .context("Missing id")?
            .to_string();

        let email = res
            .as_object()
            .and_then(|obj| obj.get("email").and_then(|id| id.as_str()))
            .map(|name| name.to_string());

        let name = res
            .as_object()
            .and_then(|obj| obj.get("display_name").and_then(|id| id.as_str()))
            .map(|name| name.to_string());

        Ok(OAuthProviderUser {
            id,
            email,
            name,
            email_verified: false,
        })
    }

    fn get_client(&self) -> BasicClient {
        self.client.clone()
    }

    fn get_scopes(&self) -> Vec<String> {
        self.scopes.clone()
    }

    fn allow_signup(&self) -> Option<Allow> {
        self.allow_signup.clone()
    }

    fn allow_linking(&self) -> Option<bool> {
        self.allow_linking
    }

    fn allow_login(&self) -> Option<Allow> {
        self.allow_login.clone()
    }
}
