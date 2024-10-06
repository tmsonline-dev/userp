use anyhow::{Context, Result};
use axum::async_trait;
use oauth2::{basic::BasicClient, AccessToken, AuthUrl, ClientId, ClientSecret, TokenUrl};
use serde_json::Value;
use url::Url;

use super::super::{OAuthProvider, OAuthProviderUser};

pub struct SpotifyOAuthProvider {
    scopes: Vec<String>,
    client: BasicClient,
}

impl SpotifyOAuthProvider {
    pub fn new(client_id: String, client_secret: String, scopes: Option<Vec<String>>) -> Self {
        let client = BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::from_url(Url::parse("https://accounts.spotify.com/authorize").unwrap()),
            Some(TokenUrl::from_url(
                Url::parse("https://accounts.spotify.com/api/token").unwrap(),
            )),
        );

        Self {
            scopes: scopes.unwrap_or(vec!["user-read-email".into()]),
            client,
        }
    }
}

#[async_trait]
impl OAuthProvider for SpotifyOAuthProvider {
    async fn get_provider_user(&self, access_token: AccessToken) -> Result<OAuthProviderUser> {
        let client = reqwest::Client::new();

        let res = client
            .get("https://api.spotify.com/v1/me")
            .header("Accept", "application/json")
            .bearer_auth(access_token.secret())
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
}
