use super::custom::OAuthCustomProvider;
use crate::oauth::OAuthProviderUser;
use anyhow::Context;
use serde_json::Value;

pub struct SpotifyOAuthProvider;

impl SpotifyOAuthProvider {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> OAuthCustomProvider {
        OAuthCustomProvider::new_with_callback(
            "spotify",
            "Spotify",
            client_id,
            client_secret,
            "https://accounts.spotify.com/authorize",
            "https://accounts.spotify.com/api/token",
            &["user-read-email"],
            |access_token| async move {
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
            },
        )
        .expect("Built in providers should work")
    }
}
