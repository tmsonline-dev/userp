use super::custom::OAuthCustomProvider;
use crate::oauth::OAuthProviderUser;
use anyhow::Context;
use serde_json::Value;

pub struct GitHubOAuthProvider;

impl GitHubOAuthProvider {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> OAuthCustomProvider {
        OAuthCustomProvider::new_with_callback(
            "github",
            "GitHub",
            client_id,
            client_secret,
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            &["user:email"],
            |access_token| async move {
                let client = reqwest::Client::new();

                let res = client
                    .get("https://api.github.com/user")
                    .header("User-Agent", "userp")
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .bearer_auth(access_token)
                    .send()
                    .await?
                    .json::<Value>()
                    .await?;

                let id = res
                    .as_object()
                    .and_then(|obj| obj.get("id").and_then(|id| id.as_number()))
                    .context("Missing id")?
                    .to_string();

                let email = res
                    .as_object()
                    .and_then(|obj| obj.get("email").and_then(|id| id.as_str()))
                    .map(|email| email.to_string());

                let name = res
                    .as_object()
                    .and_then(|obj| obj.get("name").and_then(|id| id.as_str()))
                    .map(|name| name.to_string());

                Ok(OAuthProviderUser {
                    id,
                    email_verified: email.is_some(),
                    email,
                    name,
                })
            },
        )
        .expect("Built in providers should work")
    }
}
