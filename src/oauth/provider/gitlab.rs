use super::custom::OAuthCustomProvider;
use crate::oauth::OAuthProviderUser;
use anyhow::Context;
use serde_json::Value;

pub struct GitLabOAuthProvider;

impl GitLabOAuthProvider {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> OAuthCustomProvider {
        OAuthCustomProvider::new_with_callback(
            "gitlab",
            "GitLab",
            client_id,
            client_secret,
            "https://gitlab.com/oauth/authorize",
            "https://gitlab.com/oauth/token",
            &["openid"],
            |access_token| async move {
                let client = reqwest::Client::new();

                let raw = client
                    .get("https://gitlab.com/oauth/userinfo")
                    .header("Accept", "application/json")
                    .bearer_auth(access_token)
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<Value>()
                    .await?;

                let id = raw["sub"]
                    .as_str()
                    .context("Missing 'sub' in response")?
                    .to_string();

                Ok(OAuthProviderUser { id, raw })
            },
        )
        .expect("Built in providers should work")
    }
}
