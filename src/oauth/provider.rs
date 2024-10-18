mod github;
mod spotify;

pub mod custom;
pub mod with_user_callback;

use super::UnmatchedOAuthToken;
use crate::Allow;
use async_trait::async_trait;
pub use github::GitHubOAuthProvider;
use oauth2::{AuthorizationCode, CsrfToken, RedirectUrl, RefreshToken, Scope};
pub use spotify::SpotifyOAuthProvider;
use url::Url;

pub type ExchangeResult = anyhow::Result<UnmatchedOAuthToken>;

pub trait OAuthProviderBase: Send + Sync {
    fn name(&self) -> &str;

    fn display_name(&self) -> &str {
        self.name()
    }

    fn allow_signup(&self) -> Option<Allow>;
    fn allow_login(&self) -> Option<Allow>;
    fn allow_linking(&self) -> Option<bool>;

    fn scopes(&self) -> &[Scope];

    fn get_authorization_url_and_state(
        &self,
        base_redirect_url: &RedirectUrl,
        scopes: &[Scope],
    ) -> (Url, CsrfToken);
}

#[async_trait]
pub trait OAuthProvider: OAuthProviderBase + Send + Sync {
    async fn exchange_authorization_code(
        &self,
        provider_name: &str,
        redirect_url: &RedirectUrl,
        code: &AuthorizationCode,
    ) -> ExchangeResult;

    async fn exchange_refresh_token(
        &self,
        provider_name: &str,
        redirect_url: &RedirectUrl,
        refresh_token: &RefreshToken,
    ) -> ExchangeResult;
}
