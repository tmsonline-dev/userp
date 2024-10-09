mod github;
mod spotify;

pub mod custom;
pub mod with_user_callback;

use super::UnmatchedOAuthToken;
use crate::Allow;
use axum::async_trait;
pub use github::GitHubOAuthProvider;
use oauth2::{AuthorizationCode, CsrfToken, RedirectUrl, RefreshToken, Scope};
pub use spotify::SpotifyOAuthProvider;
use url::Url;

pub type ExchangeResult = anyhow::Result<UnmatchedOAuthToken>;

pub trait OAuthProviderBase: Send + Sync {
    fn name(&self) -> String;

    fn display_name(&self) -> String {
        self.name()
    }

    fn allow_signup(&self) -> Option<Allow>;
    fn allow_login(&self) -> Option<Allow>;
    fn allow_linking(&self) -> Option<bool>;

    fn scopes(&self) -> Vec<Scope>;

    fn get_authorization_url_and_state(
        &self,
        base_redirect_url: RedirectUrl,
        scopes: Vec<Scope>,
    ) -> (Url, CsrfToken);
}

#[async_trait]
pub trait OAuthProvider: OAuthProviderBase + Send + Sync {
    async fn exchange_authorization_code(
        &self,
        redirect_url: RedirectUrl,
        code: AuthorizationCode,
    ) -> ExchangeResult;

    async fn exchange_refresh_token(
        &self,
        redirect_url: RedirectUrl,
        refresh_token: RefreshToken,
    ) -> ExchangeResult;
}
