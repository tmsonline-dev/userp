pub mod providers;

use super::{Allow, AxumUser, AxumUserStore, LoginMethod, UserTrait};
use axum::async_trait;
use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::{DateTime, Utc};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AccessToken, AuthorizationCode, CsrfToken,
    RedirectUrl, Scope, TokenResponse,
};
use std::{collections::HashMap, sync::Arc};
use url::Url;
use uuid::Uuid;

#[derive(Clone)]
pub struct OAuthConfig {
    pub allow_login: Allow,
    pub allow_signup: Allow,
    pub base_redirect_url: Url,
    pub clients: OAuthClients,
}

pub struct OAuthProviderUser {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub email_verified: bool,
}

#[derive(Clone, Default)]
pub struct OAuthClients(pub(super) Arc<HashMap<String, Box<dyn OAuthProvider>>>);

#[async_trait]
pub trait OAuthProvider: Sync + Send {
    async fn get_provider_user(
        &self,
        access_token: AccessToken,
    ) -> anyhow::Result<OAuthProviderUser>;
    fn get_client(&self) -> BasicClient;
    fn get_scopes(&self) -> Vec<String>;
}

pub struct UnmatchedOAuthToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
    pub provider_user: OAuthProviderUser,
}

#[derive(Clone, Debug)]
#[allow(unused)]
pub struct OAuthToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider_name: String,
    pub provider_user_id: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
}

impl<S: AxumUserStore> AxumUser<S> {
    pub async fn oauth_init(
        mut self,
        provider_name: String,
        next: Option<String>,
    ) -> Result<(Self, Url), (Self, &'static str)> {
        let Some(provider) = self.oauth.clients.0.get(&provider_name) else {
            return Err((self, "Provider not found"));
        };

        let (auth_url, csrf_state) = provider
            .get_client()
            .set_redirect_uri(RedirectUrl::from_url(
                self.oauth
                    .base_redirect_url
                    .join(provider_name.as_str())
                    .unwrap(),
            ))
            .authorize_url(CsrfToken::new_random)
            .add_scopes(provider.get_scopes().into_iter().map(Scope::new))
            .url();

        self.jar = self.jar.add(
            Cookie::build(("csrf_state", csrf_state.secret().clone()))
                .http_only(true)
                .same_site(SameSite::Lax)
                .secure(true)
                .build(),
        );

        if let Some(next) = next {
            self.jar = self.jar.add(
                Cookie::build(("next", next))
                    .same_site(SameSite::Lax)
                    .secure(true)
                    .build(),
            );
        }

        Ok((self, auth_url))
    }

    pub async fn oauth_login_init(
        self,
        provider_name: String,
        next: Option<String>,
    ) -> Result<(Self, Url), (Self, &'static str)> {
        self.oauth_init(provider_name, next).await
    }

    pub async fn oauth_signup_init(
        self,
        provider_name: String,
        next: Option<String>,
    ) -> Result<(Self, Url), (Self, &'static str)> {
        self.oauth_init(provider_name, next).await
    }

    pub async fn oauth_link_init(
        self,
        provider_name: String,
        next: Option<String>,
    ) -> Result<(Self, Url), (Self, &'static str)> {
        let Some(user) = self.user().await else {
            return Err((self, "Not logged in"));
        };

        let (mut new_self, url) = self.oauth_init(provider_name, next).await?;

        new_self.jar = new_self.jar.add(
            Cookie::build(("user_id", user.get_id().to_string()))
                .same_site(SameSite::Lax)
                .secure(true)
                .build(),
        );

        Ok((new_self, url))
    }

    async fn oauth_callback(
        &self,
        provider_name: String,
        code: String,
        state: String,
    ) -> Result<(UnmatchedOAuthToken, Option<String>), &'static str> {
        let Some(provider) = self.oauth.clients.0.get(&provider_name) else {
            return Err("Provider not found");
        };

        let Some(prev_state) = self.jar.get("csrf_state") else {
            return Err("No csrf token found");
        };

        if state != prev_state.value() {
            return Err("Csrf token doesn't match");
        }

        let next = self.jar.get("next").map(|x| x.value().to_string());

        let Ok(oauth_token) = provider
            .get_client()
            .exchange_code(AuthorizationCode::new(code))
            .request_async(async_http_client)
            .await
        else {
            return Err("token error");
        };

        let unmatched_token = UnmatchedOAuthToken {
            access_token: oauth_token.access_token().secret().to_string(),
            refresh_token: oauth_token.refresh_token().map(|rt| rt.secret()).cloned(),

            expires: oauth_token.expires_in().map(|seconds| Utc::now() + seconds),
            scopes: oauth_token
                .scopes()
                .map(|scopes| {
                    scopes
                        .iter()
                        .map(|scope| scope.to_string())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            provider_user: provider
                .get_provider_user(oauth_token.access_token().clone())
                .await
                .unwrap(),
        };

        Ok((unmatched_token, next))
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn oauth_login_callback(
        self,
        provider_name: String,
        code: String,
        state: String,
    ) -> Result<(Self, Option<String>), (Self, &'static str)> {
        let Ok((unmatched_token, next)) = self
            .oauth_callback(provider_name.clone(), code, state)
            .await
        else {
            return Err((self, "lkasjdklajsd"));
        };

        let Some((user, current_token)) = self
            .store
            .get_user_by_oauth_provider_id(provider_name.clone(), unmatched_token.provider_user.id)
            .await
        else {
            return Err((self, "No matching user found"));
        };

        let new_token = OAuthToken {
            id: current_token.id,
            user_id: current_token.user_id,
            provider_name: current_token.provider_name,
            provider_user_id: current_token.provider_user_id,
            access_token: unmatched_token.access_token,
            refresh_token: unmatched_token.refresh_token,
            expires: unmatched_token.expires,
            scopes: unmatched_token.scopes,
        };

        self.store.create_or_update_oauth_token(new_token).await;

        Ok((
            self.log_in(
                LoginMethod::OAuth {
                    token_id: current_token.id,
                },
                user.get_id(),
            )
            .await,
            next,
        ))
    }

    pub async fn oauth_link_callback(
        self,
        provider_name: String,
        code: String,
        state: String,
    ) -> Result<(Self, Option<String>), (Self, &'static str)> {
        let Ok((unmatched_token, next)) = self
            .oauth_callback(provider_name.clone(), code, state)
            .await
        else {
            return Err((self, "lkasjdklajsd"));
        };

        let Some(user_id) = self.jar.get("user_id") else {
            return Err((self, "No user id in cooke"));
        };

        let Ok(user_id) = Uuid::parse_str(user_id.value()) else {
            return Err((self, "Malformed user id"));
        };

        let Some(user) = self.store.get_user(user_id).await else {
            return Err((self, "No user found"));
        };

        let id = Uuid::new_v4();

        let new_token = OAuthToken {
            id,
            user_id,
            provider_name,
            provider_user_id: unmatched_token.provider_user.id,
            access_token: unmatched_token.access_token,
            refresh_token: unmatched_token.refresh_token,
            expires: unmatched_token.expires,
            scopes: unmatched_token.scopes,
        };

        self.store.create_or_update_oauth_token(new_token).await;

        Ok((
            self.log_in(LoginMethod::OAuth { token_id: id }, user.get_id())
                .await,
            next,
        ))
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn oauth_signup_callback(
        self,
        provider_name: String,
        code: String,
        state: String,
    ) -> Result<(Self, Option<String>), (Self, &'static str)> {
        let Ok((unmatched_token, next)) = self
            .oauth_callback(provider_name.clone(), code, state)
            .await
        else {
            return Err((self, "lkasjdklajsd"));
        };

        let Some((user, token)) = self
            .store
            .create_oauth_user(provider_name.clone(), unmatched_token)
            .await
        else {
            return Err((self, "i dunno"));
        };

        Ok((
            self.log_in(LoginMethod::OAuth { token_id: token.id }, user.get_id())
                .await,
            next,
        ))
    }
}
