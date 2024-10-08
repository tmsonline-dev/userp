pub mod providers;

use super::{Allow, AxumUser, AxumUserStore, LoginMethod, UserTrait};
use axum::async_trait;
use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::{DateTime, Utc};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AccessToken, AuthorizationCode, CsrfToken,
    RedirectUrl, RefreshToken, Scope, TokenResponse,
};
use std::{collections::HashMap, sync::Arc};
use url::Url;
use uuid::Uuid;

const NEXT_KEY: &str = "auth:next";
const USER_ID_KEY: &str = "auth:user_id";
const TOKEN_ID_KEY: &str = "auth:token_id";
const CSRF_STATE_KEY: &str = "auth:csrf_state";

#[derive(Clone)]
pub struct OAuthConfig {
    pub allow_login: Option<Allow>,
    pub allow_signup: Option<Allow>,
    pub allow_linking: bool,
    pub login_path: String,
    pub link_path: String,
    pub signup_path: String,
    pub refresh_path: String,
    pub base_url: Url,
    pub clients: OAuthClients,
}

#[derive(Debug, Clone)]
pub struct OAuthPaths {
    pub login: &'static str,
    pub link: &'static str,
    pub signup: &'static str,
    pub refresh: &'static str,
}

impl OAuthConfig {
    pub fn new(base_url: Url, paths: OAuthPaths) -> Self {
        Self {
            base_url,
            allow_login: None,
            allow_signup: None,
            allow_linking: true,
            login_path: paths.login.to_string(),
            link_path: paths.link.to_string(),
            signup_path: paths.signup.to_string(),
            refresh_path: paths.refresh.to_string(),
            clients: Default::default(),
        }
    }

    pub fn with_client(
        mut self,
        name: impl Into<String>,
        client: impl OAuthProvider + 'static,
    ) -> Self {
        self.clients.0.insert(name.into(), Arc::new(client));
        self
    }

    pub fn with_allow_signup(mut self, allow_signup: Allow) -> Self {
        self.allow_signup = Some(allow_signup);
        self
    }

    pub fn with_allow_login(mut self, allow_login: Allow) -> Self {
        self.allow_login = Some(allow_login);
        self
    }

    pub fn with_allow_linking(mut self, allow_linking: bool) -> Self {
        self.allow_linking = allow_linking;
        self
    }
}

pub struct OAuthProviderUser {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub email_verified: bool,
}

#[derive(Clone, Default)]
pub struct OAuthClients(pub(super) HashMap<String, Arc<dyn OAuthProvider>>);

#[async_trait]
pub trait OAuthProvider: Sync + Send {
    async fn get_provider_user(
        &self,
        access_token: AccessToken,
    ) -> anyhow::Result<OAuthProviderUser>;
    async fn refresh_token(&self, token: OAuthToken) -> anyhow::Result<ClientRefreshResult> {
        match token.refresh_token {
            Some(refresh_token) => {
                let client = self.get_client();
                let refresh_token = RefreshToken::new(refresh_token);

                let res = client
                    .exchange_refresh_token(&refresh_token)
                    .request_async(async_http_client)
                    .await?;

                Ok(ClientRefreshResult::Ok(OAuthToken {
                    access_token: res.access_token().secret().to_string(),
                    refresh_token: res.refresh_token().map(|rt| rt.secret().to_string()),
                    expires: res.expires_in().map(|seconds| Utc::now() + seconds),
                    ..token
                }))
            }
            None => Ok(ClientRefreshResult::NotSupported(token)),
        }
    }
    fn get_client(&self) -> BasicClient;
    fn get_scopes(&self) -> Vec<String>;
    fn allow_signup(&self) -> Option<Allow>;
    fn allow_login(&self) -> Option<Allow>;
    fn allow_linking(&self) -> Option<bool>;
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
    pub fn oauth_login_providers(&self) -> Vec<String> {
        self.oauth
            .clients
            .0
            .iter()
            .filter_map(|(n, c)| {
                if c.allow_login()
                    .as_ref()
                    .unwrap_or(self.oauth.allow_login.as_ref().unwrap_or(&self.allow_login))
                    != &Allow::Never
                {
                    Some(n.to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn oauth_signup_providers(&self) -> Vec<String> {
        self.oauth
            .clients
            .0
            .iter()
            .filter_map(|(n, c)| {
                if c.allow_signup().as_ref().unwrap_or(
                    self.oauth
                        .allow_signup
                        .as_ref()
                        .unwrap_or(&self.allow_signup),
                ) != &Allow::Never
                {
                    Some(n.to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn oauth_link_providers(&self) -> Vec<String> {
        self.oauth
            .clients
            .0
            .iter()
            .filter_map(|(n, c)| {
                if c.allow_linking().unwrap_or(self.oauth.allow_linking) {
                    Some(n.to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    pub async fn oauth_refresh_init(
        self,
        token: OAuthToken,
        next: Option<String>,
    ) -> Result<(Self, RefreshInitResult), (Self, &'static str)> {
        let Some(client) = self.oauth.clients.0.get(&token.provider_name) else {
            return Err((self, "Client not found"));
        };

        match client.refresh_token(token).await {
            Ok(result) => match result {
                ClientRefreshResult::Ok(token) => {
                    self.store.create_or_update_oauth_token(token).await;
                    Ok((self, RefreshInitResult::Ok))
                }
                ClientRefreshResult::NotSupported(token) => {
                    let path = self.oauth.refresh_path.clone();
                    let (mut new_self, url) =
                        self.oauth_init(path, token.provider_name, next).await?;

                    new_self.jar = new_self
                        .jar
                        .add(
                            Cookie::build((USER_ID_KEY, token.user_id.to_string()))
                                .same_site(SameSite::Lax)
                                .path("/")
                                .http_only(true)
                                .secure(new_self.https_only),
                        )
                        .add(
                            Cookie::build((TOKEN_ID_KEY, token.id.to_string()))
                                .path("/")
                                .same_site(SameSite::Lax)
                                .http_only(true)
                                .secure(new_self.https_only),
                        );

                    Ok((new_self, RefreshInitResult::Url(url)))
                }
            },
            Err(err) => {
                eprintln!("{err:#?}");
                Err((self, "something went wrong"))
            }
        }
    }

    pub async fn oauth_init(
        mut self,
        path: String,
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
                    .base_url
                    .join(path.as_str())
                    .unwrap()
                    .join(provider_name.as_str())
                    .unwrap(),
            ))
            .authorize_url(CsrfToken::new_random)
            .add_scopes(provider.get_scopes().into_iter().map(Scope::new))
            .url();

        self.jar = self.jar.add(
            Cookie::build((CSRF_STATE_KEY, csrf_state.secret().clone()))
                .path("/")
                .http_only(true)
                .same_site(SameSite::Lax)
                .secure(self.https_only)
                .build(),
        );

        if let Some(next) = next {
            self.jar = self.jar.add(
                Cookie::build((NEXT_KEY, next))
                    .path("/")
                    .same_site(SameSite::Lax)
                    .secure(self.https_only)
                    .http_only(true)
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
        let path = self.oauth.login_path.clone();
        self.oauth_init(path, provider_name, next).await
    }

    pub async fn oauth_signup_init(
        self,
        provider_name: String,
        next: Option<String>,
    ) -> Result<(Self, Url), (Self, &'static str)> {
        let path = self.oauth.signup_path.clone();
        self.oauth_init(path, provider_name, next).await
    }

    pub async fn oauth_link_init(
        self,
        provider_name: String,
        next: Option<String>,
    ) -> Result<(Self, Url), (Self, &'static str)> {
        let Some(user) = self.user().await else {
            return Err((self, "Not logged in"));
        };

        let path = self.oauth.link_path.clone();
        let (mut new_self, url) = self.oauth_init(path, provider_name, next).await?;

        new_self.jar = new_self.jar.add(
            Cookie::build((USER_ID_KEY, user.get_id().to_string()))
                .path("/")
                .same_site(SameSite::Lax)
                .secure(new_self.https_only)
                .http_only(true)
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

        let Some(prev_state) = self.jar.get(CSRF_STATE_KEY) else {
            return Err("No csrf token found");
        };

        if state != prev_state.value() {
            return Err("Csrf token doesn't match");
        }

        let next = self.jar.get(NEXT_KEY).map(|x| x.value().to_string());

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

        let Some(user_id) = self.jar.get(USER_ID_KEY) else {
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

    pub async fn oauth_refresh_callback(
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

        let Some(user_id) = self.jar.get(USER_ID_KEY) else {
            return Err((self, "No user id in cooke"));
        };

        let Ok(user_id) = Uuid::parse_str(user_id.value()) else {
            return Err((self, "Malformed user id"));
        };

        let Some(token_id) = self.jar.get(TOKEN_ID_KEY) else {
            return Err((self, "No token id in cooke"));
        };

        let Ok(token_id) = Uuid::parse_str(token_id.value()) else {
            return Err((self, "Malformed token id"));
        };

        let Some((user, token)) = self.store.get_user_oauth_token(user_id, token_id).await else {
            return Err((self, "No user or token found"));
        };

        let new_token = OAuthToken {
            access_token: unmatched_token.access_token,
            refresh_token: unmatched_token.refresh_token,
            expires: unmatched_token.expires,
            ..token
        };

        self.store.create_or_update_oauth_token(new_token).await;

        Ok((
            self.log_in(LoginMethod::OAuth { token_id: token.id }, user.get_id())
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

pub enum ClientRefreshResult {
    NotSupported(OAuthToken),
    Ok(OAuthToken),
}

pub enum RefreshInitResult {
    Url(Url),
    Ok,
}
