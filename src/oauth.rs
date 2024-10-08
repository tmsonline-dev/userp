pub mod providers;

use super::{Allow, AxumUser, AxumUserStore, LoginMethod, UserTrait};
use axum::async_trait;
use axum_extra::extract::cookie::{Cookie, SameSite};
use chrono::{DateTime, Utc};
pub use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthorizationCode, CsrfToken, RedirectUrl,
    RefreshToken, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::HashMap, sync::Arc};
use url::Url;
use uuid::Uuid;

pub struct OAuthProviderUser {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub email_verified: bool,
}

pub enum ClientRefreshResult {
    NotSupported(OAuthToken),
    Ok(OAuthToken),
}

pub enum RefreshInitResult {
    Redirect(Url),
    Ok,
}

const CSRF_STATE_KEY: &str = "auth:csrf_state";
const OAUTH_FLOW_KEY: &str = "auth:oauth_flow";

#[derive(Serialize, Deserialize, Clone)]
pub enum OAuthFlow {
    LogIn {
        next: Option<String>,
    },
    SignUp {
        next: Option<String>,
    },
    Link {
        user_id: Uuid,
        next: Option<String>,
    },
    Refresh {
        user_id: Uuid,
        token_id: Uuid,
        next: Option<String>,
    },
}

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

#[derive(Clone, Default)]
pub struct OAuthClients(pub(super) HashMap<String, Arc<dyn OAuthProvider>>);

#[async_trait]
pub trait OAuthProvider: Sync + Send {
    async fn get_provider_user(&self, access_token: String) -> anyhow::Result<OAuthProviderUser>;
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
                    let (new_self, url) = self
                        .oauth_init(
                            path,
                            token.provider_name,
                            OAuthFlow::Refresh {
                                user_id: token.user_id,
                                token_id: token.id,
                                next,
                            },
                        )
                        .await?;

                    Ok((new_self, RefreshInitResult::Redirect(url)))
                }
            },
            Err(err) => {
                eprintln!("{err:#?}");
                Err((self, "something went wrong"))
            }
        }
    }

    fn redirect_uri(&self, path: String, provider_name: &str) -> RedirectUrl {
        let path = if path.ends_with('/') {
            path
        } else {
            format!("{path}/")
        };

        RedirectUrl::from_url(
            self.oauth
                .base_url
                .join(path.as_str())
                .unwrap()
                .join(provider_name)
                .unwrap(),
        )
    }

    async fn oauth_init(
        mut self,
        path: String,
        provider_name: String,
        oauth_flow: OAuthFlow,
    ) -> Result<(Self, Url), (Self, &'static str)> {
        let Some(provider) = self.oauth.clients.0.get(&provider_name) else {
            return Err((self, "Provider not found"));
        };

        let (auth_url, csrf_state) = provider
            .get_client()
            .set_redirect_uri(self.redirect_uri(path, &provider_name))
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

        self.jar = self.jar.add(
            Cookie::build((OAUTH_FLOW_KEY, json!(oauth_flow).to_string()))
                .path("/")
                .same_site(SameSite::Lax)
                .secure(self.https_only)
                .http_only(true)
                .build(),
        );

        Ok((self, auth_url))
    }

    pub async fn oauth_login_init(
        self,
        provider_name: String,
        next: Option<String>,
    ) -> Result<(Self, Url), (Self, &'static str)> {
        let path = self.oauth.login_path.clone();
        self.oauth_init(path, provider_name, OAuthFlow::LogIn { next })
            .await
    }

    pub async fn oauth_signup_init(
        self,
        provider_name: String,
        next: Option<String>,
    ) -> Result<(Self, Url), (Self, &'static str)> {
        let path = self.oauth.signup_path.clone();
        self.oauth_init(path, provider_name, OAuthFlow::SignUp { next })
            .await
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

        self.oauth_init(
            path,
            provider_name,
            OAuthFlow::Link {
                next,
                user_id: user.get_id(),
            },
        )
        .await
    }

    async fn oauth_callback(
        &self,
        provider_name: String,
        code: AuthorizationCode,
        state: CsrfToken,
        path: String,
    ) -> Result<(UnmatchedOAuthToken, OAuthFlow), &'static str> {
        let Some(provider) = self.oauth.clients.0.get(&provider_name) else {
            return Err("Provider not found");
        };

        let Some(prev_state) = self.jar.get(CSRF_STATE_KEY) else {
            return Err("No csrf token found");
        };

        if state.secret() != prev_state.value() {
            return Err("Csrf token doesn't match");
        }

        let Some(oauth_flow) = self.jar.get(OAUTH_FLOW_KEY) else {
            return Err("No oauth flow cookie found");
        };

        let Ok(oauth_flow) = serde_json::from_str::<OAuthFlow>(oauth_flow.value()) else {
            return Err("Misformed OAuthFlow");
        };

        let oauth_token = match provider
            .get_client()
            .set_redirect_uri(self.redirect_uri(path, &provider_name))
            .exchange_code(code)
            .request_async(async_http_client)
            .await
        {
            Ok(oauth_token) => oauth_token,
            Err(err) => {
                println!("{err:#?}");
                return Err("token error");
            }
        };

        let access_token = oauth_token.access_token().secret().to_string();
        let refresh_token = oauth_token.refresh_token().map(|rt| rt.secret()).cloned();
        let expires = oauth_token.expires_in().map(|seconds| Utc::now() + seconds);
        let scopes = oauth_token
            .scopes()
            .map(|scopes| {
                scopes
                    .iter()
                    .map(|scope| scope.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let provider_user = provider
            .get_provider_user(access_token.clone())
            .await
            .unwrap();

        let unmatched_token = UnmatchedOAuthToken {
            access_token,
            refresh_token,
            expires,
            scopes,
            provider_user,
        };

        Ok((unmatched_token, oauth_flow))
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn oauth_login_callback(
        self,
        provider_name: String,
        code: AuthorizationCode,
        state: CsrfToken,
    ) -> Result<(Self, Option<String>), (Self, &'static str)> {
        let (unmatched_token, flow) = match self
            .oauth_callback(
                provider_name.clone(),
                code,
                state,
                self.oauth.login_path.clone(),
            )
            .await
        {
            Ok(ok) => ok,
            Err(err) => {
                return Err((self, err));
            }
        };

        let next = match (
            flow,
            self.oauth
                .allow_signup
                .as_ref()
                .unwrap_or(&self.allow_signup),
        ) {
            (OAuthFlow::SignUp { next }, _) => next,
            (OAuthFlow::LogIn { next }, &Allow::OnEither) => next,
            _ => {
                return Err((self, "Expected LogIn flow"));
            }
        };

        let Some((user, old_token)) = self
            .store
            .get_user_by_oauth_provider_id(provider_name.clone(), unmatched_token.provider_user.id)
            .await
        else {
            return Err((self, "No matching user found"));
        };

        let new_token = OAuthToken {
            access_token: unmatched_token.access_token,
            refresh_token: unmatched_token.refresh_token,
            expires: unmatched_token.expires,
            scopes: unmatched_token.scopes,
            ..old_token
        };

        self.store.create_or_update_oauth_token(new_token).await;

        Ok((
            self.log_in(
                LoginMethod::OAuth {
                    token_id: old_token.id,
                },
                user.get_id(),
            )
            .await,
            next,
        ))
    }

    pub async fn oauth_link_callback(
        &self,
        provider_name: String,
        code: AuthorizationCode,
        state: CsrfToken,
    ) -> Result<Option<String>, &'static str> {
        let (unmatched_token, flow) = match self
            .oauth_callback(
                provider_name.clone(),
                code,
                state,
                self.oauth.link_path.clone(),
            )
            .await
        {
            Ok(ok) => ok,
            Err(err) => {
                return Err(err);
            }
        };

        let OAuthFlow::Link { user_id, next } = flow else {
            return Err("Expected Link flow");
        };

        // let Some(user) = self.store.get_user(user_id).await else {
        //     return Err("No user found");
        // };

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

        Ok(next)

        // Ok((
        //     self.log_in(LoginMethod::OAuth { token_id: id }, user.get_id())
        //         .await,
        //     next,
        // ))
    }

    pub async fn oauth_refresh_callback(
        &self,
        provider_name: String,
        code: AuthorizationCode,
        state: CsrfToken,
    ) -> Result<Option<String>, &'static str> {
        let (unmatched_token, flow) = match self
            .oauth_callback(
                provider_name.clone(),
                code,
                state,
                self.oauth.refresh_path.clone(),
            )
            .await
        {
            Ok(ok) => ok,
            Err(err) => {
                return Err(err);
            }
        };

        let OAuthFlow::Refresh {
            user_id,
            token_id,
            next,
        } = flow
        else {
            return Err("Expected Refresh flow");
        };

        let Some(old_token) = self.store.get_oauth_token(user_id, token_id).await else {
            return Err("No user or token found");
        };

        let new_token = OAuthToken {
            access_token: unmatched_token.access_token,
            refresh_token: unmatched_token.refresh_token,
            expires: unmatched_token.expires,
            ..old_token
        };

        self.store.create_or_update_oauth_token(new_token).await;

        Ok(next)

        // Ok((
        //     self.log_in(
        //         LoginMethod::OAuth {
        //             token_id: old_token.id,
        //         },
        //         user.get_id(),
        //     )
        //     .await,
        //     next,
        // ))
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn oauth_signup_callback(
        self,
        provider_name: String,
        code: AuthorizationCode,
        state: CsrfToken,
    ) -> Result<(Self, Option<String>), (Self, &'static str)> {
        let (unmatched_token, flow) = match self
            .oauth_callback(
                provider_name.clone(),
                code,
                state,
                self.oauth.signup_path.clone(),
            )
            .await
        {
            Ok(ok) => ok,
            Err(err) => {
                return Err((self, err));
            }
        };

        let next = match (
            flow,
            self.oauth
                .allow_signup
                .as_ref()
                .unwrap_or(&self.allow_signup),
        ) {
            (OAuthFlow::SignUp { next }, _) => next,
            (OAuthFlow::LogIn { next }, &Allow::OnEither) => next,
            _ => {
                return Err((self, "Expected SignUp flow"));
            }
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
