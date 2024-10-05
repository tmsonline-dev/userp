use anyhow::Context;
use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::{request::Parts, StatusCode},
    response::IntoResponseParts,
};
use axum_extra::extract::cookie::{Cookie, Expiration, Key, PrivateCookieJar, SameSite};
use chrono::{DateTime, Utc};
use lettre::{message::header::ContentType, Message, SmtpTransport, Transport};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AccessToken, AuthUrl, AuthorizationCode,
    ClientId, ClientSecret, CsrfToken, Scope, TokenResponse, TokenUrl,
};
use serde_json::Value;
use std::{collections::HashMap, convert::Infallible, sync::Arc};
use url::Url;
use uuid::Uuid;

#[derive(Clone)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
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
impl OAuthProviderTrait for SpotifyOAuthProvider {
    async fn get_provider_user(
        &self,
        access_token: AccessToken,
    ) -> anyhow::Result<OAuthProviderUser> {
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

pub struct OAuthProviderUser {
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub email_verified: bool,
}

#[async_trait]
pub trait OAuthProviderTrait: Sync + Send {
    async fn get_provider_user(
        &self,
        access_token: AccessToken,
    ) -> anyhow::Result<OAuthProviderUser>;
    fn get_client(&self) -> BasicClient;
    fn get_scopes(&self) -> Vec<String>;
}

#[derive(Clone)]
pub struct OAuth {
    pub clients: OAuthClients,
}

#[derive(Clone, Default)]
pub struct OAuthClients(Arc<HashMap<String, Box<dyn OAuthProviderTrait>>>);

pub trait AuthUser {
    async fn get_password_hash(&self) -> String;
    async fn get_id(&self) -> Uuid;
}

pub struct Email {
    pub email: String,
    pub verified: bool,
    pub allow_login: bool,
}

pub struct EmailChallenge {
    pub email: String,
    pub code: String,
    pub next: Option<String>,
}

impl EmailChallenge {
    pub fn identifier(&self) -> String {
        format!("{}::{}", self.email, self.code)
    }
}

pub trait Store {
    type User: AuthUser;

    // session store
    async fn create_session(&self, session: Session);
    async fn get_session(&self, session_id: Uuid) -> Option<Session>;
    async fn delete_session(&self, session_id: Uuid);

    // user store
    async fn get_user(&self, user_id: Uuid) -> Option<Self::User>;

    // password user store
    async fn get_user_by_password_id(&self, password_id: String) -> Option<Self::User>;
    async fn set_password_hash(&self, user_id: Uuid, password_hash: String);
    async fn create_password_user(&self, password_id: String, password_hash: String) -> Self::User;

    // email user store
    async fn get_user_by_email(&self, email: String) -> Option<(Self::User, Email)>;
    async fn save_email_challenge(&self, challenge: EmailChallenge);
    async fn consume_email_challenge(
        &self,
        code: String,
    ) -> Option<(String, Option<(Self::User, Email)>, Option<String>)>;
    async fn get_user_emails(&self, user_id: Uuid) -> Vec<Email>;
    async fn set_user_email_verified(&self, user_id: Uuid, email: String);
    async fn create_email_user(&self, email: String) -> Self::User;

    // oauth token store
    async fn get_user_by_oauth_provider_id(
        &self,
        provider_name: String,
        provider_user_id: String,
    ) -> Option<(Self::User, OAuthToken)>;
    async fn update_oauth_token(&self, token: OAuthToken);
    async fn create_oauth_user(
        &self,
        provider_name: String,
        token: UnmatchedOAuthToken,
    ) -> Option<(Self::User, OAuthToken)>;
}

pub struct AuthSession<S: Store, K = Key> {
    jar: PrivateCookieJar<K>,
    store: S,
    smtp: Smtp,
    oauth: OAuth,
}

#[derive(Debug, Clone)]
pub struct Smtp {
    pub server_url: String,
    pub username: String,
    pub password: String,
    pub from: String,
    pub starttls: bool,
    pub base_url: Url,
    pub allow_login_on_signup: bool,
    pub allow_signup_on_login: bool,
    pub login_path: String,
    pub verify_path: String,
    pub signup_path: String,
}

impl<S: Store> AuthSession<S> {
    // Password

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn password_signup(
        self,
        password_id: String,
        password_hash: String,
    ) -> Result<Self, (Self, &'static str)> {
        if self
            .store
            .get_user_by_password_id(password_id.clone())
            .await
            .is_some()
        {
            return Err((self, "User already exists"));
        };

        let user = self
            .store
            .create_password_user(password_id, password_hash)
            .await;

        Ok(self.log_in("password".into(), user.get_id().await).await)
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn password_login(
        self,
        password_id: String,
        password_hash: String,
    ) -> Result<Self, (Self, &'static str)> {
        let Some(user) = self.store.get_user_by_password_id(password_id).await else {
            return Err((self, "Unknown user"));
        };

        if user.get_password_hash().await != password_hash {
            return Err((self, "Wrong password"));
        };

        Ok(self.log_in("password".into(), user.get_id().await).await)
    }

    // Email

    async fn send_email_challenge(
        &self,
        path: String,
        email: String,
        message: String,
        next: Option<String>,
    ) -> Result<(), String> {
        let code = format!("{}{}", Uuid::new_v4(), Uuid::new_v4()).replace('-', "");

        self.store
            .save_email_challenge(EmailChallenge {
                email: email.clone(),
                code: code.clone(),
                next,
            })
            .await;

        let url = self
            .smtp
            .base_url
            .join(&format!("{path}?code={code}"))
            .unwrap();

        let email = Message::builder()
            .from(self.smtp.from.parse().unwrap())
            .to(email.parse().unwrap())
            .subject("Login link")
            .header(ContentType::TEXT_HTML)
            .body(format!("<a href=\"{url}\">{message}</a>"))
            .unwrap();

        let mailer = (if self.smtp.starttls {
            SmtpTransport::starttls_relay
        } else {
            SmtpTransport::relay
        })(self.smtp.server_url.as_str())
        .unwrap()
        .credentials(lettre::transport::smtp::authentication::Credentials::new(
            self.smtp.username.clone(),
            self.smtp.password.clone(),
        ))
        .build();

        mailer.send(&email).unwrap();

        Ok(())
    }

    pub async fn email_login_init(&self, email: String, next: Option<String>) {
        self.send_email_challenge(
            self.smtp.login_path.clone(),
            email,
            "Click here to log in".into(),
            next,
        )
        .await
        .unwrap()
    }

    pub async fn email_verify_init(&self, email: String, next: Option<String>) {
        self.send_email_challenge(
            self.smtp.verify_path.clone(),
            email,
            "Click here to verify email".into(),
            next,
        )
        .await
        .unwrap()
    }

    pub async fn email_signup_init(&self, email: String, next: Option<String>) {
        self.send_email_challenge(
            self.smtp.signup_path.clone(),
            email,
            "Click here to sign up".into(),
            next,
        )
        .await
        .unwrap()
    }

    async fn email_login(
        self,
        user: S::User,
        email: Email,
        next: Option<String>,
    ) -> Result<(Self, Option<String>), (Self, &'static str)> {
        if !email.allow_login {
            return Err((self, "Login not activated for this email"));
        }

        if !email.verified {
            self.store
                .set_user_email_verified(user.get_id().await, email.email)
                .await;
        }

        Ok((self.log_in("email".into(), user.get_id().await).await, next))
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn email_login_callback(
        self,
        code: String,
    ) -> Result<(Self, Option<String>), (Self, &'static str)> {
        let Some((email, user_email, next)) = self.store.consume_email_challenge(code).await else {
            return Err((self, "Code not found"));
        };

        let Some((user, email)) = user_email else {
            return if self.smtp.allow_signup_on_login {
                self.email_signup(email, next).await
            } else {
                Err((self, "No such user"))
            };
        };

        self.email_login(user, email, next).await
    }

    pub async fn email_verify_callback(
        &self,
        code: String,
    ) -> Result<Option<String>, &'static str> {
        let Some((_, user_email, next)) = self.store.consume_email_challenge(code).await else {
            return Err("Code not found");
        };

        let Some((user, email)) = user_email else {
            return Err("No such user");
        };

        if !email.verified {
            self.store
                .set_user_email_verified(user.get_id().await, email.email)
                .await;
        }

        Ok(next)
    }

    async fn email_signup(
        self,
        email: String,
        next: Option<String>,
    ) -> Result<(Self, Option<String>), (Self, &'static str)> {
        let user = self.store.create_email_user(email).await;

        Ok((self.log_in("email".into(), user.get_id().await).await, next))
    }

    pub async fn email_signup_callback(
        self,
        code: String,
    ) -> Result<(Self, Option<String>), (Self, &'static str)> {
        let Some((email, existing, next)) = self.store.consume_email_challenge(code).await else {
            return Err((self, "Code not found"));
        };

        if let Some((user, email)) = existing {
            return if self.smtp.allow_login_on_signup {
                self.email_login(user, email, next).await
            } else {
                Err((self, "User already exists"))
            };
        };

        self.email_signup(email, next).await
    }

    // OAuth

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
            Cookie::build(("user_id", user.get_id().await.to_string()))
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
    ) -> Result<UnmatchedOAuthToken, &'static str> {
        let Some(provider) = self.oauth.clients.0.get(&provider_name) else {
            return Err("Provider not found");
        };

        let Some(prev_state) = self.jar.get("csrf_state") else {
            return Err("No csrf token found");
        };

        if state != prev_state.value() {
            return Err("Csrf token doesn't match");
        }

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

        Ok(unmatched_token)
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn oauth_login_callback(
        self,
        provider_name: String,
        code: String,
        state: String,
    ) -> Result<Self, (Self, &'static str)> {
        let Ok(unmatched_token) = self
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

        self.store.update_oauth_token(new_token).await;

        Ok(self.log_in(provider_name, user.get_id().await).await)
    }

    // #[must_use = "Don't forget to return the auth session as part of the response!"]
    // pub async fn oauth_signup_callback(
    //     self,
    //     provider_name: String,
    //     code: String,
    //     state: String,
    // ) -> Result<Self, &'static str> {
    //     let Ok(unmatched_token) = self
    //         .oauth_callback(provider_name.clone(), code, state)
    //         .await
    //     else {
    //         return Err((self, "lkasjdklajsd"));
    //     };
    //     let Some((user, token)) = self
    //         .store
    //         .create_oauth_user(provider_name.clone(), unmatched_token)
    //         .await
    //     else {
    //         return Err("i dunno");
    //     };
    // }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn log_in(mut self, x: String, user_id: Uuid) -> Self {
        let session_id = Uuid::new_v4();

        let session = Session {
            id: session_id,
            user_id,
            provider: x,
        };

        self.store.create_session(session).await;

        self.jar = self.jar.add(
            Cookie::build(("session_id", session_id.to_string()))
                .same_site(SameSite::Strict)
                .http_only(true)
                .expires(Expiration::Session)
                .secure(true)
                .build(),
        );

        self
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn log_out(self) -> Self {
        if let Some(session) = self.jar.get("session_id") {
            if let Ok(session_id) = Uuid::parse_str(session.value()) {
                self.store.delete_session(session_id).await;
            }
        }

        self
    }

    fn session_id_cookie(&self) -> Option<Uuid> {
        let session_id_cookie = self.jar.get("session_id")?;

        let Ok(session_id) = Uuid::parse_str(session_id_cookie.value()) else {
            return None;
        };

        Some(session_id)
    }

    pub async fn logged_in(&self) -> bool {
        let Some(session_id) = self.session_id_cookie() else {
            return false;
        };

        self.store.get_session(session_id).await.is_some()
    }

    pub async fn user(&self) -> Option<S::User> {
        let session_id = self.session_id_cookie()?;
        let session = self.store.get_session(session_id).await?;

        self.store.get_user(session.user_id).await
    }
}

impl<S: Store> IntoResponseParts for AuthSession<S> {
    type Error = Infallible;

    fn into_response_parts(
        self,
        res: axum::response::ResponseParts,
    ) -> Result<axum::response::ResponseParts, Self::Error> {
        self.jar.into_response_parts(res)
    }
}

#[async_trait]
impl<S, K, St> FromRequestParts<S> for AuthSession<St, K>
where
    Smtp: FromRef<S>,
    OAuth: FromRef<S>,
    S: Send + Sync,
    K: FromRef<S> + Into<Key>,
    St: Store + FromRef<S>,
{
    type Rejection = (StatusCode, &'static str);
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Ok(jar) = PrivateCookieJar::<K>::from_request_parts(parts, state).await else {
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "No cookie jar found"));
        };
        let store = St::from_ref(state);
        let smtp = Smtp::from_ref(state);
        let oauth = OAuth::from_ref(state);

        return Ok(AuthSession {
            jar,
            store,
            smtp,
            oauth,
        });
    }
}
