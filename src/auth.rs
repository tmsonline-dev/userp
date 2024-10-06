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
    ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde_json::Value;
use std::{collections::HashMap, convert::Infallible, sync::Arc};
use url::Url;
use uuid::Uuid;

#[derive(Clone)]
pub struct LoginSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub method: LoginMethod,
}

#[derive(Clone, PartialEq, Eq)]
pub enum LoginMethod {
    Password,
    Email { address: String },
    OAuth { token_id: Uuid },
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowLogin {
    Never,
    OnLogin,
    OnLoginAndSignup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowSignup {
    Never,
    OnSignup,
    OnSignupAndLogin,
}

#[derive(Clone)]
pub struct OAuthConfig {
    pub allow_login: AllowLogin,
    pub allow_signup: AllowSignup,
    pub base_redirect_url: Url,
    pub clients: OAuthClients,
}

#[derive(Clone)]
pub struct PasswordConfig {
    pub allow_login: AllowLogin,
    pub allow_signup: AllowSignup,
}

#[derive(Clone, Default)]
pub struct OAuthClients(Arc<HashMap<String, Box<dyn OAuthProviderTrait>>>);

pub trait UserTrait {
    fn get_password_hash(&self) -> Option<String>;
    fn get_id(&self) -> Uuid;
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
    type User: UserTrait;

    // session store
    async fn create_session(&self, session: LoginSession);
    async fn get_session(&self, session_id: Uuid) -> Option<LoginSession>;
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
    async fn set_user_email_verified(&self, user_id: Uuid, email: String);
    async fn create_email_user(&self, email: String) -> (Self::User, Email);

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

pub struct User<S: Store, K = Key> {
    jar: PrivateCookieJar<K>,
    store: S,
    pass: PasswordConfig,
    email: EmailConfig,
    oauth: OAuthConfig,
}

#[derive(Debug, Clone)]
pub struct EmailConfig {
    pub allow_login: AllowLogin,
    pub allow_signup: AllowSignup,

    pub base_url: Url,
    pub login_path: String,
    pub verify_path: String,
    pub signup_path: String,

    pub smtp: Smtp,
}

#[derive(Debug, Clone)]
pub struct Smtp {
    pub server_url: String,
    pub username: String,
    pub password: String,
    pub from: String,
    pub starttls: bool,
}

impl<S: Store> User<S> {
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

        Ok(self.log_in(LoginMethod::Password, user.get_id()).await)
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

        let Some(hash) = user.get_password_hash() else {
            return Err((self, "No password"));
        };

        if hash != password_hash {
            return Err((self, "Wrong password"));
        };

        Ok(self.log_in(LoginMethod::Password, user.get_id()).await)
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
            .email
            .base_url
            .join(&format!("{path}?code={code}"))
            .unwrap();

        let email = Message::builder()
            .from(self.email.smtp.from.parse().unwrap())
            .to(email.parse().unwrap())
            .subject("Login link")
            .header(ContentType::TEXT_HTML)
            .body(format!("<a href=\"{url}\">{message}</a>"))
            .unwrap();

        let mailer = (if self.email.smtp.starttls {
            SmtpTransport::starttls_relay
        } else {
            SmtpTransport::relay
        })(self.email.smtp.server_url.as_str())
        .unwrap()
        .credentials(lettre::transport::smtp::authentication::Credentials::new(
            self.email.smtp.username.clone(),
            self.email.smtp.password.clone(),
        ))
        .build();

        mailer.send(&email).unwrap();

        Ok(())
    }

    pub async fn email_login_init(&self, email: String, next: Option<String>) {
        self.send_email_challenge(
            self.email.login_path.clone(),
            email,
            "Click here to log in".into(),
            next,
        )
        .await
        .unwrap()
    }

    pub async fn email_verify_init(&self, email: String, next: Option<String>) {
        self.send_email_challenge(
            self.email.verify_path.clone(),
            email,
            "Click here to verify email".into(),
            next,
        )
        .await
        .unwrap()
    }

    pub async fn email_signup_init(&self, email: String, next: Option<String>) {
        self.send_email_challenge(
            self.email.signup_path.clone(),
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
                .set_user_email_verified(user.get_id(), email.email.clone())
                .await;
        }

        Ok((
            self.log_in(
                LoginMethod::Email {
                    address: email.email,
                },
                user.get_id(),
            )
            .await,
            next,
        ))
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
            return if self.email.allow_signup == AllowSignup::OnSignupAndLogin {
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
                .set_user_email_verified(user.get_id(), email.email)
                .await;
        }

        Ok(next)
    }

    async fn email_signup(
        self,
        address: String,
        next: Option<String>,
    ) -> Result<(Self, Option<String>), (Self, &'static str)> {
        let (user, email) = self.store.create_email_user(address).await;

        Ok((
            self.log_in(
                LoginMethod::Email {
                    address: email.email,
                },
                user.get_id(),
            )
            .await,
            next,
        ))
    }

    pub async fn email_signup_callback(
        self,
        code: String,
    ) -> Result<(Self, Option<String>), (Self, &'static str)> {
        let Some((email, existing, next)) = self.store.consume_email_challenge(code).await else {
            return Err((self, "Code not found"));
        };

        if let Some((user, email)) = existing {
            return if self.email.allow_login == AllowLogin::OnLoginAndSignup {
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

        self.store.update_oauth_token(new_token).await;

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

    async fn log_in(mut self, method: LoginMethod, user_id: Uuid) -> Self {
        let session_id = Uuid::new_v4();

        let session = LoginSession {
            id: session_id,
            user_id,
            method,
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

    pub async fn session(&self) -> Option<LoginSession> {
        let session_id = self.session_id_cookie()?;
        self.store.get_session(session_id).await
    }

    pub async fn user_session(&self) -> Option<(S::User, LoginSession)> {
        let session = self.session().await?;
        self.store
            .get_user(session.user_id)
            .await
            .map(|user| (user, session))
    }

    pub async fn user(&self) -> Option<S::User> {
        let session = &self.session().await?;
        self.store.get_user(session.user_id).await
    }
}

impl<S: Store> IntoResponseParts for User<S> {
    type Error = Infallible;

    fn into_response_parts(
        self,
        res: axum::response::ResponseParts,
    ) -> Result<axum::response::ResponseParts, Self::Error> {
        self.jar.into_response_parts(res)
    }
}

#[async_trait]
impl<S, K, St> FromRequestParts<S> for User<St, K>
where
    EmailConfig: FromRef<S>,
    OAuthConfig: FromRef<S>,
    PasswordConfig: FromRef<S>,
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
        let email = EmailConfig::from_ref(state);
        let oauth = OAuthConfig::from_ref(state);
        let pass = PasswordConfig::from_ref(state);

        return Ok(User {
            jar,
            store,
            email,
            pass,
            oauth,
        });
    }
}
