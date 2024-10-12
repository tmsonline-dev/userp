#[cfg(feature = "email")]
mod email;
#[cfg(feature = "oauth")]
mod oauth;
#[cfg(feature = "password")]
mod password;

mod routes;

const SESSION_ID_KEY: &str = "axum-user-session-id";
use chrono::{DateTime, Utc};

#[cfg(feature = "email")]
pub use self::email::{EmailChallenge, EmailConfig, EmailPaths, SmtpSettings, UserEmail};
#[cfg(feature = "oauth")]
pub use self::oauth::{
    provider, AuthorizationCode, CsrfToken, CustomOAuthClient, OAuthConfig, OAuthPaths,
    OAuthProviderUser, OAuthProviderUserResult, OAuthProviders, OAuthToken, RefreshInitResult,
    UnmatchedOAuthToken,
};
#[cfg(all(feature = "password", feature = "email"))]
pub use self::password::PasswordReset;
#[cfg(feature = "password")]
pub use self::password::{PasswordConfig, PasswordLoginError, PasswordSignupError};

pub use axum_extra::{self, extract::cookie::Key};
pub use chrono;
pub use url;
pub use uuid;

use uuid::Uuid;

use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
    response::IntoResponseParts,
};
use axum_extra::extract::cookie::{Cookie, Expiration, PrivateCookieJar, SameSite};
use std::{convert::Infallible, fmt::Display};

pub trait LoginSession: Send + Sync {
    fn get_id(&self) -> Uuid;
    fn get_user_id(&self) -> Uuid;
    fn get_method(&self) -> LoginMethod;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginMethod {
    #[cfg(feature = "password")]
    Password,
    #[cfg(all(feature = "password", feature = "email"))]
    PasswordReset { address: String },
    #[cfg(feature = "email")]
    Email { address: String },
    #[cfg(feature = "oauth")]
    OAuth { token_id: Uuid },
}

impl Display for LoginMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{self:#?}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Allow {
    Never,
    OnSelf,
    OnEither,
}

pub trait User: Send + Sync {
    fn get_id(&self) -> Uuid;

    #[cfg(feature = "password")]
    fn get_password_hash(&self) -> Option<String>;
    #[cfg(feature = "password")]
    fn validate_password_hash(&self, password_hash: String) -> bool {
        self.get_password_hash()
            .is_some_and(|hash| password_hash == hash)
    }
}

#[async_trait]
pub trait AxumUserStore {
    type User: User;
    #[cfg(feature = "email")]
    type UserEmail: UserEmail;
    type LoginSession: LoginSession;
    type EmailChallenge: EmailChallenge;
    type OAuthToken: OAuthToken;
    type Error: std::error::Error;

    // session store
    async fn create_session(&self, user_id: Uuid, method: LoginMethod) -> Self::LoginSession;
    async fn get_session(&self, session_id: Uuid) -> Option<Self::LoginSession>;
    async fn delete_session(&self, session_id: Uuid);

    // user store
    async fn get_user(&self, user_id: Uuid) -> Option<Self::User>;

    // password user store
    #[cfg(feature = "password")]
    async fn password_login(
        &self,
        password_id: String,
        password_hash: String,
        allow_signup: bool,
    ) -> Result<Self::User, PasswordLoginError<Self::Error>>;
    async fn password_signup(
        &self,
        password_id: String,
        password_hash: String,
        allow_login: bool,
    ) -> Result<Self::User, PasswordSignupError<Self::Error>>;

    // email user store
    #[cfg(feature = "email")]
    async fn get_user_by_email(&self, email: String) -> Option<(Self::User, Self::UserEmail)>;
    #[cfg(feature = "email")]
    async fn save_email_challenge(
        &self,
        address: String,
        code: String,
        next: Option<String>,
        expires: DateTime<Utc>,
    ) -> Self::EmailChallenge;
    #[cfg(feature = "email")]
    async fn consume_email_challenge(&self, code: String) -> Option<Self::EmailChallenge>;
    #[cfg(feature = "email")]
    async fn set_user_email_verified(&self, user_id: Uuid, address: String);
    #[cfg(feature = "email")]
    async fn create_email_user(&self, address: String) -> (Self::User, Self::UserEmail);

    // oauth token store
    #[cfg(feature = "oauth")]
    async fn get_user_by_oauth_provider_id(
        &self,
        provider_name: String,
        provider_user_id: String,
    ) -> Option<(Self::User, Self::OAuthToken)>;
    #[cfg(feature = "oauth")]
    async fn update_oauth_token(
        &self,
        token: Self::OAuthToken,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Self::OAuthToken;
    #[cfg(feature = "oauth")]
    async fn link_oauth_token(
        &self,
        user_id: Uuid,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Self::OAuthToken;
    #[cfg(feature = "oauth")]
    async fn create_oauth_user(
        &self,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Option<(Self::User, Self::OAuthToken)>;
    #[cfg(feature = "oauth")]
    async fn get_oauth_token(&self, token_id: Uuid) -> Option<Self::OAuthToken>;
}

#[async_trait]
pub trait AxumUserExtendedStore: AxumUserStore {
    async fn get_sessions(&self, user_id: Uuid) -> Vec<Self::LoginSession>;
    async fn get_oauth_tokens(&self, user_id: Uuid) -> Vec<Self::OAuthToken>;
    async fn delete_oauth_token(&self, token_id: Uuid);
    async fn delete_user(&self, id: Uuid);
    async fn clear_user_password(&self, user_id: Uuid, session_id: Uuid);
    async fn get_user_emails(&self, user_id: Uuid) -> Vec<Self::UserEmail>;
    async fn set_user_password(&self, user_id: Uuid, password: String, session_id: Uuid);
    async fn set_user_email_allow_login(&self, user_id: Uuid, address: String, allow_login: bool);
    async fn add_user_email(&self, user_id: Uuid, address: String);
    async fn delete_user_email(&self, user_id: Uuid, address: String);
}

pub struct AxumUser<S: AxumUserStore> {
    allow_signup: Allow,
    allow_login: Allow,
    jar: PrivateCookieJar,
    https_only: bool,
    store: S,
    #[cfg(feature = "password")]
    pass: PasswordConfig,
    #[cfg(feature = "email")]
    email: EmailConfig,
    #[cfg(feature = "oauth")]
    oauth: OAuthConfig,
}

impl<S: AxumUserStore> AxumUser<S> {
    async fn log_in(mut self, method: LoginMethod, user_id: Uuid) -> Self {
        let session = self.store.create_session(user_id, method).await;

        self.jar = self.jar.add(
            Cookie::build((SESSION_ID_KEY, session.get_id().to_string()))
                .same_site(SameSite::Lax)
                .http_only(true)
                .expires(Expiration::Session)
                .secure(self.https_only)
                .path("/")
                .build(),
        );

        self
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn log_out(mut self) -> Self {
        if let Some(session) = self.jar.get(SESSION_ID_KEY) {
            if let Ok(session_id) = Uuid::parse_str(session.value()) {
                self.store.delete_session(session_id).await;
                self.jar = self.jar.remove(SESSION_ID_KEY)
            }
        }

        self
    }

    fn session_id_cookie(&self) -> Option<Uuid> {
        let Some(session_id_cookie) = self.jar.get(SESSION_ID_KEY) else {
            println!("No session ID cookie found");
            return None;
        };

        let Ok(session_id) = Uuid::parse_str(session_id_cookie.value()) else {
            println!("Session ID not a UUID");
            return None;
        };

        Some(session_id)
    }

    fn is_login_session(session: &S::LoginSession) -> bool {
        #[cfg(all(feature = "password", feature = "email"))]
        return !matches!(
            session.get_method(),
            LoginMethod::PasswordReset { address: _ }
        );

        #[cfg(not(all(feature = "password", feature = "email")))]
        return true;
    }

    pub async fn logged_in(&self) -> bool {
        self.session().await.is_some()
    }

    pub async fn session(&self) -> Option<S::LoginSession> {
        let session_id = self.session_id_cookie()?;
        println!("Finding session by id: {session_id:#?}");
        self.store
            .get_session(session_id)
            .await
            .filter(Self::is_login_session)
    }

    pub async fn user_session(&self) -> Option<(S::User, S::LoginSession)> {
        let session = self.session().await?;
        println!("Finding user by id: {:#?}", session.get_user_id());
        self.store
            .get_user(session.get_user_id())
            .await
            .map(|user| (user, session))
    }

    pub async fn user(&self) -> Option<S::User> {
        self.user_session().await.map(|(user, _)| user)
    }
}

impl<S: AxumUserStore> IntoResponseParts for AxumUser<S> {
    type Error = Infallible;

    fn into_response_parts(
        self,
        res: axum::response::ResponseParts,
    ) -> Result<axum::response::ResponseParts, Self::Error> {
        self.jar.into_response_parts(res)
    }
}

#[derive(Clone)]
pub struct AxumUserConfig {
    pub key: Key,
    pub allow_signup: Allow,
    pub allow_login: Allow,
    pub https_only: bool,
    #[cfg(feature = "password")]
    pub pass: PasswordConfig,
    #[cfg(feature = "email")]
    pub email: EmailConfig,
    #[cfg(feature = "oauth")]
    pub oauth: OAuthConfig,
}

impl AxumUserConfig {
    pub fn new(
        key: Key,
        #[cfg(feature = "password")] pass: PasswordConfig,
        #[cfg(feature = "email")] email: EmailConfig,
        #[cfg(feature = "oauth")] oauth: OAuthConfig,
    ) -> Self {
        Self {
            key,
            https_only: true,
            allow_signup: Allow::OnSelf,
            allow_login: Allow::OnEither,
            #[cfg(feature = "password")]
            pass,
            #[cfg(feature = "email")]
            email,
            #[cfg(feature = "oauth")]
            oauth,
        }
    }

    pub fn with_https_only(mut self, https_only: bool) -> Self {
        self.https_only = https_only;
        self
    }

    pub fn with_allow_signup(mut self, allow_signup: Allow) -> Self {
        self.allow_signup = allow_signup;
        self
    }

    pub fn with_allow_login(mut self, allow_login: Allow) -> Self {
        self.allow_login = allow_login;
        self
    }
}

#[async_trait]
impl<S, St> FromRequestParts<S> for AxumUser<St>
where
    St: AxumUserStore,
    AxumUserConfig: FromRef<S>,
    S: Send + Sync,
    St: AxumUserStore + FromRef<S>,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Infallible> {
        let config = AxumUserConfig::from_ref(state);
        let jar = PrivateCookieJar::from_headers(&parts.headers, config.key);
        let store = St::from_ref(state);

        return Ok(AxumUser {
            allow_signup: config.allow_signup,
            allow_login: config.allow_login,
            https_only: config.https_only,
            jar,
            store,
            #[cfg(feature = "email")]
            email: config.email,
            #[cfg(feature = "password")]
            pass: config.pass,
            #[cfg(feature = "oauth")]
            oauth: config.oauth,
        });
    }
}
