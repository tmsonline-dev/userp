#[cfg(all(feature = "password", feature = "email"))]
use crate::email::reset::EmailResetError;
#[cfg(feature = "email")]
use crate::email::{
    login::EmailLoginError, signup::EmailSignupError, verify::EmailVerifyError, EmailChallenge,
    UserEmail,
};
#[cfg(feature = "oauth")]
use crate::oauth::{
    link::OAuthLinkError, login::OAuthLoginError, signup::OAuthSignupError, OAuthToken,
    UnmatchedOAuthToken,
};
#[cfg(feature = "password")]
use crate::password::{login::PasswordLoginError, signup::PasswordSignupError};

use crate::{
    enums::LoginMethod,
    traits::{LoginSession, User},
};
use async_trait::async_trait;
#[cfg(feature = "email")]
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[async_trait]
pub trait UserpStore {
    type User: User;
    type LoginSession: LoginSession;
    type Error: std::error::Error + Send;

    #[cfg(feature = "email")]
    type UserEmail: UserEmail;
    #[cfg(feature = "email")]
    type EmailChallenge: EmailChallenge;
    #[cfg(feature = "oauth")]
    type OAuthToken: OAuthToken;

    // session store
    async fn create_session(
        &self,
        user_id: Uuid,
        method: LoginMethod,
    ) -> Result<Self::LoginSession, Self::Error>;
    async fn get_session(
        &self,
        session_id: Uuid,
    ) -> Result<Option<Self::LoginSession>, Self::Error>;
    async fn delete_session(&self, session_id: Uuid) -> Result<(), Self::Error>;

    // user store
    async fn get_user(&self, user_id: Uuid) -> Result<Option<Self::User>, Self::Error>;

    // password user store
    #[cfg(feature = "password")]
    async fn password_login(
        &self,
        password_id: &str,
        password: &str,
        allow_signup: bool,
    ) -> Result<Self::User, PasswordLoginError<Self::Error>>;
    #[cfg(feature = "password")]
    async fn password_signup(
        &self,
        password_id: &str,
        password: &str,
        allow_login: bool,
    ) -> Result<Self::User, PasswordSignupError<Self::Error>>;

    // email user store
    #[cfg(feature = "email")]
    async fn email_login(
        &self,
        address: &str,
        allow_signup: bool,
    ) -> Result<Self::User, EmailLoginError<Self::Error>>;
    #[cfg(feature = "email")]
    async fn email_signup(
        &self,
        address: &str,
        allow_login: bool,
    ) -> Result<Self::User, EmailSignupError<Self::Error>>;
    #[cfg(all(feature = "email", feature = "password"))]
    async fn email_reset(
        &self,
        address: &str,
        require_verified_address: bool,
    ) -> Result<Self::User, EmailResetError<Self::Error>>;
    #[cfg(feature = "email")]
    async fn email_verify(&self, address: &str) -> Result<(), EmailVerifyError<Self::Error>>;
    #[cfg(feature = "email")]
    async fn email_create_challenge(
        &self,
        address: String,
        code: String,
        next: Option<String>,
        expires: DateTime<Utc>,
    ) -> Result<Self::EmailChallenge, Self::Error>;
    #[cfg(feature = "email")]
    async fn email_consume_challenge(
        &self,
        code: String,
    ) -> Result<Option<Self::EmailChallenge>, Self::Error>;

    // oauth token store
    #[cfg(feature = "oauth")]
    async fn oauth_signup(
        &self,
        unmatched_token: UnmatchedOAuthToken,
        allow_login: bool,
    ) -> Result<(Self::User, Self::OAuthToken), OAuthSignupError<Self::Error>>;
    #[cfg(feature = "oauth")]
    async fn oauth_login(
        &self,
        unmatched_token: UnmatchedOAuthToken,
        allow_signup: bool,
    ) -> Result<(Self::User, Self::OAuthToken), OAuthLoginError<Self::Error>>;
    #[cfg(feature = "oauth")]
    async fn oauth_link(
        &self,
        user_id: Uuid,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Self::OAuthToken, OAuthLinkError<Self::Error>>;
    #[cfg(feature = "oauth")]
    async fn oauth_update_token(
        &self,
        token: Self::OAuthToken,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Self::OAuthToken, Self::Error>;
    #[cfg(feature = "oauth")]
    async fn oauth_get_token(
        &self,
        token_id: Uuid,
    ) -> Result<Option<Self::OAuthToken>, Self::Error>;

    #[cfg(feature = "account")]
    async fn get_user_sessions(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<Self::LoginSession>, Self::Error>;
    #[cfg(all(feature = "account", feature = "oauth"))]
    async fn get_user_oauth_tokens(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<Self::OAuthToken>, Self::Error>;
    #[cfg(all(feature = "account", feature = "oauth"))]
    async fn delete_oauth_token(&self, token_id: Uuid) -> Result<(), Self::Error>;
    #[cfg(feature = "account")]
    async fn delete_user(&self, id: Uuid) -> Result<(), Self::Error>;
    #[cfg(all(feature = "account", feature = "password"))]
    async fn clear_user_password(&self, user_id: Uuid, session_id: Uuid)
        -> Result<(), Self::Error>;
    #[cfg(all(feature = "account", feature = "email"))]
    async fn get_user_emails(&self, user_id: Uuid) -> Result<Vec<Self::UserEmail>, Self::Error>;
    #[cfg(all(feature = "account", feature = "password"))]
    async fn set_user_password(
        &self,
        user_id: Uuid,
        password: String,
        session_id: Uuid,
    ) -> Result<(), Self::Error>;
    #[cfg(all(feature = "account", feature = "email"))]
    async fn set_user_email_allow_link_login(
        &self,
        user_id: Uuid,
        address: String,
        allow_login: bool,
    ) -> Result<(), Self::Error>;
    #[cfg(all(feature = "account", feature = "email"))]
    async fn add_user_email(&self, user_id: Uuid, address: String) -> Result<(), Self::Error>;
    #[cfg(all(feature = "account", feature = "email"))]
    async fn delete_user_email(&self, user_id: Uuid, address: String) -> Result<(), Self::Error>;
}
