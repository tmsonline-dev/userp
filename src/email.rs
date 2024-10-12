mod login;
#[cfg(feature = "password")]
mod reset;
mod signup;
mod verify;

pub use login::*;
#[cfg(feature = "password")]
pub use reset::*;
pub use signup::*;
pub use verify::*;

use super::{Allow, AxumUser, AxumUserStore};
use chrono::{DateTime, Duration, Utc};
use lettre::{message::header::ContentType, Message, SmtpTransport, Transport};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct EmailConfig {
    pub allow_login: Option<Allow>,
    pub allow_signup: Option<Allow>,
    pub challenge_lifetime: Duration,
    pub base_url: Url,
    pub login_path: String,
    pub verify_path: String,
    pub signup_path: String,
    #[cfg(feature = "password")]
    pub reset_pw_path: String,
    pub smtp: SmtpSettings,
}

#[derive(Debug, Clone)]
pub struct EmailPaths {
    pub login: &'static str,
    pub verify: &'static str,
    pub signup: &'static str,
    #[cfg(feature = "password")]
    pub reset_pw: &'static str,
}

impl EmailConfig {
    pub fn new(base_url: Url, paths: EmailPaths, smtp: SmtpSettings) -> Self {
        Self {
            allow_login: None,
            allow_signup: None,
            challenge_lifetime: Duration::minutes(5),
            base_url,
            login_path: paths.login.to_string(),
            verify_path: paths.verify.to_string(),
            signup_path: paths.signup.to_string(),
            #[cfg(feature = "password")]
            reset_pw_path: paths.reset_pw.to_string(),
            smtp,
        }
    }

    pub fn with_allow_signup(mut self, allow_signup: Allow) -> Self {
        self.allow_signup = Some(allow_signup);
        self
    }

    pub fn with_allow_login(mut self, allow_login: Allow) -> Self {
        self.allow_login = Some(allow_login);
        self
    }

    pub fn with_challenge_lifetime(mut self, challenge_lifetime: Duration) -> Self {
        self.challenge_lifetime = challenge_lifetime;
        self
    }
}

#[derive(Debug, Clone)]
pub struct SmtpSettings {
    pub server_url: String,
    pub username: String,
    pub password: String,
    pub from: String,
    pub starttls: bool,
}

impl SmtpSettings {
    pub fn new(
        server_url: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        from: impl Into<String>,
        starttls: bool,
    ) -> Self {
        Self {
            server_url: server_url.into(),
            username: username.into(),
            password: password.into(),
            from: from.into(),
            starttls,
        }
    }
}

pub trait UserEmail: Send + Sync {
    fn get_address(&self) -> String;
    fn get_verified(&self) -> bool;
    fn get_allow_link_login(&self) -> bool;
}

pub trait EmailChallenge: Send + Sync {
    fn get_address(&self) -> String;
    fn get_code(&self) -> String;
    fn get_next(&self) -> Option<String>;
    fn get_expires(&self) -> DateTime<Utc>;
}

#[derive(Debug, Error)]
pub enum SendEmailChallengeError<StoreError: std::error::Error> {
    #[error(transparent)]
    Url(url::ParseError),
    #[error(transparent)]
    Address(lettre::address::AddressError),
    #[error(transparent)]
    MessageBuilding(lettre::error::Error),
    #[error(transparent)]
    Transport(lettre::transport::smtp::Error),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl<S: AxumUserStore> AxumUser<S> {
    async fn send_email_challenge(
        &self,
        path: String,
        address: String,
        message: String,
        next: Option<String>,
    ) -> Result<(), SendEmailChallengeError<S::Error>> {
        let code = Uuid::new_v4().to_string().replace('-', "");

        let challenge = self
            .store
            .email_create_challenge(
                address,
                code,
                next,
                Utc::now() + self.email.challenge_lifetime,
            )
            .await?;

        let code = challenge.get_code();

        let url = self
            .email
            .base_url
            .join(&format!("{path}?code={code}"))
            .map_err(SendEmailChallengeError::Url)?;

        let email = Message::builder()
            .from(
                self.email
                    .smtp
                    .from
                    .parse()
                    .map_err(SendEmailChallengeError::Address)?,
            )
            .to(challenge
                .get_address()
                .parse()
                .map_err(SendEmailChallengeError::Address)?)
            .subject("Login link")
            .header(ContentType::TEXT_HTML)
            .body(format!("<a href=\"{url}\">{message}</a>"))
            .map_err(SendEmailChallengeError::MessageBuilding)?;

        let transport = if self.email.smtp.starttls {
            SmtpTransport::starttls_relay
        } else {
            SmtpTransport::relay
        };

        let mailer = (transport)(self.email.smtp.server_url.as_str())
            .map_err(SendEmailChallengeError::Transport)?
            .credentials(lettre::transport::smtp::authentication::Credentials::new(
                self.email.smtp.username.clone(),
                self.email.smtp.password.clone(),
            ))
            .build();

        mailer
            .send(&email)
            .map_err(SendEmailChallengeError::Transport)?;

        Ok(())
    }
}
