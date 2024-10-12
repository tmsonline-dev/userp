#[cfg(feature = "password")]
use crate::PasswordReset;

#[cfg(feature = "password")]
use super::LoginSession;
use super::{Allow, AxumUser, AxumUserStore, LoginMethod, User};
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
    fn address(&self) -> String;
    fn verified(&self) -> bool;
    fn allow_link_login(&self) -> bool;
}

pub trait EmailChallenge: Send + Sync {
    fn address(&self) -> String;
    fn code(&self) -> String;
    fn next(&self) -> Option<String>;
    fn expires(&self) -> DateTime<Utc>;
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

#[derive(Debug, Error)]
pub enum EmailLoginInitError<StoreError: std::error::Error> {
    #[error(transparent)]
    SendingEmail(#[from] SendEmailChallengeError<StoreError>),
    #[error("Login not allowed")]
    NotAllowed,
}

#[derive(Debug, Error)]
pub enum EmailSignupInitError<StoreError: std::error::Error> {
    #[error(transparent)]
    SendingEmail(#[from] SendEmailChallengeError<StoreError>),
    #[error("Signup not allowed")]
    NotAllowed,
}

#[derive(Debug, Error)]
pub enum EmailResetInitError<StoreError: std::error::Error> {
    #[error(transparent)]
    SendingEmail(#[from] SendEmailChallengeError<StoreError>),
    #[error("Reset not allowed")]
    NotAllowed,
}

#[derive(Error, Debug)]
pub enum EmailLoginError<StoreError: std::error::Error> {
    #[error("Email login not allowed")]
    NotAllowed,
    #[error("Address not verified")]
    NotVerified,
    #[error("Email user not found")]
    NoUser,
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[derive(Error, Debug)]
pub enum EmailSignupError<StoreError: std::error::Error> {
    #[error("Email signup not allowed")]
    NotAllowed,
    #[error("User already exists")]
    UserExists,
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[derive(Error, Debug)]
pub enum EmailResetError<StoreError: std::error::Error> {
    #[error("Email reset not allowed")]
    NotAllowed,
    #[error("Address not verified")]
    NotVerified,
    #[error("Email user not found")]
    NoUser,
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[derive(Error, Debug)]
pub enum EmailVerifyError<StoreError: std::error::Error> {
    #[error("Email user not found")]
    NoUser,
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[derive(Error, Debug)]
pub enum EmailLoginCallbackError<StoreError: std::error::Error> {
    #[error("Email login not allowed")]
    NotAllowed,
    #[error("Challenge expired")]
    ChallengeExpired,
    #[error("Challenge not found")]
    ChallengeNotFound,
    #[error(transparent)]
    EmailLoginError(#[from] EmailLoginError<StoreError>),
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[derive(Error, Debug)]
pub enum EmailSignupCallbackError<StoreError: std::error::Error> {
    #[error("Email signup not allowed")]
    NotAllowed,
    #[error("Challenge expired")]
    ChallengeExpired,
    #[error("Challenge not found")]
    ChallengeNotFound,
    #[error(transparent)]
    EmailSignupError(#[from] EmailSignupError<StoreError>),
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[derive(Debug, Error)]
pub enum EmailResetCallbackError<StoreError: std::error::Error> {
    #[error("Email reset not allowed")]
    NotAllowed,
    #[error("Challenge expired")]
    ChallengeExpired,
    #[error("Challenge not found")]
    ChallengeNotFound,
    #[error(transparent)]
    EmailResetError(#[from] EmailResetError<StoreError>),
    #[error(transparent)]
    Store(#[from] StoreError),
}

#[derive(Debug, Error)]
pub enum EmailVerifyCallbackError<StoreError: std::error::Error> {
    #[error("Challenge expired")]
    ChallengeExpired,
    #[error("Challenge not found")]
    ChallengeNotFound,
    #[error(transparent)]
    EmailVerifyError(#[from] EmailVerifyError<StoreError>),
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

        let code = challenge.code();

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
                .address()
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

    pub async fn email_login_init(
        &self,
        email: String,
        next: Option<String>,
    ) -> Result<(), EmailLoginInitError<S::Error>> {
        if self.email.allow_login.as_ref().unwrap_or(&self.allow_login) == &Allow::Never {
            return Err(EmailLoginInitError::NotAllowed);
        }

        self.send_email_challenge(
            self.email.login_path.clone(),
            email,
            "Click here to log in".into(),
            next,
        )
        .await?;

        Ok(())
    }

    #[cfg(feature = "password")]
    pub async fn email_reset_init(
        &self,
        email: String,
        next: Option<String>,
    ) -> Result<(), EmailResetInitError<S::Error>> {
        if self.pass.allow_reset == PasswordReset::Never {
            return Err(EmailResetInitError::NotAllowed);
        }

        self.send_email_challenge(
            self.email.reset_pw_path.clone(),
            email,
            "Click here to reset password".into(),
            next,
        )
        .await?;

        Ok(())
    }

    pub async fn email_verify_init(
        &self,
        email: String,
        next: Option<String>,
    ) -> Result<(), SendEmailChallengeError<S::Error>> {
        self.send_email_challenge(
            self.email.verify_path.clone(),
            email,
            "Click here to verify email".into(),
            next,
        )
        .await?;

        Ok(())
    }

    pub async fn email_signup_init(
        &self,
        email: String,
        next: Option<String>,
    ) -> Result<(), EmailSignupInitError<S::Error>> {
        if self
            .email
            .allow_signup
            .as_ref()
            .unwrap_or(&self.allow_signup)
            == &Allow::Never
        {
            return Err(EmailSignupInitError::NotAllowed);
        }

        self.send_email_challenge(
            self.email.signup_path.clone(),
            email,
            "Click here to sign up".into(),
            next,
        )
        .await?;

        Ok(())
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn email_login_callback(
        self,
        code: String,
    ) -> Result<(Self, Option<String>), EmailLoginCallbackError<S::Error>> {
        if self.email.allow_login.as_ref().unwrap_or(&self.allow_login) == &Allow::Never {
            return Err(EmailLoginCallbackError::NotAllowed);
        }

        let Some(challenge) = self
            .store
            .email_consume_challenge(code)
            .await
            .map_err(EmailLoginError::Store)?
        else {
            return Err(EmailLoginCallbackError::ChallengeNotFound);
        };

        if challenge.expires() < Utc::now() {
            return Err(EmailLoginCallbackError::ChallengeExpired);
        }

        let user = self
            .store
            .email_login(
                challenge.address(),
                self.email
                    .allow_signup
                    .as_ref()
                    .unwrap_or(&self.allow_signup)
                    == &Allow::OnEither,
            )
            .await?;

        Ok((
            self.log_in(
                LoginMethod::Email {
                    address: challenge.address(),
                },
                user.get_id(),
            )
            .await?,
            challenge.next(),
        ))
    }

    #[cfg(feature = "password")]
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn email_reset_callback(
        self,
        code: String,
    ) -> Result<Self, EmailResetCallbackError<S::Error>> {
        use crate::password::PasswordReset;

        if self.pass.allow_reset == PasswordReset::Never {
            return Err(EmailResetCallbackError::NotAllowed);
        }

        let Some(challenge) = self
            .store
            .email_consume_challenge(code)
            .await
            .map_err(EmailResetError::Store)?
        else {
            return Err(EmailResetCallbackError::ChallengeNotFound);
        };

        if challenge.expires() < Utc::now() {
            return Err(EmailResetCallbackError::ChallengeExpired);
        }

        let user = self
            .store
            .email_reset(
                challenge.address(),
                self.pass.allow_reset == PasswordReset::VerifiedEmailOnly,
            )
            .await?;

        Ok(self
            .log_in(
                LoginMethod::PasswordReset {
                    address: challenge.address(),
                },
                user.get_id(),
            )
            .await?)
    }

    #[cfg(feature = "password")]
    pub async fn is_reset_session(&self) -> Result<bool, S::Error> {
        Ok(self.reset_session().await?.is_some())
    }

    #[cfg(feature = "password")]
    pub async fn reset_session(&self) -> Result<Option<S::LoginSession>, S::Error> {
        let Some(session_id) = self.session_id_cookie() else {
            return Ok(None);
        };

        Ok(self
            .store
            .get_session(session_id)
            .await?
            .filter(|s| matches!(s.get_method(), LoginMethod::PasswordReset { address: _ })))
    }

    #[cfg(feature = "password")]
    pub async fn reset_user_session(&self) -> Result<Option<(S::User, S::LoginSession)>, S::Error> {
        let Some(session) = self.reset_session().await? else {
            return Ok(None);
        };

        Ok(self
            .store
            .get_user(session.get_user_id())
            .await?
            .map(|user| (user, session)))
    }

    #[cfg(feature = "password")]
    pub async fn reset_user(&self) -> Result<Option<S::User>, S::Error> {
        Ok(self.reset_user_session().await?.map(|(user, _)| user))
    }

    pub async fn email_verify_callback(
        &self,
        code: String,
    ) -> Result<(String, Option<String>), EmailVerifyCallbackError<S::Error>> {
        let Some(challenge) = self
            .store
            .email_consume_challenge(code)
            .await
            .map_err(EmailVerifyError::Store)?
        else {
            return Err(EmailVerifyCallbackError::ChallengeNotFound);
        };

        if challenge.expires() < Utc::now() {
            return Err(EmailVerifyCallbackError::ChallengeExpired);
        }

        self.store.email_verify(challenge.address()).await?;

        Ok((challenge.address(), challenge.next()))
    }

    pub async fn email_signup_callback(
        self,
        code: String,
    ) -> Result<(Self, Option<String>), EmailSignupCallbackError<S::Error>> {
        if self
            .email
            .allow_signup
            .as_ref()
            .unwrap_or(&self.allow_signup)
            == &Allow::Never
        {
            return Err(EmailSignupCallbackError::NotAllowed);
        }

        let Some(challenge) = self
            .store
            .email_consume_challenge(code)
            .await
            .map_err(EmailSignupError::Store)?
        else {
            return Err(EmailSignupCallbackError::ChallengeNotFound);
        };

        if challenge.expires() < Utc::now() {
            return Err(EmailSignupCallbackError::ChallengeExpired);
        }

        let user = self
            .store
            .email_signup(
                challenge.address(),
                self.email.allow_login.as_ref().unwrap_or(&self.allow_login) == &Allow::OnEither,
            )
            .await?;

        Ok((
            self.log_in(
                LoginMethod::Email {
                    address: challenge.address(),
                },
                user.get_id(),
            )
            .await?,
            challenge.next(),
        ))
    }
}
