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
    fn allow_login(&self) -> bool;
}

pub trait EmailChallenge: Send + Sync {
    fn address(&self) -> String;
    fn code(&self) -> String;
    fn next(&self) -> Option<String>;
    fn expires(&self) -> DateTime<Utc>;
}

#[derive(Debug, Error)]
pub enum SendEmailError {
    #[error(transparent)]
    UrlParsing(#[from] url::ParseError),
    #[error(transparent)]
    AddressParsing(#[from] lettre::address::AddressError),
    #[error(transparent)]
    MessageBuilding(#[from] lettre::error::Error),
    #[error(transparent)]
    MessageSending(#[from] lettre::transport::smtp::Error),
}

#[derive(Debug, Error)]
pub enum EmailLoginInitError {
    #[error(transparent)]
    SendingEmail(#[from] SendEmailError),
    #[error("Login not allowed")]
    NotAllowed,
}

#[derive(Debug, Error)]
pub enum EmailSignupInitError {
    #[error(transparent)]
    SendingEmail(#[from] SendEmailError),
    #[error("Signup not allowed")]
    NotAllowed,
}

#[derive(Debug, Error)]
pub enum EmailResetInitError {
    #[error(transparent)]
    SendingEmail(#[from] SendEmailError),
    #[error("Reset not allowed")]
    NotAllowed,
}

#[derive(Debug, Error)]
pub enum EmailLoginError {
    #[error("Login not allowed for address {0}")]
    NotAllowed(String),
}

#[derive(Error, Debug)]
pub enum EmailLoginCallbackError {
    #[error("Email login not allowed")]
    NotAllowed,
    #[error("Challenge expired")]
    ChallengeExpired,
    #[error("Challenge not found")]
    ChallengeNotFound,
    #[error("No user found")]
    NoUser,
    #[error(transparent)]
    EmailLoginError(#[from] EmailLoginError),
    #[error(transparent)]
    EmailSignupError(#[from] EmailSignupError),
}

#[derive(Error, Debug)]
pub enum EmailSignupCallbackError {
    #[error("Email signup not allowed")]
    NotAllowed,
    #[error("Challenge expired")]
    ChallengeExpired,
    #[error("Challenge not found")]
    ChallengeNotFound,
    #[error("User exists")]
    UserConflict,
    #[error(transparent)]
    EmailLoginError(#[from] EmailLoginError),
    #[error(transparent)]
    EmailSignupError(#[from] EmailSignupError),
}

#[derive(Debug, Error)]
pub enum EmailSignupError {
    #[error("Email address already assigned to a user: {0}")]
    AddressConflict(String),
}

impl<S: AxumUserStore> AxumUser<S> {
    async fn send_email_challenge(
        &self,
        path: String,
        address: String,
        message: String,
        next: Option<String>,
    ) -> Result<(), SendEmailError> {
        let code = Uuid::new_v4().to_string().replace('-', "");

        let challenge = self
            .store
            .save_email_challenge(
                address,
                code,
                next,
                Utc::now() + self.email.challenge_lifetime,
            )
            .await;

        let code = challenge.code();

        let url = self.email.base_url.join(&format!("{path}?code={code}"))?;

        let email = Message::builder()
            .from(self.email.smtp.from.parse()?)
            .to(challenge.address().parse()?)
            .subject("Login link")
            .header(ContentType::TEXT_HTML)
            .body(format!("<a href=\"{url}\">{message}</a>"))?;

        let transport = if self.email.smtp.starttls {
            SmtpTransport::starttls_relay
        } else {
            SmtpTransport::relay
        };

        let mailer = (transport)(self.email.smtp.server_url.as_str())?
            .credentials(lettre::transport::smtp::authentication::Credentials::new(
                self.email.smtp.username.clone(),
                self.email.smtp.password.clone(),
            ))
            .build();

        mailer.send(&email)?;

        Ok(())
    }

    pub async fn email_login_init(
        &self,
        email: String,
        next: Option<String>,
    ) -> Result<(), EmailLoginInitError> {
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
    ) -> Result<(), EmailResetInitError> {
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
    ) -> Result<(), SendEmailError> {
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
    ) -> Result<(), EmailSignupInitError> {
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

    async fn email_login(
        self,
        user: S::User,
        email: S::UserEmail,
        next: Option<String>,
    ) -> Result<(Self, Option<String>), EmailLoginError> {
        if !email.allow_login() {
            return Err(EmailLoginError::NotAllowed(email.address()));
        }

        if !email.verified() {
            self.store
                .set_user_email_verified(user.get_id(), email.address())
                .await;
        }

        Ok((
            self.log_in(
                LoginMethod::Email {
                    address: email.address(),
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
    ) -> Result<(Self, Option<String>), EmailLoginCallbackError> {
        if self.email.allow_login.as_ref().unwrap_or(&self.allow_login) == &Allow::Never {
            return Err(EmailLoginCallbackError::NotAllowed);
        }

        let Some(challenge) = self.store.consume_email_challenge(code).await else {
            return Err(EmailLoginCallbackError::ChallengeNotFound);
        };

        if challenge.expires() < Utc::now() {
            return Err(EmailLoginCallbackError::ChallengeExpired);
        }

        if let Some((user, email)) = self.store.get_user_by_email(challenge.address()).await {
            Ok(self.email_login(user, email, challenge.next()).await?)
        } else if self
            .email
            .allow_signup
            .as_ref()
            .unwrap_or(&self.allow_signup)
            == &Allow::OnEither
        {
            Ok(self
                .email_signup(challenge.address(), challenge.next())
                .await?)
        } else {
            Err(EmailLoginCallbackError::NoUser)
        }
    }

    #[cfg(feature = "password")]
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn email_reset_callback(self, code: String) -> Result<Self, (Self, &'static str)> {
        use crate::password::PasswordReset;

        if self.pass.allow_reset == PasswordReset::Never {
            return Err((self, "Forbidden"));
        }

        let Some(challenge) = self.store.consume_email_challenge(code).await else {
            return Err((self, "Code not found"));
        };

        if challenge.expires() < Utc::now() {
            return Err((self, "Challenge expired"));
        }

        let Some((user, email)) = self.store.get_user_by_email(challenge.address()).await else {
            return Err((self, "No such user"));
        };

        if !email.verified() && self.pass.allow_reset == PasswordReset::VerifiedEmailOnly {
            return Err((self, "Email not previously verified"));
        };

        Ok(self
            .log_in(
                LoginMethod::PasswordReset {
                    address: challenge.address(),
                },
                user.get_id(),
            )
            .await)
    }

    #[cfg(feature = "password")]
    pub async fn is_reset_session(&self) -> bool {
        self.reset_session().await.is_some()
    }

    #[cfg(feature = "password")]
    pub async fn reset_session(&self) -> Option<S::LoginSession> {
        let session_id = self.session_id_cookie()?;
        self.store
            .get_session(session_id)
            .await
            .filter(|s| matches!(s.get_method(), LoginMethod::PasswordReset { address: _ }))
    }

    #[cfg(feature = "password")]
    pub async fn reset_user_session(&self) -> Option<(S::User, S::LoginSession)> {
        let session = self.reset_session().await?;
        self.store
            .get_user(session.get_user_id())
            .await
            .map(|user| (user, session))
    }

    #[cfg(feature = "password")]
    pub async fn reset_user(&self) -> Option<S::User> {
        self.reset_user_session().await.map(|(user, _)| user)
    }

    pub async fn email_verify_callback(
        &self,
        code: String,
    ) -> Result<(String, Option<String>), &'static str> {
        let Some(challenge) = self.store.consume_email_challenge(code).await else {
            return Err("Code not found");
        };

        let Some((user, email)) = self.store.get_user_by_email(challenge.address()).await else {
            return Err("No such user");
        };

        if challenge.expires() < Utc::now() {
            return Err("Challenge expired");
        }

        if !email.verified() {
            self.store
                .set_user_email_verified(user.get_id(), email.address())
                .await;
        }

        Ok((email.address(), challenge.next()))
    }

    async fn email_signup(
        self,
        address: String,
        next: Option<String>,
    ) -> Result<(Self, Option<String>), EmailSignupError> {
        let (user, email) = self.store.create_email_user(address).await;

        Ok((
            self.log_in(
                LoginMethod::Email {
                    address: email.address(),
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
    ) -> Result<(Self, Option<String>), EmailSignupCallbackError> {
        if self
            .email
            .allow_signup
            .as_ref()
            .unwrap_or(&self.allow_signup)
            == &Allow::Never
        {
            return Err(EmailSignupCallbackError::NotAllowed);
        }

        let Some(challenge) = self.store.consume_email_challenge(code).await else {
            return Err(EmailSignupCallbackError::ChallengeNotFound);
        };

        if challenge.expires() < Utc::now() {
            return Err(EmailSignupCallbackError::ChallengeExpired);
        }

        if let Some((user, email)) = self.store.get_user_by_email(challenge.address()).await {
            if self.email.allow_login.as_ref().unwrap_or(&self.allow_login) == &Allow::OnEither {
                Ok(self.email_login(user, email, challenge.next()).await?)
            } else {
                Err(EmailSignupCallbackError::UserConflict)
            }
        } else {
            Ok(self
                .email_signup(challenge.address(), challenge.next())
                .await?)
        }
    }
}
