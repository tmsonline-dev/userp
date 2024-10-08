#[cfg(feature = "password")]
use super::LoginSession;
use super::{Allow, AxumUser, AxumUserStore, LoginMethod, UserTrait};
use chrono::{DateTime, Duration, Utc};
use lettre::{message::header::ContentType, Message, SmtpTransport, Transport};
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

pub trait EmailTrait {
    fn address(&self) -> String;
    fn verified(&self) -> bool;
    fn allow_login(&self) -> bool;
}

#[derive(Debug)]
pub struct EmailChallenge {
    pub email: String,
    pub code: String,
    pub next: Option<String>,
    pub expires: DateTime<Utc>,
}

impl<S: AxumUserStore> AxumUser<S> {
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
                expires: Utc::now() + self.email.challenge_lifetime,
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

    pub async fn email_reset_init(&self, email: String, next: Option<String>) {
        self.send_email_challenge(
            self.email.reset_pw_path.clone(),
            email,
            "Click here to reset password".into(),
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
        email: S::Email,
        next: Option<String>,
    ) -> Result<(Self, Option<String>), (Self, &'static str)> {
        if !email.allow_login() {
            return Err((self, "Login not activated for this email"));
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
    ) -> Result<(Self, Option<String>), (Self, &'static str)> {
        let allow = self.email.allow_login.as_ref().unwrap_or(&self.allow_login);

        if allow == &Allow::Never {
            return Err((self, "Forbidden"));
        }

        let Some(EmailChallenge {
            email,
            next,
            expires,
            ..
        }) = self.store.consume_email_challenge(code).await
        else {
            return Err((self, "Code not found"));
        };

        if expires < Utc::now() {
            return Err((self, "Challenge expired"));
        }

        if let Some((user, email)) = self.store.get_user_by_email(email.clone()).await {
            self.email_login(user, email, next).await
        } else {
            match allow {
                Allow::Never => unreachable!(),
                Allow::OnEither => self.email_signup(email, next).await,
                Allow::OnSelf => Err((self, "No such user")),
            }
        }
    }

    #[cfg(feature = "password")]
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn email_reset_callback(self, code: String) -> Result<Self, (Self, &'static str)> {
        use crate::password::PasswordReset;

        if self.pass.allow_reset == PasswordReset::Never {
            return Err((self, "Forbidden"));
        }

        let Some(EmailChallenge {
            email: address,
            expires,
            ..
        }) = self.store.consume_email_challenge(code).await
        else {
            return Err((self, "Code not found"));
        };

        if expires < Utc::now() {
            return Err((self, "Challenge expired"));
        }

        let Some((user, email)) = self.store.get_user_by_email(address.clone()).await else {
            return Err((self, "No such user"));
        };

        if !email.verified() && self.pass.allow_reset == PasswordReset::VerifiedEmailOnly {
            return Err((self, "Email not previously verified"));
        };

        Ok(self
            .log_in(LoginMethod::PasswordReset { address }, user.get_id())
            .await)
    }

    #[cfg(feature = "password")]
    pub async fn is_reset_session(&self) -> bool {
        self.reset_session().await.is_some()
    }

    #[cfg(feature = "password")]
    pub async fn reset_session(&self) -> Option<LoginSession> {
        let session_id = self.session_id_cookie()?;
        self.store
            .get_session(session_id)
            .await
            .filter(|s| matches!(s.method, LoginMethod::PasswordReset { address: _ }))
    }

    #[cfg(feature = "password")]
    pub async fn reset_user_session(&self) -> Option<(S::User, LoginSession)> {
        let session = self.reset_session().await?;
        self.store
            .get_user(session.user_id)
            .await
            .map(|user| (user, session))
    }

    #[cfg(feature = "password")]
    pub async fn reset_user(&self) -> Option<S::User> {
        self.reset_user_session().await.map(|(user, _)| user)
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn email_verify_callback(
        &self,
        code: String,
    ) -> Result<(String, Option<String>), &'static str> {
        let Some(EmailChallenge {
            email,
            next,
            expires,
            ..
        }) = self.store.consume_email_challenge(code).await
        else {
            return Err("Code not found");
        };

        let Some((user, email)) = self.store.get_user_by_email(email.clone()).await else {
            return Err("No such user");
        };

        if expires < Utc::now() {
            return Err("Challenge expired");
        }

        if !email.verified() {
            self.store
                .set_user_email_verified(user.get_id(), email.address())
                .await;
        }

        Ok((email.address(), next))
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
    ) -> Result<(Self, Option<String>), (Self, &'static str)> {
        let allow = self
            .email
            .allow_signup
            .as_ref()
            .unwrap_or(&self.allow_signup);

        if allow == &Allow::Never {
            return Err((self, "Forbidden"));
        }

        let Some(EmailChallenge {
            email,
            next,
            expires,
            ..
        }) = self.store.consume_email_challenge(code).await
        else {
            return Err((self, "Code not found"));
        };

        if expires < Utc::now() {
            return Err((self, "Challenge expired"));
        }

        if let Some((user, email)) = self.store.get_user_by_email(email.clone()).await {
            match self.email.allow_login.as_ref().unwrap_or(&self.allow_login) {
                Allow::Never => unreachable!(),
                Allow::OnEither => self.email_login(user, email, next).await,
                Allow::OnSelf => Err((self, "User already exists")),
            }
        } else {
            self.email_signup(email, next).await
        }
    }
}
