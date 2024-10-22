use super::{EmailChallenge, SendEmailChallengeError};
use crate::{Allow, LoginMethod, User, Userp, UserpStore};
use chrono::Utc;
use thiserror::Error;

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

#[derive(Debug, Error)]
pub enum EmailLoginInitError<StoreError: std::error::Error> {
    #[error(transparent)]
    SendingEmail(#[from] SendEmailChallengeError<StoreError>),
    #[error("Login not allowed")]
    NotAllowed,
}

impl<S: UserpStore> Userp<S> {
    pub async fn email_login_init(
        &self,
        email: String,
        next: Option<String>,
    ) -> Result<(), EmailLoginInitError<S::Error>> {
        if self.email.allow_login.as_ref().unwrap_or(&self.allow_login) == &Allow::Never {
            return Err(EmailLoginInitError::NotAllowed);
        }

        self.send_email_challenge(
            self.routes.actions.login_email.clone(),
            email,
            "Click here to log in".into(),
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

        if challenge.get_expires() < Utc::now() {
            return Err(EmailLoginCallbackError::ChallengeExpired);
        }

        let user = self
            .store
            .email_login(
                challenge.get_address(),
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
                    address: challenge.get_address().to_owned(),
                },
                user.get_id(),
            )
            .await?,
            challenge.get_next().clone(),
        ))
    }
}
