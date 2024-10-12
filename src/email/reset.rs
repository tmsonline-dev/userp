use super::{EmailChallenge, SendEmailChallengeError};
use crate::{AxumUser, AxumUserStore, LoginMethod, LoginSession, PasswordReset, User};
use chrono::Utc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EmailResetInitError<StoreError: std::error::Error> {
    #[error(transparent)]
    SendingEmail(#[from] SendEmailChallengeError<StoreError>),
    #[error("Reset not allowed")]
    NotAllowed,
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

impl<S: AxumUserStore> AxumUser<S> {
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

        if challenge.get_expires() < Utc::now() {
            return Err(EmailResetCallbackError::ChallengeExpired);
        }

        let user = self
            .store
            .email_reset(
                challenge.get_address(),
                self.pass.allow_reset == PasswordReset::VerifiedEmailOnly,
            )
            .await?;

        Ok(self
            .log_in(
                LoginMethod::PasswordReset {
                    address: challenge.get_address(),
                },
                user.get_id(),
            )
            .await?)
    }

    pub async fn is_reset_session(&self) -> Result<bool, S::Error> {
        Ok(self.reset_session().await?.is_some())
    }

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

    pub async fn reset_user(&self) -> Result<Option<S::User>, S::Error> {
        Ok(self.reset_user_session().await?.map(|(user, _)| user))
    }
}
