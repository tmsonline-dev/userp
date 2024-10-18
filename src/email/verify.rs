use super::{EmailChallenge, SendEmailChallengeError};
use crate::{AxumUser, AxumUserStore};
use chrono::Utc;
use thiserror::Error;

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

#[derive(Error, Debug)]
pub enum EmailVerifyError<StoreError: std::error::Error> {
    #[error("Email user not found")]
    NoUser,
    #[error(transparent)]
    Store(#[from] StoreError),
}
impl<S: AxumUserStore> AxumUser<S> {
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

        if challenge.get_expires() < Utc::now() {
            return Err(EmailVerifyCallbackError::ChallengeExpired);
        }

        self.store.email_verify(challenge.get_address()).await?;

        Ok((
            challenge.get_address().to_owned(),
            challenge.get_next().clone(),
        ))
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
}
