use super::SendEmailChallengeError;
use crate::{
    core::CoreUserp,
    models::{email::EmailChallenge, UserpCookies},
    store::UserpStore,
};
use chrono::Utc;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EmailVerifyCallbackError<StoreError: std::error::Error> {
    #[error("Challenge expired")]
    ChallengeExpired,
    #[error("Challenge not found")]
    ChallengeNotFound,
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl<S: UserpStore, C: UserpCookies> CoreUserp<S, C> {
    pub async fn email_verify_callback(
        &self,
        code: String,
    ) -> Result<(String, Option<String>), EmailVerifyCallbackError<S::Error>> {
        let Some(challenge) = self.store.email_consume_challenge(code).await? else {
            return Err(EmailVerifyCallbackError::ChallengeNotFound);
        };

        if challenge.get_expires() < Utc::now() {
            return Err(EmailVerifyCallbackError::ChallengeExpired);
        }

        self.store
            .email_set_verified(challenge.get_address())
            .await?;

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
            self.routes.email.user_email_verify.clone(),
            email,
            "Click here to verify email".into(),
            next,
        )
        .await?;

        Ok(())
    }
}
