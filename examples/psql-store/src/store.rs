use crate::models::{MyEmailChallenge, MyLoginSession, MyOAuthToken, MyUser, MyUserEmail};
use axum::async_trait;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use sqlx::postgres::PgPool;
use thiserror::Error;
use userp::{
    prelude::*,
    reexports::{
        chrono::{DateTime, Utc},
        uuid::Uuid,
    },
};

#[derive(Clone, Debug)]
pub struct PsqlStore {
    pub pool: PgPool,
}

#[derive(Debug, Error)]
pub enum AuthStoreError {
    #[error(transparent)]
    SqlxError(#[from] sqlx::Error),
}

impl IntoResponse for AuthStoreError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!("{self:#?}");

        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "There was an authentication store error! Developers have been notified.",
        )
            .into_response()
    }
}

#[async_trait]
impl UserpStore for PsqlStore {
    type User = MyUser;
    type UserEmail = MyUserEmail;
    type LoginSession = MyLoginSession;
    type EmailChallenge = MyEmailChallenge;
    type OAuthToken = MyOAuthToken;
    type Error = AuthStoreError;

    async fn get_session(
        &self,
        session_id: Uuid,
    ) -> Result<Option<Self::LoginSession>, Self::Error> {
        Ok(sqlx::query_as!(
            Self::LoginSession,
            "
                SELECT *
                FROM login_session
                WHERE id = $1
            ",
            session_id
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn create_session(
        &self,
        user_id: Uuid,
        method: LoginMethod,
    ) -> Result<Self::LoginSession, Self::Error> {
        let (method, address, token_id) = match method {
            LoginMethod::Password => ("password".to_string(), None, None),
            LoginMethod::PasswordReset { address } => {
                ("password_reset".into(), Some(address), None)
            }
            LoginMethod::Email { address } => ("email".into(), Some(address), None),
            LoginMethod::OAuth { token_id } => ("oauth".into(), None, Some(token_id)),
        };

        Ok(sqlx::query_as!(
            Self::LoginSession,
            "
                INSERT INTO login_session (
                    id, user_id, method, oauth_token_id, email_address
                )
                VALUES (
                    $1, $2, $3, $4, $5
                )
                RETURNING *
            ",
            Uuid::new_v4(),
            user_id,
            method,
            token_id,
            address,
        )
        .fetch_one(&self.pool)
        .await?)
    }

    async fn delete_session(&self, user_id: Uuid, session_id: Uuid) -> Result<(), Self::Error> {
        Ok(sqlx::query!(
            "
                DELETE FROM login_session
                WHERE id = $1 AND user_id = $2
            ",
            session_id,
            user_id
        )
        .execute(&self.pool)
        .await
        .map(|_| ())?)
    }

    async fn get_user(&self, user_id: Uuid) -> Result<Option<Self::User>, Self::Error> {
        Ok(sqlx::query_as!(
            Self::User,
            "
                SELECT *
                FROM users
                WHERE id = $1
            ",
            user_id
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn email_set_verified(&self, address: &str) -> Result<(), Self::Error> {
        sqlx::query!(
            "
                UPDATE user_email
                SET verified = true
                WHERE address = $1
            ",
            address
        )
        .execute(&self.pool)
        .await
        .map_err(AuthStoreError::from)?;

        Ok(())
    }

    async fn email_create_challenge(
        &self,
        address: String,
        code: String,
        next: Option<String>,
        expires: DateTime<Utc>,
    ) -> Result<Self::EmailChallenge, Self::Error> {
        Ok(sqlx::query_as!(
            Self::EmailChallenge,
            "
                INSERT INTO email_challenge (
                    id, address, code, next, expires
                )
                VALUES (
                    $1, $2, $3, $4, $5
                )
                RETURNING *
            ",
            Uuid::new_v4(),
            address,
            code,
            next,
            expires
        )
        .fetch_one(&self.pool)
        .await?)
    }

    async fn email_consume_challenge(
        &self,
        code: String,
    ) -> Result<Option<Self::EmailChallenge>, Self::Error> {
        Ok(sqlx::query_as!(
            Self::EmailChallenge,
            "
                DELETE FROM email_challenge
                WHERE code = $1
                RETURNING *
            ",
            code
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn get_user_sessions(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<Self::LoginSession>, Self::Error> {
        Ok(sqlx::query_as!(
            Self::LoginSession,
            "
                SELECT *
                FROM login_session
                WHERE user_id = $1
            ",
            user_id
        )
        .fetch_all(&self.pool)
        .await?)
    }

    async fn get_user_oauth_tokens(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<Self::OAuthToken>, Self::Error> {
        Ok(sqlx::query_as!(
            Self::OAuthToken,
            "
                SELECT *
                FROM oauth_token
                WHERE user_id = $1
            ",
            user_id
        )
        .fetch_all(&self.pool)
        .await?)
    }

    async fn delete_oauth_token(&self, user_id: Uuid, token_id: Uuid) -> Result<(), Self::Error> {
        sqlx::query!(
            "
                DELETE FROM oauth_token
                WHERE id = $1 AND user_id = $2
            ",
            token_id,
            user_id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete_user(&self, id: Uuid) -> Result<(), Self::Error> {
        sqlx::query!(
            "
                DELETE FROM users
                WHERE id = $1
            ",
            id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
    async fn clear_user_password_hash(
        &self,
        user_id: Uuid,
        session_id: Uuid,
    ) -> Result<(), Self::Error> {
        sqlx::query!(
            "
                DELETE FROM login_session
                WHERE user_id = $1
                AND method = 'password'
                AND id != $2
            ",
            user_id,
            session_id
        )
        .execute(&self.pool)
        .await?;

        sqlx::query!(
            "
                UPDATE users
                SET password_hash = NULL
                WHERE id = $1
            ",
            user_id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
    async fn get_user_emails(&self, user_id: Uuid) -> Result<Vec<Self::UserEmail>, Self::Error> {
        Ok(sqlx::query_as!(
            Self::UserEmail,
            "
                SELECT *
                FROM user_email
                WHERE user_id = $1
            ",
            user_id
        )
        .fetch_all(&self.pool)
        .await?)
    }

    async fn set_user_password_hash(
        &self,
        user_id: Uuid,
        password_hash: String,
        session_id: Uuid,
    ) -> Result<(), Self::Error> {
        sqlx::query!(
            "
                DELETE FROM login_session
                WHERE user_id = $1
                AND method = 'password'
                AND id != $2
            ",
            user_id,
            session_id
        )
        .execute(&self.pool)
        .await?;

        sqlx::query!(
            "
                UPDATE users
                SET password_hash = $2
                WHERE id = $1
            ",
            user_id,
            password_hash
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn set_user_email_allow_link_login(
        &self,
        user_id: Uuid,
        address: String,
        allow_login: bool,
    ) -> Result<(), Self::Error> {
        sqlx::query!(
            "
                UPDATE user_email
                SET allow_link_login = $1
                WHERE user_id = $2
                AND address = $3
            ",
            allow_login,
            user_id,
            address
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn add_user_email(&self, user_id: Uuid, address: String) -> Result<(), Self::Error> {
        sqlx::query!(
            "
                INSERT INTO user_email (
                    id, user_id, address, verified, allow_link_login
                )
                VALUES (
                    $1, $2, $3, $4, $5
                )
            ",
            Uuid::new_v4(),
            user_id,
            address,
            false,
            false,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete_user_email(&self, user_id: Uuid, address: String) -> Result<(), Self::Error> {
        sqlx::query!(
            "
                DELETE FROM user_email
                WHERE user_id = $1
                AND address = $2
            ",
            user_id,
            address,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // password store
    async fn password_get_user_by_password_id(
        &self,
        password_id: &str,
    ) -> Result<Option<Self::User>, Self::Error> {
        Ok(sqlx::query_as!(
            Self::User,
            "
                SELECT u.*
                FROM users u
                JOIN user_email ue
                ON u.id = ue.user_id
                WHERE ue.address = $1
            ",
            password_id
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn password_create_user(
        &self,
        password_id: &str,
        password_hash: &str,
    ) -> Result<Self::User, Self::Error> {
        let user_id = Uuid::new_v4();

        let mut tx = self.pool.begin().await?;

        sqlx::query!(
            "
                INSERT INTO users (id, password_hash)
                VALUES ($1, $2)
            ",
            user_id,
            password_hash
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query!(
            "
                INSERT INTO user_email (id, user_id, address, verified)
                VALUES ($1, $2, $3, $4)
            ",
            Uuid::new_v4(),
            user_id,
            password_id,
            false
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        let user = MyUser {
            id: user_id,
            name: None,
            password_hash: Some(password_hash.into()),
        };

        Ok(user)
    }

    // email store
    async fn email_get_user_by_email_address(
        &self,
        address: &str,
    ) -> Result<Option<(Self::User, Self::UserEmail)>, Self::Error> {
        let user_email = sqlx::query_as!(
            Self::UserEmail,
            "
                SELECT * FROM user_email
                WHERE address = $1
            ",
            address
        )
        .fetch_optional(&self.pool)
        .await?;

        let Some(user_email) = user_email else {
            return Ok(None);
        };

        let user = sqlx::query_as!(
            Self::User,
            "
                SELECT * FROM users
                WHERE id = $1
            ",
            user_email.get_user_id()
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(Some((user, user_email)))
    }

    async fn email_create_user_by_email_address(
        &self,
        address: &str,
    ) -> Result<(Self::User, Self::UserEmail), Self::Error> {
        let user_id = Uuid::new_v4();
        let user_email_id = Uuid::new_v4();

        let mut tx = self.pool.begin().await?;

        sqlx::query!(
            "
                INSERT INTO users (id)
                VALUES ($1)
            ",
            user_id,
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query!(
            "
                INSERT INTO user_email (id, user_id, address, verified)
                VALUES ($1, $2, $3, $4)
            ",
            user_email_id,
            user_id,
            address,
            false
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        let user = MyUser {
            id: user_id,
            name: None,
            password_hash: None,
        };

        let user_email = MyUserEmail {
            id: user_email_id,
            user_id,
            address: address.into(),
            verified: true,
            allow_link_login: true,
        };

        Ok((user, user_email))
    }

    // oauth store
    async fn update_token_by_unmatched_token(
        &self,
        token_id: Uuid,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Self::OAuthToken, Self::Error> {
        Ok(sqlx::query_as!(
            Self::OAuthToken,
            "
                UPDATE oauth_token
                SET
                    provider_name = $2,
                    provider_user_id = $3,
                    access_token = $4,
                    refresh_token = $5,
                    expires = $6,
                    scopes = $7
                WHERE id = $1
                RETURNING *
            ",
            token_id,
            unmatched_token.provider_name,
            unmatched_token.provider_user_id,
            unmatched_token.access_token,
            unmatched_token.refresh_token,
            unmatched_token.expires,
            &unmatched_token.scopes,
        )
        .fetch_one(&self.pool)
        .await?)
    }
    async fn oauth_get_token_by_id(
        &self,
        token_id: Uuid,
    ) -> Result<Option<Self::OAuthToken>, Self::Error> {
        Ok(sqlx::query_as!(
            Self::OAuthToken,
            "
                SELECT * FROM oauth_token
                WHERE id = $1
            ",
            token_id
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn get_token_by_unmatched_token(
        &self,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Option<Self::OAuthToken>, Self::Error> {
        Ok(sqlx::query_as!(
            Self::OAuthToken,
            "
                SELECT * FROM oauth_token
                WHERE provider_name = $1
                AND provider_user_id = $2
            ",
            unmatched_token.provider_name,
            unmatched_token.provider_user_id,
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    async fn create_user_token_from_unmatched_token(
        &self,
        user_id: Uuid,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Self::OAuthToken, Self::Error> {
        let token = sqlx::query_as!(
            Self::OAuthToken,
            "
                INSERT INTO oauth_token (
                    id, user_id, provider_name, provider_user_id, access_token, refresh_token, expires, scopes
                )
                VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8
                )
                RETURNING *
            ",
            Uuid::new_v4(),
            user_id,
            unmatched_token.provider_name,
            unmatched_token.provider_user_id,
            unmatched_token.access_token,
            unmatched_token.refresh_token,
            unmatched_token.expires,
            &unmatched_token.scopes
        ).fetch_one(&self.pool).await?;

        Ok(token)
    }

    async fn create_user_from_unmatched_token(
        &self,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<(Self::User, Self::OAuthToken), Self::Error> {
        let user = sqlx::query_as!(
            Self::User,
            "
                INSERT INTO users (id, name)
                VALUES ($1, $2)
                RETURNING *
            ",
            Uuid::new_v4(),
            unmatched_token.provider_user_raw["name"].as_str()
        )
        .fetch_one(&self.pool)
        .await?;

        if let Some(address) = unmatched_token.provider_user_raw["email"].as_str() {
            sqlx::query!(
                "
                    INSERT INTO user_email (id, user_id, address, verified)
                    VALUES ($1, $2, $3, $4)
                ",
                Uuid::new_v4(),
                user.get_id(),
                address,
                false
            )
            .execute(&self.pool)
            .await?;
        }

        let token = sqlx::query_as!(
            Self::OAuthToken,
            "
                INSERT INTO oauth_token (
                    id, user_id, provider_name, provider_user_id, access_token, refresh_token, expires, scopes
                )
                VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8
                )
                RETURNING *
            ",
            Uuid::new_v4(),
            user.get_id(),
            unmatched_token.provider_name,
            unmatched_token.provider_user_id,
            unmatched_token.access_token,
            unmatched_token.refresh_token,
            unmatched_token.expires,
            &unmatched_token.scopes
        ).fetch_one(&self.pool).await?;

        Ok((user, token))
    }

    async fn get_user_by_unmatched_token(
        &self,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Option<(Self::User, Self::OAuthToken)>, Self::Error> {
        let token = sqlx::query_as!(
            Self::OAuthToken,
            "
                SELECT * FROM oauth_token
                WHERE provider_name = $1
                AND provider_user_id = $2
            ",
            unmatched_token.provider_name,
            unmatched_token.provider_user_id
        )
        .fetch_optional(&self.pool)
        .await?;

        let Some(token) = token else {
            return Ok(None);
        };

        let user = sqlx::query_as!(
            Self::User,
            "
                SELECT * FROM users
                WHERE id = $1
            ",
            token.get_user_id()
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(Some((user, token)))
    }
}
