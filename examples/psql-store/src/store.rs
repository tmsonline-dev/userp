use crate::models::{MyEmailChallenge, MyLoginSession, MyOAuthToken, MyUser, MyUserEmail};
use crate::password::hash;
use axum::async_trait;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use sqlx::postgres::PgPool;
use thiserror::Error;
use userp::{
    self,
    chrono::{DateTime, Utc},
    uuid::Uuid,
    EmailLoginError, EmailResetError, EmailSignupError, EmailVerifyError, LoginMethod,
    OAuthLinkError, OAuthLoginError, OAuthSignupError, PasswordLoginError, PasswordSignupError,
    UnmatchedOAuthToken, UserpStore,
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

    async fn delete_session(&self, session_id: Uuid) -> Result<(), Self::Error> {
        Ok(sqlx::query!(
            "
                DELETE FROM login_session
                WHERE id = $1
            ",
            session_id
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

    async fn password_login(
        &self,
        password_id: &str,
        password: &str,
        allow_signup: bool,
    ) -> Result<Self::User, PasswordLoginError<Self::Error>> {
        let user = sqlx::query_as!(
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
        .await
        .map_err(AuthStoreError::from)?;

        match user {
            Some(user) => {
                if user.validate_password(password).await {
                    Ok(user)
                } else {
                    Err(PasswordLoginError::WrongPassword)
                }
            }
            None => {
                if allow_signup {
                    let user = sqlx::query_as!(
                        Self::User,
                        "
                            INSERT INTO users (
                                id, password_hash
                            )
                            VALUES (
                                $1, $2
                            )
                            RETURNING *
                        ",
                        Uuid::new_v4(),
                        Some(hash(password.to_owned()).await)
                    )
                    .fetch_one(&self.pool)
                    .await
                    .map_err(AuthStoreError::from)?;

                    sqlx::query_as!(
                        Self::UserEmail,
                        "
                            INSERT INTO user_email (
                                id, user_id, address, verified, allow_link_login
                            ) VALUES (
                                $1, $2, $3, $4, $5
                            )
                        ",
                        Uuid::new_v4(),
                        user.id,
                        password_id,
                        false,
                        false
                    )
                    .execute(&self.pool)
                    .await
                    .map_err(AuthStoreError::from)?;

                    Ok(user)
                } else {
                    Err(PasswordLoginError::NoUser)
                }
            }
        }
    }

    async fn password_signup(
        &self,
        password_id: &str,
        password: &str,
        allow_login: bool,
    ) -> Result<Self::User, PasswordSignupError<Self::Error>> {
        let user = sqlx::query_as!(
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
        .await
        .map_err(AuthStoreError::from)?;

        match user {
            Some(user) => {
                if allow_login {
                    if user.validate_password(password).await {
                        Ok(user)
                    } else {
                        Err(PasswordSignupError::WrongPassword)
                    }
                } else {
                    Err(PasswordSignupError::UserExists)
                }
            }
            None => {
                let user = sqlx::query_as!(
                    Self::User,
                    "
                        INSERT INTO users (
                            id, password_hash
                        )
                        VALUES (
                            $1, $2
                        )
                        RETURNING *
                    ",
                    Uuid::new_v4(),
                    Some(hash(password.to_owned()).await)
                )
                .fetch_one(&self.pool)
                .await
                .map_err(AuthStoreError::from)?;

                sqlx::query_as!(
                    Self::UserEmail,
                    "
                        INSERT INTO user_email (
                            id, user_id, address, verified, allow_link_login
                        ) VALUES (
                            $1, $2, $3, $4, $5
                        )
                    ",
                    Uuid::new_v4(),
                    user.id,
                    password_id,
                    false,
                    false
                )
                .execute(&self.pool)
                .await
                .map_err(AuthStoreError::from)?;

                Ok(user)
            }
        }
    }

    async fn email_login(
        &self,
        address: &str,
        allow_signup: bool,
    ) -> Result<Self::User, EmailLoginError<Self::Error>> {
        let row = sqlx::query!(
            "
                SELECT
                    u.id as user_id,
                    u.password_hash AS user_password_hash,
                    u.name AS user_name,
                    ue.allow_link_login as user_email_allow_link_login
                FROM user_email ue
                JOIN users u
                ON u.id = ue.user_id
                WHERE ue.address = $1
            ",
            address
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(AuthStoreError::from)?;

        match row {
            Some(row) => {
                if row.user_email_allow_link_login {
                    Ok(Self::User {
                        id: row.user_id,
                        name: row.user_name,
                        password_hash: row.user_password_hash,
                    })
                } else {
                    Err(EmailLoginError::NotAllowed)
                }
            }
            None => {
                if allow_signup {
                    let user = sqlx::query_as!(
                        Self::User,
                        "
                            INSERT INTO users (
                                id, password_hash
                            )
                            VALUES (
                                $1, $2
                            )
                            RETURNING *
                        ",
                        Uuid::new_v4(),
                        Option::<String>::None
                    )
                    .fetch_one(&self.pool)
                    .await
                    .map_err(AuthStoreError::from)?;

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
                        user.id,
                        address,
                        true,
                        true
                    )
                    .execute(&self.pool)
                    .await
                    .map_err(AuthStoreError::from)?;

                    Ok(user)
                } else {
                    Err(EmailLoginError::NoUser)
                }
            }
        }
    }

    async fn email_signup(
        &self,
        address: &str,
        allow_login: bool,
    ) -> Result<Self::User, EmailSignupError<Self::Error>> {
        let row = sqlx::query!(
            "
                SELECT
                    u.id as user_id,
                    u.password_hash AS user_password_hash,
                    u.name AS user_name,
                    ue.allow_link_login AS user_email_allow_link_login
                FROM user_email ue
                JOIN users u
                ON u.id = ue.user_id
                WHERE ue.address = $1
            ",
            address
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(AuthStoreError::from)?;

        match row {
            Some(row) => {
                if !row.user_email_allow_link_login {
                    Err(EmailSignupError::NotAllowed)
                } else if !allow_login {
                    Err(EmailSignupError::UserExists)
                } else {
                    Ok(Self::User {
                        id: row.user_id,
                        name: row.user_name,
                        password_hash: row.user_password_hash,
                    })
                }
            }
            None => {
                let user = sqlx::query_as!(
                    Self::User,
                    "
                        INSERT INTO users (
                            id, password_hash
                        )
                        VALUES (
                            $1, $2
                        )
                        RETURNING *
                    ",
                    Uuid::new_v4(),
                    Option::<String>::None
                )
                .fetch_one(&self.pool)
                .await
                .map_err(AuthStoreError::from)?;

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
                    user.id,
                    address,
                    true,
                    true
                )
                .execute(&self.pool)
                .await
                .map_err(AuthStoreError::from)?;

                Ok(user)
            }
        }
    }

    async fn email_reset(
        &self,
        address: &str,
        require_verified_address: bool,
    ) -> Result<Self::User, EmailResetError<Self::Error>> {
        let row = sqlx::query!(
            "
                SELECT
                    u.id AS user_id,
                    u.password_hash AS user_password_hash,
                    u.name AS user_name,
                    ue.verified AS user_email_verified
                FROM user_email ue
                JOIN users u
                ON u.id = ue.user_id
                WHERE ue.address = $1
            ",
            address
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(AuthStoreError::from)?;

        match row {
            Some(row) => {
                if !require_verified_address || row.user_email_verified {
                    Ok(Self::User {
                        id: row.user_id,
                        name: row.user_name,
                        password_hash: row.user_password_hash,
                    })
                } else {
                    Err(EmailResetError::NotVerified)
                }
            }
            None => Err(EmailResetError::NoUser),
        }
    }

    async fn email_verify(&self, address: &str) -> Result<(), EmailVerifyError<Self::Error>> {
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

    async fn oauth_signup(
        &self,
        unmatched_token: UnmatchedOAuthToken,
        allow_login: bool,
    ) -> Result<(Self::User, Self::OAuthToken), OAuthSignupError<Self::Error>> {
        let token = sqlx::query_as!(
            Self::OAuthToken,
            "
                SELECT * FROM oauth_token
                WHERE provider_name = $1
                AND provider_user_id = $2
            ",
            unmatched_token.provider_name,
            unmatched_token.provider_user.id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(AuthStoreError::from)?;

        let user_token = if let Some(token) = token {
            Some((
                sqlx::query_as!(
                    Self::User,
                    "
                        SELECT * FROM users
                        WHERE id = $1
                    ",
                    token.user_id
                )
                .fetch_one(&self.pool)
                .await
                .map_err(AuthStoreError::from)?,
                token,
            ))
        } else {
            None
        };

        match user_token {
            Some((user, token)) => {
                if allow_login {
                    Ok((user, token))
                } else {
                    Err(OAuthSignupError::UserExists)
                }
            }
            None => {
                let user = sqlx::query_as!(
                    Self::User,
                    "
                        INSERT INTO users (
                            id, name
                        )
                        VALUES (
                            $1, $2
                        )
                        RETURNING *
                    ",
                    Uuid::new_v4(),
                    unmatched_token.provider_user.name.as_ref()
                )
                .fetch_one(&self.pool)
                .await
                .map_err(AuthStoreError::from)?;

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
                    user.id,
                    unmatched_token.provider_name,
                    unmatched_token.provider_user.id,
                    unmatched_token.access_token,
                    unmatched_token.refresh_token,
                    unmatched_token.expires,
                    &unmatched_token.scopes
                )
                .fetch_one(&self.pool)
                .await.map_err(AuthStoreError::from)?;

                Ok((user, token))
            }
        }
    }

    async fn oauth_login(
        &self,
        unmatched_token: UnmatchedOAuthToken,
        allow_signup: bool,
    ) -> Result<(Self::User, Self::OAuthToken), OAuthLoginError<Self::Error>> {
        let token = sqlx::query_as!(
            Self::OAuthToken,
            "
                SELECT * FROM oauth_token
                WHERE provider_name = $1
                AND provider_user_id = $2
            ",
            unmatched_token.provider_name,
            unmatched_token.provider_user.id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(AuthStoreError::from)?;

        let user_token = if let Some(token) = token {
            Some((
                sqlx::query_as!(
                    Self::User,
                    "
                        SELECT * FROM users
                        WHERE id = $1
                    ",
                    token.user_id
                )
                .fetch_one(&self.pool)
                .await
                .map_err(AuthStoreError::from)?,
                token,
            ))
        } else {
            None
        };

        match user_token {
            Some((user, token)) => Ok((user, token)),
            None => {
                if allow_signup {
                    let user = sqlx::query_as!(
                        Self::User,
                        "
                        INSERT INTO users (
                            id, name
                        )
                        VALUES (
                            $1, $2
                        )
                        RETURNING *
                    ",
                        Uuid::new_v4(),
                        unmatched_token.provider_user.name.as_ref()
                    )
                    .fetch_one(&self.pool)
                    .await
                    .map_err(AuthStoreError::from)?;

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
                        user.id,
                        unmatched_token.provider_name,
                        unmatched_token.provider_user.id,
                        unmatched_token.access_token,
                        unmatched_token.refresh_token,
                        unmatched_token.expires,
                        &unmatched_token.scopes
                    )
                    .fetch_one(&self.pool)
                    .await.map_err(AuthStoreError::from)?;

                    Ok((user, token))
                } else {
                    Err(OAuthLoginError::NoUser)
                }
            }
        }
    }

    async fn oauth_link(
        &self,
        user_id: Uuid,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Self::OAuthToken, OAuthLinkError<Self::Error>> {
        Ok(
            sqlx::query_as!(
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
                unmatched_token.provider_user.id,
                unmatched_token.access_token,
                unmatched_token.refresh_token,
                unmatched_token.expires,
                &unmatched_token.scopes
            )
            .fetch_one(&self.pool)
            .await.map_err(AuthStoreError::from)?
        )
    }

    async fn oauth_update_token(
        &self,
        token: Self::OAuthToken,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Self::OAuthToken, Self::Error> {
        Ok(sqlx::query_as!(
            Self::OAuthToken,
            "
                UPDATE oauth_token
                SET
                    access_token = $3,
                    refresh_token = $4,
                    expires = $5,
                    scopes = $6
                WHERE id = $1
                AND user_id = $2
                RETURNING *
            ",
            token.id,
            token.user_id,
            unmatched_token.access_token,
            unmatched_token.refresh_token,
            unmatched_token.expires,
            &unmatched_token.scopes
        )
        .fetch_one(&self.pool)
        .await?)
    }

    async fn oauth_get_token(
        &self,
        token_id: Uuid,
    ) -> Result<Option<Self::OAuthToken>, Self::Error> {
        Ok(sqlx::query_as!(
            Self::OAuthToken,
            "
                SELECT *
                FROM oauth_token
                WHERE id = $1
            ",
            token_id
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

    async fn delete_oauth_token(&self, token_id: Uuid) -> Result<(), Self::Error> {
        sqlx::query!(
            "
                DELETE FROM oauth_token
                WHERE id = $1
            ",
            token_id
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
    async fn clear_user_password(
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

    async fn set_user_password(
        &self,
        user_id: Uuid,
        password: String,
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

        let password_hash = hash(password).await;

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
}
