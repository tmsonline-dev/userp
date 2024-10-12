use crate::{MyEmailChallenge, MyLoginSession, MyOAuthToken, MyUser, MyUserEmail};
use axum::async_trait;
use axum_user::{
    AxumUserExtendedStore, AxumUserStore, EmailLoginError, EmailResetError, EmailSignupError,
    EmailVerifyError, LoginMethod, PasswordLoginError, PasswordSignupError, UnmatchedOAuthToken,
    User,
};
use chrono::{DateTime, Utc};
use std::{collections::HashMap, convert::Infallible, sync::Arc};
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone, Default, Debug)]
pub struct MemoryStore {
    sessions: Arc<RwLock<HashMap<Uuid, MyLoginSession>>>,
    users: Arc<RwLock<HashMap<Uuid, MyUser>>>,
    challenges: Arc<RwLock<HashMap<String, MyEmailChallenge>>>,
    oauth_tokens: Arc<RwLock<HashMap<Uuid, MyOAuthToken>>>,
}

#[async_trait]
impl AxumUserStore for MemoryStore {
    type User = MyUser;
    type UserEmail = MyUserEmail;
    type LoginSession = MyLoginSession;
    type EmailChallenge = MyEmailChallenge;
    type OAuthToken = MyOAuthToken;
    type Error = Infallible;

    async fn get_session(&self, session_id: Uuid) -> Option<Self::LoginSession> {
        let sessions = self.sessions.read().await;

        sessions.get(&session_id).cloned()
    }

    async fn delete_session(&self, session_id: Uuid) {
        let mut sessions = self.sessions.write().await;

        sessions.remove(&session_id);
    }

    async fn create_session(&self, user_id: Uuid, method: LoginMethod) -> Self::LoginSession {
        let session = MyLoginSession {
            id: Uuid::new_v4(),
            user_id,
            method,
        };

        let mut sessions = self.sessions.write().await;

        sessions.insert(session.id, session.clone());

        session
    }

    async fn get_user(&self, user_id: Uuid) -> Option<MyUser> {
        let users = self.users.read().await;

        users.get(&user_id).cloned()
    }
    async fn password_login(
        &self,
        password_id: String,
        password_hash: String,
        allow_signup: bool,
    ) -> Result<Self::User, PasswordLoginError<Self::Error>> {
        let mut users = self.users.write().await;

        let user = users
            .values()
            .find(|user| user.emails.iter().any(|e| e.email == password_id));

        match user {
            Some(user) => {
                if user.validate_password_hash(password_hash) {
                    Ok(user.clone())
                } else {
                    Err(PasswordLoginError::WrongPassword)
                }
            }
            None => {
                if allow_signup {
                    let id = Uuid::new_v4();
                    let user = MyUser {
                        id,
                        password: Some(password_hash),
                        emails: vec![MyUserEmail {
                            email: password_id,
                            verified: false,
                            allow_link_login: false,
                        }],
                    };

                    users.insert(id, user.clone());

                    Ok(user)
                } else {
                    Err(PasswordLoginError::NoUser)
                }
            }
        }
    }

    async fn password_signup(
        &self,
        password_id: String,
        password_hash: String,
        allow_login: bool,
    ) -> Result<Self::User, PasswordSignupError<Self::Error>> {
        let mut users = self.users.write().await;

        let user = users
            .values()
            .find(|user| user.emails.iter().any(|e| e.email == password_id));

        match user {
            Some(user) => {
                if allow_login {
                    if user.validate_password_hash(password_hash) {
                        Ok(user.clone())
                    } else {
                        Err(PasswordSignupError::WrongPassword)
                    }
                } else {
                    Err(PasswordSignupError::UserExists)
                }
            }
            None => {
                let id = Uuid::new_v4();
                let user = MyUser {
                    id,
                    password: Some(password_hash),
                    emails: vec![MyUserEmail {
                        email: password_id,
                        verified: false,
                        allow_link_login: false,
                    }],
                };

                users.insert(id, user.clone());

                Ok(user)
            }
        }
    }

    async fn email_login(
        &self,
        address: String,
        allow_signup: bool,
    ) -> Result<Self::User, EmailLoginError<Self::Error>> {
        let mut users = self.users.write().await;

        let user_email = users.values().find_map(|user| {
            user.emails
                .iter()
                .find(|e| e.email == address)
                .map(|email| (user, email))
        });

        match user_email {
            Some((user, email)) => {
                if email.allow_link_login {
                    Ok(user.clone())
                } else {
                    Err(EmailLoginError::NotAllowed)
                }
            }
            None => {
                if allow_signup {
                    let id = Uuid::new_v4();
                    let user = MyUser {
                        id,
                        password: None,
                        emails: vec![MyUserEmail {
                            email: address,
                            verified: true,
                            allow_link_login: true,
                        }],
                    };

                    users.insert(id, user.clone());

                    Ok(user)
                } else {
                    Err(EmailLoginError::NoUser)
                }
            }
        }
    }
    async fn email_signup(
        &self,
        address: String,
        allow_login: bool,
    ) -> Result<Self::User, EmailSignupError<Self::Error>> {
        let mut users = self.users.write().await;

        let user_email = users.values().find_map(|user| {
            user.emails
                .iter()
                .find(|e| e.email == address)
                .map(|email| (user, email))
        });

        match user_email {
            Some((user, email)) => {
                if !email.allow_link_login {
                    Err(EmailSignupError::NotAllowed)
                } else if !allow_login {
                    Err(EmailSignupError::UserExists)
                } else {
                    Ok(user.clone())
                }
            }
            None => {
                let id = Uuid::new_v4();
                let user = MyUser {
                    id,
                    password: None,
                    emails: vec![MyUserEmail {
                        email: address,
                        verified: true,
                        allow_link_login: true,
                    }],
                };

                users.insert(id, user.clone());

                Ok(user)
            }
        }
    }
    async fn email_reset(
        &self,
        address: String,
        require_verified_address: bool,
    ) -> Result<Self::User, EmailResetError<Self::Error>> {
        let users = self.users.read().await;
        let user_email = users
            .values()
            .find_map(|u| u.emails.iter().find(|e| e.email == address).map(|e| (u, e)));

        match user_email {
            Some((user, email)) => {
                if !require_verified_address || email.verified {
                    Ok(user.clone())
                } else {
                    Err(EmailResetError::NotVerified)
                }
            }
            None => Err(EmailResetError::NoUser),
        }
    }

    async fn email_verify(&self, address: String) -> Result<(), EmailVerifyError<Self::Error>> {
        let mut users = self.users.write().await;

        users
            .values_mut()
            .find_map(|u| u.emails.iter_mut().find(|e| e.email == address))
            .map(|e| e.verified = true)
            .ok_or(EmailVerifyError::NoUser)
    }

    async fn email_create_challenge(
        &self,

        address: String,
        code: String,
        next: Option<String>,
        expires: DateTime<Utc>,
    ) -> Result<Self::EmailChallenge, Self::Error> {
        let challenge = MyEmailChallenge {
            address,
            code,
            next,
            expires,
        };

        let mut challenges = self.challenges.write().await;
        challenges.insert(challenge.code.clone(), challenge.clone());

        Ok(challenge)
    }

    async fn email_consume_challenge(
        &self,
        code: String,
    ) -> Result<Option<Self::EmailChallenge>, Self::Error> {
        let challenge = {
            let mut challenges = self.challenges.write().await;
            challenges.remove(&code)
        };

        Ok(challenge)
    }

    async fn link_oauth_token(
        &self,
        user_id: Uuid,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Self::OAuthToken {
        let UnmatchedOAuthToken {
            access_token,
            refresh_token,
            expires,
            scopes,
            provider_name,
            provider_user,
        } = unmatched_token;

        let token = MyOAuthToken {
            id: Uuid::new_v4(),
            user_id,
            provider_name,
            provider_user_id: provider_user.id,
            access_token,
            refresh_token,
            expires,
            scopes,
        };

        let mut oauth_tokens = self.oauth_tokens.write().await;

        oauth_tokens.insert(token.id, token.clone());

        token
    }

    // async fn create_oauth_token(&self, unmatched_token: UnmatchedOAuthToken) -> Self::OAuthToken {}

    async fn get_user_by_oauth_provider_id(
        &self,
        provider_name: String,
        provider_user_id: String,
    ) -> Option<(Self::User, Self::OAuthToken)> {
        let token = {
            let tokens = self.oauth_tokens.read().await;

            tokens
                .values()
                .find(|t| {
                    t.provider_name == provider_name && t.provider_user_id == provider_user_id
                })
                .cloned()
        }?;

        let user = {
            let users = self.users.read().await;
            users.get(&token.user_id).cloned()
        }?;

        Some((user, token))
    }

    async fn update_oauth_token(
        &self,
        prev_token: Self::OAuthToken,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Self::OAuthToken {
        let UnmatchedOAuthToken {
            access_token,
            refresh_token,
            expires,
            scopes,
            provider_name,
            provider_user,
        } = unmatched_token;

        let token = MyOAuthToken {
            access_token,
            refresh_token,
            expires,
            scopes,
            provider_name,
            provider_user_id: provider_user.id,
            ..prev_token
        };

        let mut tokens = self.oauth_tokens.write().await;
        tokens.insert(token.id, token.clone());

        token
    }

    async fn create_oauth_user(
        &self,
        token: UnmatchedOAuthToken,
    ) -> Option<(Self::User, Self::OAuthToken)> {
        let mut tokens = self.oauth_tokens.write().await;

        if tokens.values().any(|t| {
            t.provider_name == token.provider_name && t.provider_user_id == token.provider_user.id
        }) {
            panic!("In use")
        }

        let mut users = self.users.write().await;

        let id = Uuid::new_v4();

        let user = MyUser {
            id,
            password: None,
            emails: match token.provider_user.email {
                Some(email) => vec![MyUserEmail {
                    email,
                    allow_link_login: token.provider_user.email_verified,
                    verified: token.provider_user.email_verified,
                }],
                None => vec![],
            },
        };

        users.insert(id, user.clone());

        let token = Self::OAuthToken {
            id: Uuid::new_v4(),
            user_id: id,
            provider_name: token.provider_name,
            provider_user_id: token.provider_user.id,
            access_token: token.access_token,
            refresh_token: token.refresh_token,
            expires: token.expires,
            scopes: token.scopes,
        };

        tokens.insert(token.id, token.clone());

        Some((user, token))
    }

    async fn get_oauth_token(&self, token_id: Uuid) -> Option<Self::OAuthToken> {
        let tokens = self.oauth_tokens.read().await;
        tokens.get(&token_id).cloned()
    }
}

#[async_trait]
impl AxumUserExtendedStore for MemoryStore {
    async fn get_user_emails(&self, user_id: Uuid) -> Vec<MyUserEmail> {
        let users = self.users.read().await;

        users
            .get(&user_id)
            .map(|u| u.emails.clone())
            .unwrap_or_default()
    }

    async fn get_sessions(&self, user_id: Uuid) -> Vec<MyLoginSession> {
        let sessions = self.sessions.read().await;

        sessions
            .values()
            .filter(|s| s.user_id == user_id)
            .cloned()
            .collect()
    }

    async fn get_oauth_tokens(&self, user_id: Uuid) -> Vec<MyOAuthToken> {
        let tokens = self.oauth_tokens.read().await;

        tokens
            .values()
            .filter(|s| s.user_id == user_id)
            .cloned()
            .collect()
    }

    async fn delete_oauth_token(&self, token_id: Uuid) {
        let mut tokens = self.oauth_tokens.write().await;

        tokens.retain(|_, token| token.id != token_id);
    }

    async fn delete_user(&self, id: Uuid) {
        let mut users = self.users.write().await;
        let mut sessions = self.sessions.write().await;

        users.remove(&id);
        sessions.retain(|_, session| session.user_id != id);
    }

    async fn clear_user_password(&self, user_id: Uuid, session_id: Uuid) {
        let mut users = self.users.write().await;

        if let Some(user) = users.get_mut(&user_id) {
            let mut sessions = self.sessions.write().await;
            sessions.retain(|_, session| {
                session.user_id != user_id
                    || session.method != LoginMethod::Password
                    || session.id == session_id
            });

            user.password = None
        }
    }

    async fn set_user_password(&self, user_id: Uuid, password: String, session_id: Uuid) {
        let mut users = self.users.write().await;

        if let Some(user) = users.get_mut(&user_id) {
            let mut sessions = self.sessions.write().await;
            sessions.retain(|_, session| {
                session.user_id != user_id
                    || session.method != LoginMethod::Password
                    || session.id == session_id
            });

            user.password = Some(password)
        };
    }

    async fn set_user_email_allow_login(&self, user_id: Uuid, address: String, allow_login: bool) {
        let mut users = self.users.write().await;

        users.get_mut(&user_id).map(|u| {
            u.emails
                .iter_mut()
                .find(|e| e.email == address)
                .map(|e| e.allow_link_login = allow_login)
        });
    }

    async fn add_user_email(&self, user_id: Uuid, address: String) {
        let mut users = self.users.write().await;

        if users
            .values()
            .any(|u| u.id != user_id && u.emails.iter().any(|e| e.email == address))
        {
            panic!("Email already in use");
        }

        let emails = &mut users.get_mut(&user_id).expect("User not found").emails;

        if !emails.iter().any(|e| e.email == address) {
            emails.push(MyUserEmail {
                email: address,
                verified: false,
                allow_link_login: false,
            });
        }
    }

    async fn delete_user_email(&self, user_id: Uuid, address: String) {
        let mut users = self.users.write().await;

        users
            .get_mut(&user_id)
            .expect("User not found")
            .emails
            .retain(|e| e.email != address);
    }
}
