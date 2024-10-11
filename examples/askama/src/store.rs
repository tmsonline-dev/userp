use crate::{MyEmailChallenge, MyLoginSession, MyOAuthToken, MyUser, MyUserEmail};
use axum::async_trait;
use axum_user::{AxumUserStore, LoginMethod, UnmatchedOAuthToken};
use chrono::{DateTime, Utc};
use std::{collections::HashMap, sync::Arc};
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
    type Email = MyUserEmail;
    type LoginSession = MyLoginSession;
    type EmailChallenge = MyEmailChallenge;
    type OAuthToken = MyOAuthToken;

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

    async fn get_user_by_password_id(&self, password_id: String) -> Option<Self::User> {
        let users = self.users.read().await;

        users
            .values()
            .find(|user| user.emails.iter().any(|e| e.email == password_id))
            .cloned()
    }

    async fn get_user_by_email(&self, email: String) -> Option<(Self::User, Self::Email)> {
        let users = self.users.read().await;

        users.values().find_map(|user| {
            user.emails
                .iter()
                .find(|user_email| user_email.email == email)
                .map(|email| (user.clone(), email.clone()))
        })
    }

    async fn save_email_challenge(
        &self,

        address: String,
        code: String,
        next: Option<String>,
        expires: DateTime<Utc>,
    ) -> Self::EmailChallenge {
        let challenge = MyEmailChallenge {
            address,
            code,
            next,
            expires,
        };

        let mut challenges = self.challenges.write().await;
        challenges.insert(challenge.code.clone(), challenge.clone());

        challenge
    }

    async fn consume_email_challenge(&self, code: String) -> Option<Self::EmailChallenge> {
        let challenge = {
            let mut challenges = self.challenges.write().await;
            challenges.remove(&code)
        }?;

        Some(challenge)
    }

    async fn set_user_email_verified(&self, user_id: Uuid, email: String) {
        let mut users = self.users.write().await;

        let Some(user) = users.get_mut(&user_id) else {
            return;
        };

        user.emails.iter_mut().for_each(|e| {
            if e.email == email {
                e.verified = true
            }
        });
    }

    async fn create_password_user(&self, email: String, password_hash: String) -> Self::User {
        if self.get_user_by_email(email.clone()).await.is_some() {
            panic!("user conflict");
        };

        let mut users = self.users.write().await;

        let id = Uuid::new_v4();

        let user = MyUser {
            id,
            name: "".into(),
            password: Some(password_hash),
            emails: vec![MyUserEmail {
                email,
                verified: false,
                allow_login: false,
            }],
        };

        users.insert(id, user.clone());

        user
    }

    async fn create_email_user(&self, email: String) -> (Self::User, Self::Email) {
        if self.get_user_by_email(email.clone()).await.is_some() {
            panic!("user conflict");
        };

        let mut users = self.users.write().await;

        let id = Uuid::new_v4();

        let email = MyUserEmail {
            email,
            allow_login: true,
            verified: true,
        };

        let user = MyUser {
            id,
            name: "".into(),
            password: None,
            emails: vec![email.clone()],
        };

        users.insert(id, user.clone());

        (user, email)
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

    async fn create_or_update_oauth_token(
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
        provider_name: String,
        token: UnmatchedOAuthToken,
    ) -> Option<(Self::User, Self::OAuthToken)> {
        let mut tokens = self.oauth_tokens.write().await;

        if tokens.values().any(|t| {
            t.provider_name == provider_name && t.provider_user_id == token.provider_user.id
        }) {
            panic!("In use")
        }

        let mut users = self.users.write().await;

        let id = Uuid::new_v4();

        let user = MyUser {
            id,
            name: token.provider_user.name.unwrap_or("".into()),
            password: None,
            emails: match token.provider_user.email {
                Some(email) => vec![MyUserEmail {
                    email,
                    allow_login: token.provider_user.email_verified,
                    verified: token.provider_user.email_verified,
                }],
                None => vec![],
            },
        };

        users.insert(id, user.clone());

        let token = Self::OAuthToken {
            id: Uuid::new_v4(),
            user_id: id,
            provider_name,
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

impl MemoryStore {
    pub async fn get_sessions(&self, user_id: Uuid) -> Vec<MyLoginSession> {
        let sessions = self.sessions.read().await;

        sessions
            .values()
            .filter(|s| s.user_id == user_id)
            .cloned()
            .collect()
    }

    pub async fn get_oauth_tokens(&self, user_id: Uuid) -> Vec<MyOAuthToken> {
        let tokens = self.oauth_tokens.read().await;

        tokens
            .values()
            .filter(|s| s.user_id == user_id)
            .cloned()
            .collect()
    }

    pub async fn get_oauth_token(&self, user_id: Uuid, token_id: Uuid) -> Option<MyOAuthToken> {
        let tokens = self.oauth_tokens.read().await;

        tokens
            .values()
            .find(|s| s.user_id == user_id && s.id == token_id)
            .cloned()
    }

    pub async fn delete_oauth_token(&self, user_id: Uuid, token_id: Uuid) {
        let mut tokens = self.oauth_tokens.write().await;

        tokens.retain(|_, token| token.id != token_id || token.user_id != user_id);
    }

    pub async fn delete_user(&self, id: Uuid) {
        let mut users = self.users.write().await;
        let mut sessions = self.sessions.write().await;

        users.remove(&id);
        sessions.retain(|_, session| session.user_id != id);
    }

    pub async fn clear_user_password(&self, user_id: Uuid, session_id: Uuid) {
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

    pub async fn set_user_password(
        &self,
        user_id: Uuid,
        password: impl Into<String>,
        session_id: Uuid,
    ) {
        let mut users = self.users.write().await;

        if let Some(user) = users.get_mut(&user_id) {
            let mut sessions = self.sessions.write().await;
            sessions.retain(|_, session| {
                session.user_id != user_id
                    || session.method != LoginMethod::Password
                    || session.id == session_id
            });

            user.password = Some(password.into())
        }
    }

    pub async fn set_user_email_allow_login(
        &self,
        user_id: Uuid,
        address: String,
        allow_login: bool,
    ) {
        let mut users = self.users.write().await;

        users.get_mut(&user_id).map(|u| {
            u.emails
                .iter_mut()
                .find(|e| e.email == address)
                .map(|e| e.allow_login = allow_login)
        });
    }

    pub async fn add_user_email(&self, user_id: Uuid, address: String) {
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
                allow_login: false,
            });
        }
    }

    pub async fn delete_user_email(&self, user_id: Uuid, address: String) {
        let mut users = self.users.write().await;

        users
            .get_mut(&user_id)
            .expect("User not found")
            .emails
            .retain(|e| e.email != address);
    }
}
