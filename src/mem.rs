use crate::{
    auth::{
        Email, EmailChallenge, LoginMethod, LoginSession, OAuthToken, Store, UnmatchedOAuthToken,
    },
    MyUser, MyUserEmail,
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone, Default)]
pub struct MemoryAuthStore {
    sessions: Arc<RwLock<HashMap<Uuid, LoginSession>>>,
    users: Arc<RwLock<HashMap<Uuid, MyUser>>>,
    challenges: Arc<RwLock<HashMap<String, EmailChallenge>>>,
    oauth_tokens: Arc<RwLock<HashMap<Uuid, OAuthToken>>>,
}

impl Store for MemoryAuthStore {
    type User = MyUser;

    async fn get_session(&self, session_id: Uuid) -> Option<LoginSession> {
        let sessions = self.sessions.read().await;

        sessions.get(&session_id).cloned()
    }

    async fn delete_session(&self, session_id: Uuid) {
        let mut sessions = self.sessions.write().await;

        sessions.remove(&session_id);
    }

    async fn create_session(&self, session: LoginSession) {
        let mut sessions = self.sessions.write().await;

        sessions.insert(session.id, session);
    }

    async fn get_user(&self, user_id: Uuid) -> Option<MyUser> {
        let users = self.users.read().await;

        users.get(&user_id).cloned()
    }

    async fn set_password_hash(&self, user_id: Uuid, password_hash: String) {
        let mut users = self.users.write().await;

        if let Some(user) = users.get_mut(&user_id) {
            user.password = password_hash;
        }
    }

    async fn get_user_by_password_id(&self, password_id: String) -> Option<Self::User> {
        let users = self.users.read().await;

        users
            .values()
            .find(|user| user.name == password_id)
            .cloned()
    }

    async fn get_user_by_email(&self, email: String) -> Option<(Self::User, Email)> {
        let users = self.users.read().await;

        users.values().find_map(|user| {
            user.emails
                .iter()
                .find(|user_email| user_email.email == email)
                .map(|email| (user.clone(), email.clone().into()))
        })
    }

    async fn save_email_challenge(&self, challenge: EmailChallenge) {
        let mut challenges = self.challenges.write().await;
        challenges.insert(challenge.identifier(), challenge);
    }

    async fn consume_email_challenge(
        &self,
        identifier: String,
    ) -> Option<(String, Option<(Self::User, Email)>, Option<String>)> {
        let challenge = {
            let mut challenges = self.challenges.write().await;
            challenges.remove(&identifier)
        }?;

        Some((
            challenge.email.clone(),
            self.get_user_by_email(challenge.email).await,
            challenge.next,
        ))
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
        let mut users = self.users.write().await;

        if self.get_user_by_email(email.clone()).await.is_some() {
            panic!("user conflict");
        };

        let id = Uuid::new_v4();

        let user = MyUser {
            id,
            name: "".into(),
            password: password_hash,
            emails: vec![MyUserEmail {
                email,
                verified: false,
            }],
        };

        users.insert(id, user.clone());

        user
    }

    async fn create_email_user(&self, email: String) -> (Self::User, Email) {
        let mut users = self.users.write().await;

        if self.get_user_by_email(email.clone()).await.is_some() {
            panic!("user conflict");
        };

        let id = Uuid::new_v4();

        let email = MyUserEmail {
            email,
            verified: true,
        };

        let user = MyUser {
            id,
            name: "".into(),
            password: "".into(),
            emails: vec![email.clone()],
        };

        users.insert(id, user.clone());

        (user, email.into())
    }

    async fn get_user_by_oauth_provider_id(
        &self,
        provider_name: String,
        provider_user_id: String,
    ) -> Option<(Self::User, crate::auth::OAuthToken)> {
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

    async fn update_oauth_token(&self, token: crate::auth::OAuthToken) {
        let mut tokens = self.oauth_tokens.write().await;
        tokens.insert(token.id, token);
    }

    async fn create_oauth_user(
        &self,
        provider_name: String,
        token: UnmatchedOAuthToken,
    ) -> Option<(Self::User, crate::auth::OAuthToken)> {
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
            password: "".into(),
            emails: match token.provider_user.email {
                Some(email) => vec![MyUserEmail {
                    email,
                    verified: token.provider_user.email_verified,
                }],
                None => vec![],
            },
        };

        users.insert(id, user.clone());

        let token = OAuthToken {
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
}

impl MemoryAuthStore {
    pub async fn delete_user(&self, id: Uuid) {
        let mut users = self.users.write().await;
        let mut sessions = self.sessions.write().await;

        users.remove(&id);
        sessions.retain(|_, session| session.user_id != id);
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

            user.password = password.into()
        }
    }
}
