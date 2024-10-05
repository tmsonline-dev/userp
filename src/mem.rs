use crate::{
    auth::{Email, EmailChallenge, OAuthToken, Session, Store, UnmatchedOAuthToken},
    MyUser, MyUserEmail,
};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone, Default)]
pub struct MemoryAuthStore {
    sessions: Arc<RwLock<HashMap<Uuid, Session>>>,
    users: Arc<RwLock<HashMap<Uuid, MyUser>>>,
    challenges: Arc<RwLock<HashMap<String, EmailChallenge>>>,
    oauth_tokens: Arc<RwLock<HashMap<Uuid, OAuthToken>>>,
}

impl Store for MemoryAuthStore {
    type User = MyUser;

    // async fn verify_session(&self, id: Uuid) -> bool {
    //     let lock = self.sessions.read().await;

    //     lock.get(&id).is_some()
    // }

    async fn get_session(&self, session_id: Uuid) -> Option<Session> {
        let sessions = self.sessions.read().await;

        sessions.get(&session_id).cloned()
    }

    async fn delete_session(&self, session_id: Uuid) {
        let mut sessions = self.sessions.write().await;

        sessions.remove(&session_id);
    }

    async fn create_session(&self, session: Session) {
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

    async fn get_user_emails(&self, user_id: Uuid) -> Vec<crate::auth::Email> {
        let users = self.users.read().await;

        let Some(user) = users.get(&user_id) else {
            return vec![];
        };

        user.emails
            .clone()
            .into_iter()
            .map(|e| Email {
                email: e.email,
                verified: e.verified,
                allow_login: true,
            })
            .collect()
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

    async fn create_email_user(&self, email: String) -> Self::User {
        let mut users = self.users.write().await;

        if self.get_user_by_email(email.clone()).await.is_some() {
            panic!("user conflict");
        };

        let id = Uuid::new_v4();

        let user = MyUser {
            id,
            name: "".into(),
            password: "".into(),
            emails: vec![MyUserEmail {
                email,
                verified: true,
            }],
        };

        users.insert(id, user.clone());

        user
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
    pub async fn user_name_taken(&self, name: &str) -> bool {
        let users = self.users.read().await;

        users.values().any(|user| user.name == name)
    }

    pub async fn login(
        &self,
        name: impl Into<String>,
        password: impl Into<String>,
    ) -> Option<Uuid> {
        let name = name.into();
        let password = password.into();
        let users = self.users.read().await;

        users
            .iter()
            .find(|(_, user)| user.name == name && user.password == password)
            .map(|(id, _)| *id)
    }

    pub async fn create_user(&self, name: impl Into<String>, password: impl Into<String>) -> Uuid {
        let id = Uuid::new_v4();

        let mut users = self.users.write().await;

        users.insert(
            id,
            MyUser {
                id,
                name: name.into(),
                password: password.into(),
                emails: vec![],
            },
        );

        id
    }

    pub async fn delete_user(&self, id: Uuid) {
        let mut users = self.users.write().await;
        let mut sessions = self.sessions.write().await;

        users.remove(&id);
        sessions.retain(|_, session| session.user_id != id);
    }

    pub async fn set_user_password(&self, user_id: Uuid, password: impl Into<String>) {
        let mut users = self.users.write().await;

        if let Some(user) = users.get_mut(&user_id) {
            user.password = password.into()
        }
    }
}
