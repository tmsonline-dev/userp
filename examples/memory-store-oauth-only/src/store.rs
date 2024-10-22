use crate::models::{MyLoginSession, MyOAuthToken, MyUser};
use axum::async_trait;
use std::{collections::HashMap, convert::Infallible, sync::Arc};
use tokio::sync::RwLock;

use userp::{
    uuid::Uuid, LoginMethod, OAuthLinkError, OAuthLoginError, OAuthSignupError,
    UnmatchedOAuthToken, UserpStore,
};

#[derive(Clone, Default, Debug)]
pub struct MemoryStore {
    sessions: Arc<RwLock<HashMap<Uuid, MyLoginSession>>>,
    users: Arc<RwLock<HashMap<Uuid, MyUser>>>,
    oauth_tokens: Arc<RwLock<HashMap<Uuid, MyOAuthToken>>>,
}

#[async_trait]
impl UserpStore for MemoryStore {
    type User = MyUser;
    type LoginSession = MyLoginSession;
    type OAuthToken = MyOAuthToken;
    type Error = Infallible;

    async fn get_session(
        &self,
        session_id: Uuid,
    ) -> Result<Option<Self::LoginSession>, Self::Error> {
        let sessions = self.sessions.read().await;

        Ok(sessions.get(&session_id).cloned())
    }

    async fn delete_session(&self, session_id: Uuid) -> Result<(), Self::Error> {
        let mut sessions = self.sessions.write().await;

        sessions.remove(&session_id);

        Ok(())
    }

    async fn create_session(
        &self,
        user_id: Uuid,
        method: LoginMethod,
    ) -> Result<Self::LoginSession, Self::Error> {
        let session = MyLoginSession {
            id: Uuid::new_v4(),
            user_id,
            method,
        };

        let mut sessions = self.sessions.write().await;

        sessions.insert(session.id, session.clone());

        Ok(session)
    }

    async fn get_user(&self, user_id: Uuid) -> Result<Option<MyUser>, Self::Error> {
        let users = self.users.read().await;

        Ok(users.get(&user_id).cloned())
    }

    async fn oauth_link(
        &self,
        user_id: Uuid,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Self::OAuthToken, OAuthLinkError<Self::Error>> {
        let UnmatchedOAuthToken {
            access_token,
            refresh_token,
            expires,
            scopes,
            provider_name,
            provider_user,
        } = unmatched_token;

        let mut oauth_tokens = self.oauth_tokens.write().await;

        let existing_token = oauth_tokens
            .values()
            .find(|t| t.provider_name == provider_name && t.provider_user_id == provider_user.id);

        if existing_token.is_some_and(|t| t.user_id != user_id) {
            return Err(OAuthLinkError::UserConflict);
        };

        let token = MyOAuthToken {
            id: existing_token.map(|t| t.id).unwrap_or(Uuid::new_v4()),
            user_id,
            provider_name,
            provider_user_id: provider_user.id,
            access_token,
            refresh_token,
            expires,
            scopes,
        };

        oauth_tokens.insert(token.id, token.clone());

        Ok(token)
    }

    async fn oauth_signup(
        &self,
        unmatched_token: UnmatchedOAuthToken,
        allow_login: bool,
    ) -> Result<(Self::User, Self::OAuthToken), OAuthSignupError<Self::Error>> {
        let mut tokens = self.oauth_tokens.write().await;
        let mut users = self.users.write().await;

        let user_token = tokens
            .values()
            .find(|t| {
                t.provider_name == unmatched_token.provider_name
                    && t.provider_user_id == unmatched_token.provider_user.id
            })
            .and_then(|t| users.get(&t.user_id).map(|u| (u, t)));

        if let Some((user, token)) = user_token {
            if allow_login {
                Ok((user.clone(), token.clone()))
            } else {
                Err(OAuthSignupError::UserExists)
            }
        } else {
            let user_id = Uuid::new_v4();
            let user = MyUser { id: user_id };

            let token_id = Uuid::new_v4();

            let token = MyOAuthToken {
                id: token_id,
                user_id,
                provider_name: unmatched_token.provider_name,
                provider_user_id: unmatched_token.provider_user.id,
                access_token: unmatched_token.access_token,
                refresh_token: unmatched_token.refresh_token,
                expires: unmatched_token.expires,
                scopes: unmatched_token.scopes,
            };

            users.insert(user_id, user.clone());
            tokens.insert(token_id, token.clone());

            Ok((user, token))
        }
    }

    async fn oauth_login(
        &self,
        unmatched_token: UnmatchedOAuthToken,
        allow_signup: bool,
    ) -> Result<(Self::User, Self::OAuthToken), OAuthLoginError<Self::Error>> {
        let mut tokens = self.oauth_tokens.write().await;
        let mut users = self.users.write().await;

        let user_token = tokens
            .values()
            .find(|t| {
                t.provider_name == unmatched_token.provider_name
                    && t.provider_user_id == unmatched_token.provider_user.id
            })
            .and_then(|t| users.get(&t.user_id).map(|u| (u, t)));

        if let Some((user, token)) = user_token {
            Ok((user.clone(), token.clone()))
        } else if allow_signup {
            let user_id = Uuid::new_v4();
            let user = MyUser { id: user_id };

            let token_id = Uuid::new_v4();

            let token = MyOAuthToken {
                id: token_id,
                user_id,
                provider_name: unmatched_token.provider_name,
                provider_user_id: unmatched_token.provider_user.id,
                access_token: unmatched_token.access_token,
                refresh_token: unmatched_token.refresh_token,
                expires: unmatched_token.expires,
                scopes: unmatched_token.scopes,
            };

            users.insert(user_id, user.clone());
            tokens.insert(token_id, token.clone());

            Ok((user, token))
        } else {
            Err(OAuthLoginError::NoUser)
        }
    }

    async fn oauth_update_token(
        &self,
        prev_token: Self::OAuthToken,
        unmatched_token: UnmatchedOAuthToken,
    ) -> Result<Self::OAuthToken, Self::Error> {
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

        Ok(token)
    }

    async fn oauth_get_token(
        &self,
        token_id: Uuid,
    ) -> Result<Option<Self::OAuthToken>, Self::Error> {
        let tokens = self.oauth_tokens.read().await;
        Ok(tokens.get(&token_id).cloned())
    }
}
