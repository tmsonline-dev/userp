use crate::models::{MyLoginSession, MyUser};
use crate::password::hash;
use axum::async_trait;
use std::{collections::HashMap, convert::Infallible, sync::Arc};
use tokio::sync::RwLock;

use userp::{uuid::Uuid, LoginMethod, PasswordLoginError, PasswordSignupError, UserpStore};

#[derive(Clone, Default, Debug)]
pub struct MemoryStore {
    sessions: Arc<RwLock<HashMap<Uuid, MyLoginSession>>>,
    users: Arc<RwLock<HashMap<Uuid, MyUser>>>,
}

#[async_trait]
impl UserpStore for MemoryStore {
    type User = MyUser;
    type LoginSession = MyLoginSession;
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

    async fn password_login(
        &self,
        password_id: &str,
        password: &str,
        allow_signup: bool,
    ) -> Result<Self::User, PasswordLoginError<Self::Error>> {
        let mut users = self.users.write().await;

        let user = users.values().find(|user| user.email == password_id);

        match user {
            Some(user) => {
                if user.validate_password(password).await {
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
                        password_hash: Some(hash(password.to_owned()).await),
                        email: password_id.to_owned(),
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
        password_id: &str,
        password: &str,
        allow_login: bool,
    ) -> Result<Self::User, PasswordSignupError<Self::Error>> {
        let mut users = self.users.write().await;

        let user = users.values().find(|user| user.email == password_id);

        match user {
            Some(user) => {
                if allow_login {
                    if user.validate_password(password).await {
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
                    password_hash: Some(hash(password.into()).await),
                    email: password_id.into(),
                };

                users.insert(id, user.clone());

                Ok(user)
            }
        }
    }
}
