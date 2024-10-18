use crate::password::hash;
use crate::{MyEmailChallenge, MyLoginSession, MyOAuthToken, MyUser, MyUserEmail};
use axum::async_trait;
use chrono::{DateTime, Utc};
use std::{collections::HashMap, convert::Infallible, sync::Arc};
use tokio::sync::RwLock;
use userp::{
    EmailLoginError, EmailResetError, EmailSignupError, EmailVerifyError, LoginMethod,
    OAuthLinkError, OAuthLoginError, OAuthSignupError, PasswordLoginError, PasswordSignupError,
    UnmatchedOAuthToken, User, UserpStore,
};
use uuid::Uuid;

#[derive(Clone, Default, Debug)]
pub struct MemoryStore {
    sessions: Arc<RwLock<HashMap<Uuid, MyLoginSession>>>,
    users: Arc<RwLock<HashMap<Uuid, MyUser>>>,
    challenges: Arc<RwLock<HashMap<String, MyEmailChallenge>>>,
    oauth_tokens: Arc<RwLock<HashMap<Uuid, MyOAuthToken>>>,
}

#[async_trait]
impl UserpStore for MemoryStore {
    type User = MyUser;
    type UserEmail = MyUserEmail;
    type LoginSession = MyLoginSession;
    type EmailChallenge = MyEmailChallenge;
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

    async fn password_login(
        &self,
        password_id: &str,
        password: &str,
        allow_signup: bool,
    ) -> Result<Self::User, PasswordLoginError<Self::Error>> {
        let mut users = self.users.write().await;

        let user = users
            .values()
            .find(|user| user.emails.iter().any(|e| e.email == password_id));

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
                        emails: vec![MyUserEmail {
                            email: password_id.to_owned(),
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
        password_id: &str,
        password: &str,
        allow_login: bool,
    ) -> Result<Self::User, PasswordSignupError<Self::Error>> {
        let mut users = self.users.write().await;

        let user = users
            .values()
            .find(|user| user.emails.iter().any(|e| e.email == password_id));

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
                    emails: vec![MyUserEmail {
                        email: password_id.into(),
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
        address: &str,
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
                        password_hash: None,
                        emails: vec![MyUserEmail {
                            email: address.into(),
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
        address: &str,
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
                    password_hash: None,
                    emails: vec![MyUserEmail {
                        email: address.into(),
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
        address: &str,
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

    async fn email_verify(&self, address: &str) -> Result<(), EmailVerifyError<Self::Error>> {
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
            let user = MyUser {
                id: user_id,
                password_hash: None,
                emails: unmatched_token
                    .provider_user
                    .email
                    .map(|e| {
                        vec![MyUserEmail {
                            email: e,
                            verified: unmatched_token.provider_user.email_verified,
                            allow_link_login: unmatched_token.provider_user.email_verified,
                        }]
                    })
                    .unwrap_or_default(),
            };

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
            let user = MyUser {
                id: user_id,
                password_hash: None,
                emails: unmatched_token
                    .provider_user
                    .email
                    .map(|e| {
                        vec![MyUserEmail {
                            email: e,
                            verified: unmatched_token.provider_user.email_verified,
                            allow_link_login: unmatched_token.provider_user.email_verified,
                        }]
                    })
                    .unwrap_or_default(),
            };

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

    async fn get_user_emails(&self, user_id: Uuid) -> Result<Vec<MyUserEmail>, Self::Error> {
        let users = self.users.read().await;

        Ok(users
            .get(&user_id)
            .map(|u| u.emails.clone())
            .unwrap_or_default())
    }

    async fn get_user_sessions(&self, user_id: Uuid) -> Result<Vec<MyLoginSession>, Self::Error> {
        let sessions = self.sessions.read().await;

        Ok(sessions
            .values()
            .filter(|s| s.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn get_user_oauth_tokens(&self, user_id: Uuid) -> Result<Vec<MyOAuthToken>, Self::Error> {
        let tokens = self.oauth_tokens.read().await;

        Ok(tokens
            .values()
            .filter(|s| s.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn delete_oauth_token(&self, token_id: Uuid) -> Result<(), Self::Error> {
        let mut tokens = self.oauth_tokens.write().await;

        tokens.retain(|_, token| token.id != token_id);
        Ok(())
    }

    async fn delete_user(&self, id: Uuid) -> Result<(), Self::Error> {
        let mut users = self.users.write().await;
        let mut sessions = self.sessions.write().await;

        users.remove(&id);
        sessions.retain(|_, session| session.user_id != id);
        Ok(())
    }

    async fn clear_user_password(
        &self,
        user_id: Uuid,
        session_id: Uuid,
    ) -> Result<(), Self::Error> {
        let mut users = self.users.write().await;

        if let Some(user) = users.get_mut(&user_id) {
            let mut sessions = self.sessions.write().await;
            sessions.retain(|_, session| {
                session.user_id != user_id
                    || session.method != LoginMethod::Password
                    || session.id == session_id
            });

            user.password_hash = None
        }
        Ok(())
    }

    async fn set_user_password(
        &self,
        user_id: Uuid,
        password: String,
        session_id: Uuid,
    ) -> Result<(), Self::Error> {
        let mut users = self.users.write().await;

        if let Some(user) = users.get_mut(&user_id) {
            let mut sessions = self.sessions.write().await;
            sessions.retain(|_, session| {
                session.user_id != user_id
                    || session.method != LoginMethod::Password
                    || session.id == session_id
            });

            user.password_hash = Some(hash(password).await)
        };
        Ok(())
    }

    async fn set_user_email_allow_link_login(
        &self,
        user_id: Uuid,
        address: String,
        allow_login: bool,
    ) -> Result<(), Self::Error> {
        let mut users = self.users.write().await;

        users.get_mut(&user_id).map(|u| {
            u.emails
                .iter_mut()
                .find(|e| e.email == address)
                .map(|e| e.allow_link_login = allow_login)
        });
        Ok(())
    }

    async fn add_user_email(&self, user_id: Uuid, address: String) -> Result<(), Self::Error> {
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
        Ok(())
    }

    async fn delete_user_email(&self, user_id: Uuid, address: String) -> Result<(), Self::Error> {
        let mut users = self.users.write().await;

        users
            .get_mut(&user_id)
            .expect("User not found")
            .emails
            .retain(|e| e.email != address);
        Ok(())
    }
}
