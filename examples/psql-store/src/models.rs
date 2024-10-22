use crate::password;

use userp::{
    chrono::{DateTime, Utc},
    prelude::{EmailChallenge, LoginMethod, LoginSession, OAuthToken, User, UserEmail},
    uuid::Uuid,
};

#[derive(Debug, Clone)]
pub struct MyUser {
    pub id: Uuid,
    #[allow(unused)]
    pub name: Option<String>,
    pub password_hash: Option<String>,
}

impl User for MyUser {
    fn get_allow_password_login(&self) -> bool {
        self.password_hash.is_some()
    }

    fn get_id(&self) -> Uuid {
        self.id
    }
}

impl MyUser {
    pub async fn validate_password(&self, password: &str) -> bool {
        if let Some(hash) = self.password_hash.as_ref() {
            password::verify(password.to_string(), hash.clone()).await
        } else {
            false
        }
    }
}

#[derive(Debug, Clone)]
pub struct MyUserEmail {
    #[allow(unused)]
    pub id: Uuid,
    #[allow(unused)]
    pub user_id: Uuid,
    pub address: String,
    pub verified: bool,
    pub allow_link_login: bool,
}

impl UserEmail for MyUserEmail {
    fn get_address(&self) -> &str {
        self.address.as_str()
    }

    fn get_verified(&self) -> bool {
        self.verified
    }

    fn get_allow_link_login(&self) -> bool {
        self.allow_link_login
    }
}

#[derive(Debug, Clone)]
pub struct MyLoginSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub method: String,
    pub oauth_token_id: Option<Uuid>,
    pub email_address: Option<String>,
}

impl LoginSession for MyLoginSession {
    fn get_id(&self) -> Uuid {
        self.id
    }

    fn get_user_id(&self) -> Uuid {
        self.user_id
    }

    fn get_method(&self) -> LoginMethod {
        match self.method.as_str() {
            "password" => LoginMethod::Password,
            "password_reset" => LoginMethod::PasswordReset {
                address: self
                    .email_address
                    .as_ref()
                    .expect("Missing email_address for LoginMethod::PasswordReset")
                    .clone(),
            },
            "email" => LoginMethod::Email {
                address: self
                    .email_address
                    .as_ref()
                    .expect("Missing email_address for LoginMethod::Email")
                    .clone(),
            },
            "oauth" => LoginMethod::OAuth {
                token_id: self
                    .oauth_token_id
                    .expect("Missing oauth token id for LoginMethod::OAuth"),
            },
            method => panic!("Unexpected login method: {method}"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MyEmailChallenge {
    #[allow(unused)]
    pub id: Uuid,
    pub address: String,
    pub code: String,
    pub next: Option<String>,
    pub expires: DateTime<Utc>,
}

impl EmailChallenge for MyEmailChallenge {
    fn get_address(&self) -> &str {
        &self.address
    }

    fn get_code(&self) -> &str {
        &self.code
    }

    fn get_next(&self) -> &Option<String> {
        &self.next
    }

    fn get_expires(&self) -> DateTime<Utc> {
        self.expires
    }
}

#[derive(Clone, Debug)]
#[allow(unused)]
pub struct MyOAuthToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider_name: String,
    pub provider_user_id: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
}

impl OAuthToken for MyOAuthToken {
    fn get_id(&self) -> Uuid {
        self.id
    }

    fn get_provider_name(&self) -> &str {
        self.provider_name.as_str()
    }

    fn get_refresh_token(&self) -> &Option<String> {
        &self.refresh_token
    }
}
