use crate::models::*;
use userp::{
    prelude::*,
    reexports::{
        chrono::{DateTime, Utc},
        uuid::Uuid,
    },
};

impl User for MyUser {
    fn get_password_hash(&self) -> Option<String> {
        self.password_hash.clone()
    }

    fn get_id(&self) -> Uuid {
        self.id
    }
}

impl UserEmail for MyUserEmail {
    fn get_user_id(&self) -> Uuid {
        self.user_id
    }

    fn get_address(&self) -> &str {
        self.email.as_str()
    }

    fn get_verified(&self) -> bool {
        self.verified
    }

    fn get_allow_link_login(&self) -> bool {
        self.allow_link_login
    }
}

pub const PASSWORD_LOGIN_METHOD: &str = "password";
pub const PASSWORD_RESET_LOGIN_METHOD: &str = "password_reset";
pub const EMAIL_LOGIN_METHOD: &str = "email";
pub const OAUTH_LOGIN_METHOD: &str = "oauth";

impl LoginSession for MyLoginSession {
    fn get_id(&self) -> Uuid {
        self.id
    }

    fn get_user_id(&self) -> Uuid {
        self.user_id
    }

    fn get_method(&self) -> LoginMethod {
        match self.method.as_str() {
            PASSWORD_LOGIN_METHOD => LoginMethod::Password,
            PASSWORD_RESET_LOGIN_METHOD => LoginMethod::PasswordReset {
                address: self
                    .email_address
                    .as_ref()
                    .expect("Missing email_address for LoginMethod::PasswordReset")
                    .clone(),
            },
            EMAIL_LOGIN_METHOD => LoginMethod::Email {
                address: self
                    .email_address
                    .as_ref()
                    .expect("Missing email_address for LoginMethod::Email")
                    .clone(),
            },
            OAUTH_LOGIN_METHOD => LoginMethod::OAuth {
                token_id: self
                    .oauth_token_id
                    .expect("Missing oauth token id for LoginMethod::OAuth"),
            },
            method => panic!("Unexpected login method: {method}"),
        }
    }
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
impl OAuthToken for MyOAuthToken {
    fn get_id(&self) -> Uuid {
        self.id
    }

    fn get_user_id(&self) -> Uuid {
        self.user_id
    }

    fn get_provider_name(&self) -> &str {
        self.provider_name.as_str()
    }

    fn get_refresh_token(&self) -> &Option<String> {
        &self.refresh_token
    }
}
