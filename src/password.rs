use super::{Allow, AxumUser, AxumUserStore, LoginMethod, User};
use thiserror::Error;

#[cfg(feature = "email")]
#[derive(Clone, PartialEq, Eq)]
pub enum PasswordReset {
    Never,
    VerifiedEmailOnly,
    AnyUserEmail,
}

#[derive(Clone)]
pub struct PasswordConfig {
    pub allow_login: Option<Allow>,
    pub allow_signup: Option<Allow>,
    #[cfg(feature = "email")]
    pub allow_reset: PasswordReset,
}

impl PasswordConfig {
    pub fn new() -> Self {
        Self {
            allow_login: None,
            allow_signup: None,
            allow_reset: PasswordReset::VerifiedEmailOnly,
        }
    }

    pub fn with_allow_signup(mut self, allow_signup: Allow) -> Self {
        self.allow_signup = Some(allow_signup);
        self
    }

    pub fn with_allow_login(mut self, allow_login: Allow) -> Self {
        self.allow_login = Some(allow_login);
        self
    }

    #[cfg(feature = "email")]
    pub fn with_allow_reset(mut self, allow_reset: PasswordReset) -> Self {
        self.allow_reset = allow_reset;
        self
    }
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Error, Debug)]
pub enum PasswordLoginError<T: std::error::Error> {
    #[error("Password login not allowed")]
    NotAllowed,
    #[error("User doesn't exists")]
    NoUser,
    #[error("Wrong password")]
    WrongPassword,
    #[error(transparent)]
    StoreError(#[from] T),
}

#[derive(Error, Debug)]
pub enum PasswordSignupError<T: std::error::Error> {
    #[error("Password signup not allowed")]
    NotAllowed,
    #[error("User already exists")]
    UserExists,
    #[error("Wrong login password")]
    WrongPassword,
    #[error(transparent)]
    StoreError(#[from] T),
}

impl<S: AxumUserStore> AxumUser<S> {
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn password_signup(
        self,
        password_id: String,
        password_hash: String,
    ) -> Result<Self, PasswordSignupError<S::Error>> {
        if self
            .pass
            .allow_signup
            .as_ref()
            .unwrap_or(&self.allow_signup)
            == &Allow::Never
        {
            return Err(PasswordSignupError::NotAllowed);
        }

        let user = self
            .store
            .password_signup(
                password_id,
                password_hash,
                self.email
                    .allow_login
                    .as_ref()
                    .unwrap_or(&self.allow_signup)
                    == &Allow::OnEither,
            )
            .await?;

        Ok(self.log_in(LoginMethod::Password, user.get_id()).await)
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn password_login(
        self,
        password_id: String,
        password_hash: String,
    ) -> Result<Self, PasswordLoginError<S::Error>> {
        if self.pass.allow_login.as_ref().unwrap_or(&self.allow_login) == &Allow::Never {
            return Err(PasswordLoginError::NotAllowed);
        };

        let user = self
            .store
            .password_login(
                password_id,
                password_hash,
                self.email
                    .allow_signup
                    .as_ref()
                    .unwrap_or(&self.allow_signup)
                    == &Allow::OnEither,
            )
            .await?;

        Ok(self.log_in(LoginMethod::Password, user.get_id()).await)
    }
}
