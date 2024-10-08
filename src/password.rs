use super::{Allow, AxumUser, AxumUserStore, LoginMethod, UserTrait};

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

impl<S: AxumUserStore> AxumUser<S> {
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn password_signup(
        self,
        password_id: String,
        password_hash: String,
    ) -> Result<Self, (Self, &'static str)> {
        let allow = self.pass.allow_login.as_ref().unwrap_or(&self.allow_login);

        if allow == &Allow::Never {
            return Err((self, "Forbidden"));
        }

        match self
            .store
            .get_user_by_password_id(password_id.clone())
            .await
        {
            Some(user) => match allow {
                Allow::Never => unreachable!(),
                Allow::OnEither => match user.validate_password_hash(password_hash) {
                    true => Ok(self.log_in(LoginMethod::Password, user.get_id()).await),
                    false => Err((self, "Wrong password")),
                },
                Allow::OnSelf => Err((self, "User already exists")),
            },
            None => {
                let user = self
                    .store
                    .create_password_user(password_id, password_hash)
                    .await;

                Ok(self.log_in(LoginMethod::Password, user.get_id()).await)
            }
        }
    }

    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn password_login(
        self,
        password_id: String,
        password_hash: String,
    ) -> Result<Self, (Self, &'static str)> {
        let allow = self.pass.allow_login.as_ref().unwrap_or(&self.allow_login);

        if allow == &Allow::Never {
            return Err((self, "Forbidden"));
        };

        match self
            .store
            .get_user_by_password_id(password_id.clone())
            .await
        {
            Some(user) => {
                if user.validate_password_hash(password_hash) {
                    Ok(self.log_in(LoginMethod::Password, user.get_id()).await)
                } else {
                    Err((self, "Wrong password"))
                }
            }
            None => match allow {
                Allow::Never => unreachable!(),
                Allow::OnEither => {
                    let user = self
                        .store
                        .create_password_user(password_id, password_hash)
                        .await;

                    Ok(self.log_in(LoginMethod::Password, user.get_id()).await)
                }
                Allow::OnSelf => Err((self, "Unknown user")),
            },
        }
    }
}
