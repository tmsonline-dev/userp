use super::{Allow, AxumUser, AxumUserStore, LoginMethod, UserTrait};

#[derive(Clone)]
pub struct PasswordConfig {
    pub allow_login: Allow,
    pub allow_signup: Allow,
}

impl<S: AxumUserStore> AxumUser<S> {
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn password_signup(
        self,
        password_id: String,
        password_hash: String,
    ) -> Result<Self, (Self, &'static str)> {
        match self
            .store
            .get_user_by_password_id(password_id.clone())
            .await
        {
            Some(user) => match self.pass.allow_login {
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
        match self
            .store
            .get_user_by_password_id(password_id.clone())
            .await
        {
            Some(user) => match user.validate_password_hash(password_hash) {
                true => Ok(self.log_in(LoginMethod::Password, user.get_id()).await),
                false => Err((self, "Wrong password")),
            },
            None => match self.pass.allow_signup {
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
