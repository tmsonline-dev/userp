use crate::{
    config::Allow,
    core::CoreUserp,
    enums::LoginMethod,
    traits::{User, UserpCookies, UserpStore},
};
use thiserror::Error;

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

impl<S: UserpStore, C: UserpCookies> CoreUserp<S, C> {
    #[must_use = "Don't forget to return the auth session as part of the response!"]
    pub async fn password_login(
        self,
        password_id: &str,
        password: &str,
    ) -> Result<Self, PasswordLoginError<S::Error>> {
        if self.pass.allow_login.as_ref().unwrap_or(&self.allow_login) == &Allow::Never {
            return Err(PasswordLoginError::NotAllowed);
        };

        let allow_signup = self
            .pass
            .allow_signup
            .as_ref()
            .unwrap_or(&self.allow_signup)
            == &Allow::OnEither;

        let user = match self
            .store
            .password_get_user_by_password_id(password_id)
            .await?
        {
            Some(user) => match user.get_password_hash() {
                Some(hash) => {
                    if self
                        .pass
                        .hasher
                        .verify_password(password.into(), hash)
                        .await
                    {
                        Ok(user)
                    } else {
                        Err(PasswordLoginError::WrongPassword)
                    }
                }
                None => Err(PasswordLoginError::NotAllowed),
            },
            None if allow_signup => Ok(self
                .store
                .password_create_user(
                    password_id,
                    &self.pass.hasher.genereate_hash(password.to_string()).await,
                )
                .await?),
            None => Err(PasswordLoginError::NoUser),
        }?;

        Ok(self.log_in(LoginMethod::Password, user.get_id()).await?)
    }
}
