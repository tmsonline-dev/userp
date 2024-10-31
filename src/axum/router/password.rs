use crate::prelude::{PasswordLoginError, PasswordSignupError};
use crate::{axum::AxumUserp, config::UserpConfig, traits::UserpStore};
use axum::{
    extract::FromRef,
    response::{IntoResponse, Redirect},
    routing::post,
    Form, Router,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordIdNextForm {
    pub password_id: String,
    pub password: String,
    pub next: Option<String>,
}

impl UserpConfig {
    pub(crate) fn with_password_routes<St, S>(&self, mut router: Router<S>) -> Router<S>
    where
        UserpConfig: FromRef<S>,
        S: Send + Sync + Clone + 'static,
        St: UserpStore + FromRef<S> + Send + Sync + 'static,
        St::Error: IntoResponse,
    {
        router = router
            .route(
                self.routes.password.login_password.as_str(),
                post(post_login_password::<St>),
            )
            .route(
                self.routes.password.signup_password.as_str(),
                post(post_signup_password::<St>),
            );

        router
    }
}

async fn post_signup_password<St>(
    auth: AxumUserp<St>,
    Form(PasswordIdNextForm {
        password_id: email,
        password,
        next,
    }): Form<PasswordIdNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let signup_route = auth.routes.pages.signup.clone();

    match auth.password_signup(&email, &password).await {
        Ok(auth) => {
            let next = next.unwrap_or(auth.routes.pages.post_login.clone());
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            PasswordSignupError::StoreError(err) => Err(err),
            _ => {
                let next = format!(
                    "{signup_route}?error={}",
                    urlencoding::encode(&err.to_string())
                );
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

async fn post_login_password<St>(
    auth: AxumUserp<St>,
    Form(PasswordIdNextForm {
        password_id: email,
        password,
        next,
    }): Form<PasswordIdNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.pages.login.clone();

    match auth.password_login(&email, &password).await {
        Ok(auth) => {
            let next = next.unwrap_or(auth.routes.pages.post_login.clone());
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            PasswordLoginError::StoreError(err) => Err(err),
            PasswordLoginError::NotAllowed
            | PasswordLoginError::NoUser
            | PasswordLoginError::WrongPassword => {
                let next = format!(
                    "{login_route}?error={}",
                    urlencoding::encode(&err.to_string())
                );
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}
