use crate::email::verify::EmailVerifyCallbackError;
use crate::email::SendEmailChallengeError;
use crate::prelude::{
    EmailLoginCallbackError, EmailLoginError, EmailLoginInitError, EmailSignupCallbackError,
    EmailSignupInitError,
};
use crate::{axum::AxumUserp, config::UserpConfig, traits::UserpStore};
use axum::extract::Query;
use axum::routing::get;
use axum::{
    extract::FromRef,
    response::{IntoResponse, Redirect},
    routing::post,
    Form, Router,
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct EmailNextForm {
    pub email: String,
    pub next: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CodeQuery {
    pub code: String,
}

#[derive(Deserialize)]
pub struct NewPasswordForm {
    pub new_password: String,
}

impl UserpConfig {
    pub(crate) fn with_email_routes<St, S>(&self, mut router: Router<S>) -> Router<S>
    where
        UserpConfig: FromRef<S>,
        S: Send + Sync + Clone + 'static,
        St: UserpStore + FromRef<S> + Send + Sync + 'static,
        St::Error: IntoResponse,
    {
        router = router
            .route(
                self.routes.email.login_email.as_str(),
                post(post_login_email::<St>).get(get_login_email::<St>),
            )
            .route(
                self.routes.email.signup_email.as_str(),
                post(post_signup_email::<St>).get(get_signup_email::<St>),
            )
            .route(
                self.routes.email.user_email_verify.as_str(),
                post(post_user_email_verify::<St>).get(get_user_email_verify::<St>),
            );

        #[cfg(feature = "axum-router-password")]
        {
            router = router
                .route(
                    self.routes.email.password_reset.as_str(),
                    post(post_password_reset::<St>),
                )
                .route(
                    self.routes.email.password_reset_callback.as_str(),
                    get(get_password_reset_callback::<St>),
                )
                .route(
                    self.routes.email.password_send_reset.as_str(),
                    post(post_password_send_reset::<St>),
                );
        }

        router
    }
}

async fn post_login_email<St>(
    auth: AxumUserp<St>,
    Form(EmailNextForm { email, next }): Form<EmailNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.pages.login.clone();

    match auth.email_login_init(email.clone(), next).await {
        Ok(()) => {
            let next = format!(
                "{login_route}?message=Login link sent to {}!",
                urlencoding::encode(&email)
            );

            Ok(Redirect::to(&next).into_response())
        }
        Err(err) => match err {
            EmailLoginInitError::SendingEmail(SendEmailChallengeError::Store(err)) => Err(err),
            _ => {
                let next = format!(
                    "{login_route}?error={}",
                    urlencoding::encode(&err.to_string())
                );
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

async fn get_login_email<St>(
    auth: AxumUserp<St>,
    Query(CodeQuery { code }): Query<CodeQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.pages.login.clone();

    match auth.email_login_callback(code).await {
        Ok((auth, next)) => {
            let next = next.unwrap_or(auth.routes.pages.post_login.clone());
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            EmailLoginCallbackError::Store(err) => Err(err),
            EmailLoginCallbackError::EmailLoginError(EmailLoginError::Store(err)) => Err(err),
            _ => {
                let next = format!(
                    "{login_route}?error={}",
                    urlencoding::encode(&err.to_string())
                );
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

async fn post_signup_email<St>(
    auth: AxumUserp<St>,
    Form(EmailNextForm { email, next }): Form<EmailNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let signup_route = auth.routes.pages.signup.clone();

    match auth.email_signup_init(email.clone(), next).await {
        Ok(()) => {
            let next = format!(
                "{signup_route}?message=Signup email sent to {}!",
                urlencoding::encode(&email)
            );

            Ok(Redirect::to(&next).into_response())
        }
        Err(err) => match err {
            EmailSignupInitError::SendingEmail(SendEmailChallengeError::Store(err)) => Err(err),
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

async fn get_signup_email<St>(
    auth: AxumUserp<St>,
    Query(CodeQuery { code }): Query<CodeQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let signup_route = auth.routes.pages.signup.clone();

    match auth.email_signup_callback(code).await {
        Ok((auth, next)) => {
            let next = next.unwrap_or(auth.routes.pages.post_login.clone());
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            EmailSignupCallbackError::Store(err) => Err(err),
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

async fn get_user_email_verify<St>(
    auth: AxumUserp<St>,
    Query(CodeQuery { code }): Query<CodeQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.pages.login.clone();

    #[cfg(feature = "account")]
    let user_route = auth.routes.pages.user.clone();
    #[cfg(not(feature = "account"))]
    let user_route = auth.routes.pages.post_login.clone();

    match auth.email_verify_callback(code).await {
        Ok((address, next)) => {
            let next = match next {
                Some(next) => next,
                None => {
                    if auth.logged_in().await? {
                        format!(
                            "{user_route}?message={} verified!",
                            urlencoding::encode(&address)
                        )
                    } else {
                        format!(
                            "{login_route}?message={} verified!",
                            urlencoding::encode(&address)
                        )
                    }
                }
            };

            Ok(Redirect::to(&next))
        }
        Err(err) => match err {
            EmailVerifyCallbackError::Store(err) => Err(err),
            _ => {
                let next = format!(
                    "{login_route}?error={}",
                    urlencoding::encode(&err.to_string())
                );
                Ok(Redirect::to(&next))
            }
        },
    }
}

async fn post_user_email_verify<St>(
    auth: AxumUserp<St>,
    Form(EmailNextForm { email, next }): Form<EmailNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    if !auth.logged_in().await? {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    #[cfg(feature = "account")]
    let user_route = auth.routes.pages.user.clone();
    #[cfg(not(feature = "account"))]
    let user_route = auth.routes.pages.post_login.clone();

    match auth.email_verify_init(email.clone(), next).await {
        Ok(()) => {
            let next = format!(
                "{user_route}?message=Verification mail sent to {}",
                urlencoding::encode(&email)
            );

            Ok(Redirect::to(&next).into_response())
        }
        Err(err) => match err {
            SendEmailChallengeError::Store(err) => Err(err),
            _ => {
                let next = format!(
                    "{user_route}?error={}",
                    urlencoding::encode(&err.to_string())
                );
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

#[cfg(feature = "axum-router-password")]
async fn post_password_send_reset<St>(
    auth: AxumUserp<St>,
    Form(EmailNextForm { email, next }): Form<EmailNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let password_send_reset_route = auth.routes.pages.password_send_reset.clone();

    if let Err(err) = auth.email_reset_init(email.clone(), next).await {
        let next = format!(
            "{password_send_reset_route}?error={}&address={}",
            urlencoding::encode(&err.to_string()),
            email
        );

        Ok(Redirect::to(&next).into_response())
    } else {
        let next = format!("{password_send_reset_route}?sent=true&address={}", email);

        Ok(Redirect::to(&next).into_response())
    }
}

#[cfg(feature = "axum-router-password")]
pub async fn post_password_reset<St>(
    auth: AxumUserp<St>,
    Form(NewPasswordForm { new_password }): Form<NewPasswordForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    use crate::traits::{LoginSession, User};

    if let Some((user, session)) = auth.reset_user_session().await? {
        let new_password_hash = auth.pass.hasher.genereate_hash(new_password).await;
        auth.store
            .set_user_password_hash(user.get_id(), new_password_hash, session.get_id())
            .await?;

        let login_route = auth.routes.pages.login;

        Ok(Redirect::to(&format!("{login_route}?message=Password has been reset")).into_response())
    } else {
        Ok(StatusCode::UNAUTHORIZED.into_response())
    }
}

#[cfg(feature = "axum-router-password")]
async fn get_password_reset_callback<St>(
    auth: AxumUserp<St>,
    Query(query): Query<CodeQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    use crate::prelude::{EmailResetCallbackError, EmailResetError};

    let login_route = auth.routes.pages.login.clone();

    match auth.email_reset_callback(query.code).await {
        Ok(auth) => {
            let reset_password_page_route = auth.routes.pages.password_reset.clone();

            Ok((auth, Redirect::to(&reset_password_page_route)).into_response())
        }
        Err(err) => match err {
            EmailResetCallbackError::Store(err) => Err(err),
            EmailResetCallbackError::EmailResetError(EmailResetError::Store(err)) => Err(err),
            _ => Ok(Redirect::to(&format!(
                "{login_route}?err={}",
                urlencoding::encode(&err.to_string())
            ))
            .into_response()),
        },
    }
}
