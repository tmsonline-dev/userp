mod forms;
mod queries;

#[cfg(feature = "extended-store")]
mod extended;
#[cfg(feature = "extended-store")]
use extended::*;

#[cfg(feature = "axum-askama")]
use askama_axum::IntoResponse;
#[cfg(not(feature = "axum-askama"))]
use axum::response::IntoResponse;

#[cfg(feature = "axum-askama")]
use crate::templates::*;
use axum::{
    extract::{FromRef, Path, Query},
    http::StatusCode,
    response::Redirect,
    routing::{get, post},
    Form, Router,
};
use forms::*;
use queries::*;
use urlencoding::encode;

#[cfg(feature = "oauth")]
use oauth_handlers::*;
#[cfg(feature = "oauth")]
mod oauth_handlers;

#[cfg(feature = "email")]
use crate::email::{
    EmailLoginCallbackError, EmailLoginError, EmailLoginInitError, EmailSignupCallbackError,
    EmailSignupInitError, EmailVerifyCallbackError, SendEmailChallengeError,
};

#[cfg(feature = "password")]
use crate::{PasswordLoginError, PasswordSignupError};

use crate::{Userp, UserpConfig, UserpStore};

#[cfg(all(feature = "axum-askama", feature = "email", feature = "password"))]
use crate::{email::EmailResetCallbackError, EmailResetError};

impl UserpConfig {
    pub fn handlers<St, S>(&self) -> Router<S>
    where
        UserpConfig: FromRef<S>,
        S: Send + Sync + Clone + 'static,
        St: UserpStore + FromRef<S> + Send + Sync + 'static,
        St::Error: IntoResponse,
    {
        let mut router = Router::new();

        #[cfg(feature = "axum-askama")]
        {
            router = router
                .route(self.routes.login.as_str(), get(get_login::<St>))
                .route(self.routes.signup.as_str(), get(get_signup::<St>));

            #[cfg(all(feature = "password", feature = "email"))]
            {
                router = router.route(
                    self.routes.password_send_reset.as_str(),
                    get(get_password_send_reset::<St>).post(post_password_send_reset::<St>),
                );
            }

            #[cfg(feature = "extended-store")]
            {
                router = router
                    .route(self.routes.user.as_str(), get(get_user::<St>))
                    .route(
                        self.routes.password_reset.as_str(),
                        get(get_password_reset::<St>).post(post_password_reset::<St>),
                    );
            }
        }

        #[cfg(all(not(feature = "axum-askama"), feature = "password", feature = "email"))]
        {
            router = router.route(
                self.routes.password_send_reset.as_str(),
                post(post_password_send_reset::<St>),
            );

            #[cfg(feature = "extended-store")]
            {
                router = router.route(
                    self.routes.password_reset.as_str(),
                    post(post_password_reset::<St>),
                );
            }
        }

        #[cfg(feature = "password")]
        {
            router = router
                .route(
                    self.routes.login_password.as_str(),
                    post(post_login_password::<St>),
                )
                .route(
                    self.routes.signup_password.as_str(),
                    post(post_signup_password::<St>),
                )
        }

        #[cfg(feature = "email")]
        {
            router = router
                .route(
                    self.routes.login_email.as_str(),
                    post(post_login_email::<St>).get(get_login_email::<St>),
                )
                .route(
                    self.routes.signup_email.as_str(),
                    post(post_signup_email::<St>).get(get_signup_email::<St>),
                )
                .route(
                    self.routes.user_email_verify.as_str(),
                    get(get_user_email_verify::<St>).post(post_user_email_verify::<St>),
                );
        }

        router = router
            .route(self.routes.logout.as_str(), get(get_user_logout::<St>))
            .route(
                self.routes.user_verify_session.as_str(),
                get(get_user_verify_session::<St>),
            )
            .route(
                self.routes.user_session_delete.as_str(),
                post(post_user_session_delete::<St>),
            );

        #[cfg(feature = "extended-store")]
        {
            router = router
                .route(
                    self.routes.user_delete.as_str(),
                    post(post_user_delete::<St>),
                )
                .route(
                    self.routes.user_password_set.as_str(),
                    post(post_user_password_set::<St>),
                )
                .route(
                    self.routes.user_password_delete.as_str(),
                    post(post_user_password_delete::<St>),
                )
                .route(
                    self.routes.user_oauth_delete.as_str(),
                    post(post_user_oauth_delete::<St>),
                )
                .route(
                    self.routes.user_email_add.as_str(),
                    post(post_user_email_add::<St>),
                )
                .route(
                    self.routes.user_email_delete.as_str(),
                    post(post_user_email_delete::<St>),
                )
                .route(
                    self.routes.user_email_enable_login.as_str(),
                    post(post_user_email_enable_login::<St>),
                )
                .route(
                    self.routes.user_email_disable_login.as_str(),
                    post(post_user_email_disable_login::<St>),
                );
        }

        #[cfg(feature = "oauth")]
        {
            router = router
                .route(
                    self.routes.login_oauth.as_str(),
                    post(post_login_oauth::<St>),
                )
                .route(
                    self.routes.signup_oauth.as_str(),
                    post(post_signup_oauth::<St>),
                )
                .route(
                    self.routes.user_oauth_link.as_str(),
                    post(post_user_oauth_link::<St>),
                )
                .route(
                    self.routes.user_oauth_refresh.as_str(),
                    post(post_user_oauth_refresh::<St>),
                );

            if self.routes.login_oauth_provider == self.routes.signup_oauth_provider
                || self.routes.login_oauth_provider == self.routes.user_oauth_link_provider
                || self.routes.login_oauth_provider == self.routes.user_oauth_refresh_provider
            {
                router = router
                    .route(
                        self.routes.login_oauth_provider.as_str(),
                        get(get_generic_oauth::<St>),
                    )
                    .route(
                        &(self.routes.login_oauth_provider.to_owned() + "/"),
                        get(get_generic_oauth::<St>),
                    );
            } else {
                router = router
                    .route(
                        self.routes.login_oauth_provider.as_str(),
                        get(get_login_oauth::<St>),
                    )
                    .route(
                        &(self.routes.login_oauth_provider.to_owned() + "/"),
                        get(get_login_oauth::<St>),
                    );
            }

            if self.routes.signup_oauth_provider == self.routes.login_oauth_provider
                || self.routes.signup_oauth_provider == self.routes.user_oauth_link_provider
                || self.routes.signup_oauth_provider == self.routes.user_oauth_refresh_provider
            {
                router = router
                    .route(
                        self.routes.signup_oauth_provider.as_str(),
                        get(get_generic_oauth::<St>),
                    )
                    .route(
                        &(self.routes.signup_oauth_provider.to_owned() + "/"),
                        get(get_generic_oauth::<St>),
                    );
            } else {
                router = router
                    .route(
                        self.routes.signup_oauth_provider.as_str(),
                        get(get_signup_oauth::<St>),
                    )
                    .route(
                        &(self.routes.signup_oauth_provider.to_owned() + "/"),
                        get(get_signup_oauth::<St>),
                    );
            }

            if self.routes.user_oauth_link_provider == self.routes.signup_oauth_provider
                || self.routes.user_oauth_link_provider == self.routes.login_oauth_provider
                || self.routes.user_oauth_link_provider == self.routes.user_oauth_refresh_provider
            {
                router = router
                    .route(
                        self.routes.user_oauth_link_provider.as_str(),
                        get(get_generic_oauth::<St>),
                    )
                    .route(
                        &(self.routes.user_oauth_link_provider.to_owned() + "/"),
                        get(get_generic_oauth::<St>),
                    );
            } else {
                router = router
                    .route(
                        self.routes.user_oauth_link_provider.as_str(),
                        get(get_user_oauth_link::<St>),
                    )
                    .route(
                        &(self.routes.user_oauth_link_provider.to_owned() + "/"),
                        get(get_user_oauth_link::<St>),
                    );
            }

            if self.routes.user_oauth_refresh_provider == self.routes.signup_oauth_provider
                || self.routes.user_oauth_refresh_provider == self.routes.user_oauth_link_provider
                || self.routes.user_oauth_refresh_provider == self.routes.login_oauth_provider
            {
                router = router
                    .route(
                        self.routes.user_oauth_refresh_provider.as_str(),
                        get(get_generic_oauth::<St>),
                    )
                    .route(
                        &(self.routes.user_oauth_refresh_provider.to_owned() + "/"),
                        get(get_generic_oauth::<St>),
                    );
            } else {
                router = router
                    .route(
                        self.routes.user_oauth_refresh_provider.as_str(),
                        get(get_user_oauth_refresh::<St>),
                    )
                    .route(
                        &(self.routes.user_oauth_refresh_provider.to_owned() + "/"),
                        get(get_user_oauth_refresh::<St>),
                    );
            }
        }

        router
    }
}

#[cfg(feature = "axum-askama")]
async fn get_login<St>(
    auth: Userp<St>,
    Query(NextMessageErrorQuery {
        next,
        message,
        error,
        ..
    }): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    Ok(if auth.logged_in().await? {
        Redirect::to(&auth.routes.post_login).into_response()
    } else {
        LoginTemplate::response_from(&auth, next.as_deref(), message.as_deref(), error.as_deref())
            .into_response()
    })
}

#[cfg(feature = "password")]
async fn post_login_password<St>(
    auth: Userp<St>,
    Form(EmailPasswordNextForm {
        email,
        password,
        next,
    }): Form<EmailPasswordNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.login.clone();

    match auth.password_login(&email, &password).await {
        Ok(auth) => {
            let next = next.unwrap_or(auth.routes.post_login.clone());
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

#[cfg(feature = "email")]
async fn post_login_email<St>(
    auth: Userp<St>,
    Form(EmailNextForm { email, next }): Form<EmailNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.login.clone();

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

#[cfg(feature = "email")]
async fn get_login_email<St>(
    auth: Userp<St>,
    Query(CodeQuery { code }): Query<CodeQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.login.clone();

    match auth.email_login_callback(code).await {
        Ok((auth, next)) => {
            let next = next.unwrap_or(auth.routes.post_login.clone());
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

#[cfg(feature = "axum-askama")]
async fn get_signup<St>(
    auth: Userp<St>,
    Query(NextMessageErrorQuery {
        error,
        message,
        next,
        ..
    }): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    Ok(
        SignupTemplate::response_from(&auth, next.as_deref(), message.as_deref(), error.as_deref())
            .into_response(),
    )
}

#[cfg(feature = "password")]
async fn post_signup_password<St>(
    auth: Userp<St>,
    Form(EmailPasswordNextForm {
        email,
        password,
        next,
    }): Form<EmailPasswordNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let signup_route = auth.routes.signup.clone();

    match auth.password_signup(&email, &password).await {
        Ok(auth) => {
            let next = next.unwrap_or(auth.routes.post_login.clone());
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

#[cfg(feature = "email")]
async fn post_signup_email<St>(
    auth: Userp<St>,
    Form(EmailNextForm { email, next }): Form<EmailNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let signup_route = auth.routes.signup.clone();

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

#[cfg(feature = "email")]
async fn get_signup_email<St>(
    auth: Userp<St>,
    Query(CodeQuery { code }): Query<CodeQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let signup_route = auth.routes.signup.clone();

    match auth.email_signup_callback(code).await {
        Ok((auth, next)) => {
            let next = next.unwrap_or(auth.routes.post_login.clone());
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

async fn get_user_logout<St>(auth: Userp<St>) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let post_logout = auth.routes.post_logout.clone();

    Ok((auth.log_out().await?, Redirect::to(&post_logout)))
}

async fn get_user_verify_session<St>(auth: Userp<St>) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    Ok(if auth.logged_in().await? {
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    })
}

async fn post_user_session_delete<St>(
    auth: Userp<St>,
    Form(IdForm { id }): Form<IdForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    if !auth.logged_in().await? {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store.delete_session(id).await?;

    let user_route = auth.routes.user;

    Ok(Redirect::to(&format!("{user_route}?message=Session deleted")).into_response())
}

#[cfg(feature = "email")]
async fn get_user_email_verify<St>(
    auth: Userp<St>,
    Query(CodeQuery { code }): Query<CodeQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.login.clone();
    let user_route = auth.routes.user.clone();

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

#[cfg(feature = "email")]
async fn post_user_email_verify<St>(
    auth: Userp<St>,
    Form(EmailNextForm { email, next }): Form<EmailNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    if !auth.logged_in().await? {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    let user_route = auth.routes.user.clone();

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

#[cfg(all(feature = "axum-askama", feature = "email", feature = "password"))]
async fn get_password_send_reset<St>(
    auth: Userp<St>,
    Query(query): Query<AddressMessageSentErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    Ok(SendResetPasswordTemplate {
        sent: query.sent.is_some_and(|sent| sent),
        address: query.address.as_deref(),
        error: query.error.as_deref(),
        message: query.message.as_deref(),
        routes: auth.routes.as_ref().into(),
    }
    .into_response())
}

#[cfg(all(feature = "email", feature = "password"))]
async fn post_password_send_reset<St>(
    auth: Userp<St>,
    Form(EmailNextForm { email, next }): Form<EmailNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let password_send_reset_route = auth.routes.password_send_reset.clone();

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

#[cfg(all(feature = "axum-askama", feature = "email", feature = "password"))]
async fn get_password_reset<St>(
    auth: Userp<St>,
    Query(query): Query<CodeQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.login.clone();

    match auth.email_reset_callback(query.code).await {
        Ok(auth) => {
            let routes = auth.routes.clone();
            let routes = routes.as_ref().into();

            Ok((auth, ResetPasswordTemplate { routes }).into_response())
        }
        Err(err) => match err {
            EmailResetCallbackError::Store(err) => Err(err),
            EmailResetCallbackError::EmailResetError(EmailResetError::Store(err)) => Err(err),
            _ => Ok(
                Redirect::to(&format!("{login_route}?err={}", encode(&err.to_string())))
                    .into_response(),
            ),
        },
    }
}
