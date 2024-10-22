#[cfg(feature = "account")]
mod account;
mod forms;
mod queries;
#[cfg(feature = "account")]
use account::*;
use axum::response::IntoResponse;

#[cfg(feature = "axum-pages")]
use crate::pages::*;
use crate::{config::UserpConfig, traits::UserpStore};
use axum::{
    extract::{FromRef, Query},
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
use super::AxumUserp;
#[cfg(all(feature = "axum-pages", feature = "email", feature = "password"))]
use crate::email::reset::{EmailResetCallbackError, EmailResetError};
#[cfg(feature = "email")]
use crate::email::{
    login::{EmailLoginCallbackError, EmailLoginError, EmailLoginInitError},
    signup::{EmailSignupCallbackError, EmailSignupInitError},
    verify::EmailVerifyCallbackError,
    SendEmailChallengeError,
};
#[cfg(feature = "password")]
use crate::password::{login::PasswordLoginError, signup::PasswordSignupError};

impl UserpConfig {
    pub fn router<St, S>(&self) -> Router<S>
    where
        UserpConfig: FromRef<S>,
        S: Send + Sync + Clone + 'static,
        St: UserpStore + FromRef<S> + Send + Sync + 'static,
        St::Error: IntoResponse,
    {
        let mut router = Router::new();

        #[cfg(feature = "axum-pages")]
        {
            router = router
                .route(self.routes.pages.login.as_str(), get(get_login::<St>))
                .route(self.routes.pages.signup.as_str(), get(get_signup::<St>));

            #[cfg(all(feature = "password", feature = "email"))]
            {
                router = router
                    .route(
                        self.routes.pages.password_send_reset.as_str(),
                        get(get_password_send_reset::<St>),
                    )
                    .route(
                        self.routes.actions.password_send_reset.as_str(),
                        post(post_password_send_reset::<St>),
                    )
                    .route(
                        self.routes.pages.password_reset.as_str(),
                        get(get_password_reset::<St>),
                    );

                #[cfg(feature = "account")]
                {
                    router = router.route(
                        self.routes.actions.password_reset.as_str(),
                        post(post_password_reset::<St>),
                    );
                }
            }

            #[cfg(feature = "account")]
            {
                router = router.route(self.routes.pages.user.as_str(), get(get_user::<St>));
            }
        }

        #[cfg(all(not(feature = "axum-pages"), feature = "password", feature = "email"))]
        {
            router = router.route(
                self.routes.actions.password_send_reset.as_str(),
                post(post_password_send_reset::<St>),
            );

            #[cfg(feature = "account")]
            {
                router = router.route(
                    self.routes.actions.password_reset.as_str(),
                    post(post_password_reset::<St>),
                );
            }
        }

        #[cfg(feature = "password")]
        {
            router = router
                .route(
                    self.routes.actions.login_password.as_str(),
                    post(post_login_password::<St>),
                )
                .route(
                    self.routes.actions.signup_password.as_str(),
                    post(post_signup_password::<St>),
                )
        }

        #[cfg(feature = "email")]
        {
            router = router
                .route(
                    self.routes.actions.login_email.as_str(),
                    post(post_login_email::<St>).get(get_login_email::<St>),
                )
                .route(
                    self.routes.actions.signup_email.as_str(),
                    post(post_signup_email::<St>).get(get_signup_email::<St>),
                )
                .route(
                    self.routes.actions.user_email_verify.as_str(),
                    get(get_user_email_verify::<St>).post(post_user_email_verify::<St>),
                );
        }

        router = router
            .route(
                self.routes.actions.logout.as_str(),
                get(get_user_logout::<St>),
            )
            .route(
                self.routes.actions.user_verify_session.as_str(),
                get(get_user_verify_session::<St>),
            );

        #[cfg(feature = "account")]
        {
            router = router
                .route(
                    self.routes.actions.user_delete.as_str(),
                    post(post_user_delete::<St>),
                )
                .route(
                    self.routes.actions.user_session_delete.as_str(),
                    post(post_user_session_delete::<St>),
                );

            #[cfg(feature = "password")]
            {
                router = router
                    .route(
                        self.routes.actions.user_password_set.as_str(),
                        post(post_user_password_set::<St>),
                    )
                    .route(
                        self.routes.actions.user_password_delete.as_str(),
                        post(post_user_password_delete::<St>),
                    );
            }

            #[cfg(feature = "oauth")]
            {
                router = router.route(
                    self.routes.actions.user_oauth_delete.as_str(),
                    post(post_user_oauth_delete::<St>),
                );
            }

            #[cfg(feature = "email")]
            {
                router = router
                    .route(
                        self.routes.actions.user_email_add.as_str(),
                        post(post_user_email_add::<St>),
                    )
                    .route(
                        self.routes.actions.user_email_delete.as_str(),
                        post(post_user_email_delete::<St>),
                    )
                    .route(
                        self.routes.actions.user_email_enable_login.as_str(),
                        post(post_user_email_enable_login::<St>),
                    )
                    .route(
                        self.routes.actions.user_email_disable_login.as_str(),
                        post(post_user_email_disable_login::<St>),
                    );
            }
        }

        #[cfg(feature = "oauth")]
        {
            router = router
                .route(
                    self.routes.actions.login_oauth.as_str(),
                    post(post_login_oauth::<St>),
                )
                .route(
                    self.routes.actions.signup_oauth.as_str(),
                    post(post_signup_oauth::<St>),
                )
                .route(
                    self.routes.actions.user_oauth_link.as_str(),
                    post(post_user_oauth_link::<St>),
                )
                .route(
                    self.routes.actions.user_oauth_refresh.as_str(),
                    post(post_user_oauth_refresh::<St>),
                );

            if self.routes.actions.login_oauth_provider == self.routes.actions.signup_oauth_provider
                || self.routes.actions.login_oauth_provider
                    == self.routes.actions.user_oauth_link_provider
                || self.routes.actions.login_oauth_provider
                    == self.routes.actions.user_oauth_refresh_provider
            {
                router = router
                    .route(
                        self.routes.actions.login_oauth_provider.as_str(),
                        get(get_generic_oauth::<St>),
                    )
                    .route(
                        &(self.routes.actions.login_oauth_provider.to_owned() + "/"),
                        get(get_generic_oauth::<St>),
                    );
            } else {
                router = router
                    .route(
                        self.routes.actions.login_oauth_provider.as_str(),
                        get(get_login_oauth::<St>),
                    )
                    .route(
                        &(self.routes.actions.login_oauth_provider.to_owned() + "/"),
                        get(get_login_oauth::<St>),
                    );
            }

            if self.routes.actions.signup_oauth_provider == self.routes.actions.login_oauth_provider
                || self.routes.actions.signup_oauth_provider
                    == self.routes.actions.user_oauth_link_provider
                || self.routes.actions.signup_oauth_provider
                    == self.routes.actions.user_oauth_refresh_provider
            {
                router = router
                    .route(
                        self.routes.actions.signup_oauth_provider.as_str(),
                        get(get_generic_oauth::<St>),
                    )
                    .route(
                        &(self.routes.actions.signup_oauth_provider.to_owned() + "/"),
                        get(get_generic_oauth::<St>),
                    );
            } else {
                router = router
                    .route(
                        self.routes.actions.signup_oauth_provider.as_str(),
                        get(get_signup_oauth::<St>),
                    )
                    .route(
                        &(self.routes.actions.signup_oauth_provider.to_owned() + "/"),
                        get(get_signup_oauth::<St>),
                    );
            }

            if self.routes.actions.user_oauth_link_provider
                == self.routes.actions.signup_oauth_provider
                || self.routes.actions.user_oauth_link_provider
                    == self.routes.actions.login_oauth_provider
                || self.routes.actions.user_oauth_link_provider
                    == self.routes.actions.user_oauth_refresh_provider
            {
                router = router
                    .route(
                        self.routes.actions.user_oauth_link_provider.as_str(),
                        get(get_generic_oauth::<St>),
                    )
                    .route(
                        &(self.routes.actions.user_oauth_link_provider.to_owned() + "/"),
                        get(get_generic_oauth::<St>),
                    );
            } else {
                router = router
                    .route(
                        self.routes.actions.user_oauth_link_provider.as_str(),
                        get(get_user_oauth_link::<St>),
                    )
                    .route(
                        &(self.routes.actions.user_oauth_link_provider.to_owned() + "/"),
                        get(get_user_oauth_link::<St>),
                    );
            }

            if self.routes.actions.user_oauth_refresh_provider
                == self.routes.actions.signup_oauth_provider
                || self.routes.actions.user_oauth_refresh_provider
                    == self.routes.actions.user_oauth_link_provider
                || self.routes.actions.user_oauth_refresh_provider
                    == self.routes.actions.login_oauth_provider
            {
                router = router
                    .route(
                        self.routes.actions.user_oauth_refresh_provider.as_str(),
                        get(get_generic_oauth::<St>),
                    )
                    .route(
                        &(self.routes.actions.user_oauth_refresh_provider.to_owned() + "/"),
                        get(get_generic_oauth::<St>),
                    );
            } else {
                router = router
                    .route(
                        self.routes.actions.user_oauth_refresh_provider.as_str(),
                        get(get_user_oauth_refresh::<St>),
                    )
                    .route(
                        &(self.routes.actions.user_oauth_refresh_provider.to_owned() + "/"),
                        get(get_user_oauth_refresh::<St>),
                    );
            }
        }

        router
    }
}

#[cfg(feature = "axum-pages")]
async fn get_login<St>(
    auth: AxumUserp<St>,
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
        Redirect::to(&auth.routes.redirects.post_login).into_response()
    } else {
        LoginTemplate::into_response_with(
            &auth,
            next.as_deref(),
            message.as_deref(),
            error.as_deref(),
        )
        .into_response()
    })
}

#[cfg(feature = "password")]
async fn post_login_password<St>(
    auth: AxumUserp<St>,
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
    let login_route = auth.routes.pages.login.clone();

    match auth.password_login(&email, &password).await {
        Ok(auth) => {
            let next = next.unwrap_or(auth.routes.redirects.post_login.clone());
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

#[cfg(feature = "email")]
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
            let next = next.unwrap_or(auth.routes.redirects.post_login.clone());
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

#[cfg(feature = "axum-pages")]
async fn get_signup<St>(
    auth: AxumUserp<St>,
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
    auth: AxumUserp<St>,
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
    let signup_route = auth.routes.pages.signup.clone();

    match auth.password_signup(&email, &password).await {
        Ok(auth) => {
            let next = next.unwrap_or(auth.routes.redirects.post_login.clone());
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

#[cfg(feature = "email")]
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
            let next = next.unwrap_or(auth.routes.redirects.post_login.clone());
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

async fn get_user_logout<St>(auth: AxumUserp<St>) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let post_logout = auth.routes.redirects.post_logout.clone();

    Ok((auth.log_out().await?, Redirect::to(&post_logout)))
}

async fn get_user_verify_session<St>(auth: AxumUserp<St>) -> Result<impl IntoResponse, St::Error>
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

#[cfg(feature = "email")]
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
    let user_route = auth.routes.redirects.post_login.clone();

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
    let user_route = auth.routes.redirects.post_login.clone();

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

#[cfg(all(feature = "axum-pages", feature = "email", feature = "password"))]
async fn get_password_send_reset<St>(
    auth: AxumUserp<St>,
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
        send_reset_password_action_route: &auth.routes.actions.password_send_reset,
    }
    .into_response())
}

#[cfg(all(feature = "email", feature = "password"))]
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

#[cfg(all(feature = "axum-pages", feature = "email", feature = "password"))]
async fn get_password_reset<St>(
    auth: AxumUserp<St>,
    Query(query): Query<CodeQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.pages.login.clone();

    match auth.email_reset_callback(query.code).await {
        Ok(auth) => {
            let reset_password_action_route = auth.routes.actions.password_reset.clone();

            Ok((
                auth,
                ResetPasswordTemplate {
                    reset_password_action_route: &reset_password_action_route,
                },
            )
                .into_response())
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
