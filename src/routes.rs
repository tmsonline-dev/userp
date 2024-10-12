mod forms;
mod queries;
#[cfg(feature = "templates")]
mod templates;

#[cfg(feature = "extended")]
mod extended;
#[cfg(feature = "extended")]
use extended::*;

#[cfg(feature = "templates")]
use askama_axum::IntoResponse;
#[cfg(not(feature = "templates"))]
use axum::response::IntoResponse;

use axum::{
    extract::{FromRef, Path, Query},
    response::Redirect,
    routing::{get, post},
    Form, Router,
};
use forms::*;
use queries::*;
use reqwest::StatusCode;
#[cfg(feature = "templates")]
use templates::*;
use urlencoding::encode;

use crate::{
    email::{
        EmailLoginCallbackError, EmailLoginInitError, EmailSignupCallbackError,
        EmailSignupInitError, EmailVerifyCallbackError, SendEmailChallengeError,
    },
    oauth::{
        OAuthGenericCallbackError, OAuthLinkCallbackError, OAuthLinkInitError,
        OAuthLoginCallbackError, OAuthRefreshCallbackError, OAuthSignupCallbackError,
    },
    AxumUser, AxumUserConfig, AxumUserStore, EmailLoginError, PasswordLoginError,
    PasswordSignupError, RefreshInitResult,
};

#[cfg(feature = "templates")]
use crate::{email::EmailResetCallbackError, EmailResetError};

#[cfg(feature = "templates")]
async fn get_login<St>(
    auth: AxumUser<St>,
    Query(NextMessageErrorQuery {
        next,
        message,
        error,
        ..
    }): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    Ok(if auth.logged_in().await? {
        Redirect::to("/user").into_response()
    } else {
        LoginTemplate {
            next,
            message,
            error,
            oauth_providers: auth
                .oauth_login_providers()
                .into_iter()
                .map(|p| p.into())
                .collect(),
        }
        .into_response()
    })
}

async fn post_login_password<St>(
    auth: AxumUser<St>,
    Form(EmailPasswordNextForm {
        email,
        password,
        next,
    }): Form<EmailPasswordNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    match auth.password_login(email, password).await {
        Ok(auth) => {
            let next = next.unwrap_or("/user".into());
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            PasswordLoginError::StoreError(err) => Err(err),
            PasswordLoginError::NotAllowed
            | PasswordLoginError::NoUser
            | PasswordLoginError::WrongPassword => {
                let next = format!("/login?error={}", urlencoding::encode(&err.to_string()));
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

async fn post_login_email<St>(
    auth: AxumUser<St>,
    Form(EmailNextForm { email, next }): Form<EmailNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    match auth.email_login_init(email.clone(), next).await {
        Ok(()) => {
            let next = format!(
                "/login?message=Login link sent to {}!",
                urlencoding::encode(&email)
            );

            Ok(Redirect::to(&next).into_response())
        }
        Err(err) => match err {
            EmailLoginInitError::SendingEmail(SendEmailChallengeError::Store(err)) => Err(err),
            _ => {
                let next = format!("/login?error={}", urlencoding::encode(&err.to_string()));
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

async fn get_login_email<St>(
    auth: AxumUser<St>,
    Query(CodeQuery { code }): Query<CodeQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    match auth.email_login_callback(code).await {
        Ok((auth, next)) => {
            let next = next.unwrap_or("/user".into());
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            EmailLoginCallbackError::Store(err) => Err(err),
            EmailLoginCallbackError::EmailLoginError(EmailLoginError::Store(err)) => Err(err),
            _ => {
                let next = format!("/login?error={}", urlencoding::encode(&err.to_string()));
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

async fn post_login_oauth<St>(
    auth: AxumUser<St>,
    Form(ProviderNextForm { provider, next }): Form<ProviderNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    match auth.oauth_login_init(provider, next).await {
        Ok((auth, redirect_url)) => Ok((auth, Redirect::to(redirect_url.as_str())).into_response()),
        Err(err) => {
            let next = format!("/login?error={}", urlencoding::encode(&err.to_string()));
            Ok(Redirect::to(&next).into_response())
        }
    }
}

async fn get_login_oauth<St>(
    auth: AxumUser<St>,
    Path(ProviderPath { provider }): Path<ProviderPath>,
    Query(CodeStateQuery { code, state }): Query<CodeStateQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    match auth.oauth_login_callback(provider, code, state).await {
        Ok((auth, next)) => {
            let next = next.unwrap_or("/user".into());
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            OAuthLoginCallbackError::Store(err) => Err(err),
            _ => {
                let next = format!("/login?error={}", urlencoding::encode(&err.to_string()));
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

async fn get_generic_oauth<St>(
    auth: AxumUser<St>,
    Path(ProviderPath { provider }): Path<ProviderPath>,
    Query(CodeStateQuery { code, state }): Query<CodeStateQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    match auth.oauth_generic_callback(provider, code, state).await {
        Ok((auth, next)) => {
            let next = next.unwrap_or("/user".into());
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            OAuthGenericCallbackError::Signup(OAuthSignupCallbackError::Store(err))
            | OAuthGenericCallbackError::Login(OAuthLoginCallbackError::Store(err))
            | OAuthGenericCallbackError::Refresh(OAuthRefreshCallbackError::Store(err))
            | OAuthGenericCallbackError::Link(OAuthLinkCallbackError::Store(err)) => Err(err),
            _ => {
                let next = format!("/login?error={}", urlencoding::encode(&err.to_string()));
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

#[cfg(feature = "templates")]
async fn get_signup<St>(
    auth: AxumUser<St>,
    Query(NextMessageErrorQuery {
        error,
        message,
        next,
        ..
    }): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    Ok(SignupTemplate {
        error,
        message,
        next,
        oauth_providers: auth
            .oauth_signup_providers()
            .into_iter()
            .map(|p| p.into())
            .collect(),
    }
    .into_response())
}

async fn post_signup_password<St>(
    auth: AxumUser<St>,
    Form(EmailPasswordNextForm {
        email,
        password,
        next,
    }): Form<EmailPasswordNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    if password.len() <= 3 {
        return Ok(
            Redirect::to("/signup?error=Password must include more than 3 letters").into_response(),
        );
    }

    match auth.password_signup(email, password).await {
        Ok(auth) => {
            let next = next.unwrap_or("/user".into());
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            PasswordSignupError::StoreError(err) => Err(err),
            _ => {
                let next = format!("/signup?error={}", urlencoding::encode(&err.to_string()));
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

async fn post_signup_email<St>(
    auth: AxumUser<St>,
    Form(EmailNextForm { email, next }): Form<EmailNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    match auth.email_signup_init(email.clone(), next).await {
        Ok(()) => {
            let next = format!(
                "/signup?message=Signup email sent to {}!",
                urlencoding::encode(&email)
            );

            Ok(Redirect::to(&next).into_response())
        }
        Err(err) => match err {
            EmailSignupInitError::SendingEmail(SendEmailChallengeError::Store(err)) => Err(err),
            _ => {
                let next = format!("/signup?error={}", urlencoding::encode(&err.to_string()));
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

async fn get_signup_email<St>(
    auth: AxumUser<St>,
    Query(CodeQuery { code }): Query<CodeQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    match auth.email_signup_callback(code).await {
        Ok((auth, next)) => {
            let next = next.unwrap_or("/user".into());
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            EmailSignupCallbackError::Store(err) => Err(err),
            _ => {
                let next = format!("/signup?error={}", urlencoding::encode(&err.to_string()));
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

async fn post_signup_oauth<St>(
    auth: AxumUser<St>,
    Form(ProviderNextForm { provider, next }): Form<ProviderNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    match auth.oauth_signup_init(provider, next).await {
        Ok((auth, redirect_url)) => Ok((auth, Redirect::to(redirect_url.as_str())).into_response()),
        Err(err) => {
            let next = format!("/signup?error={}", urlencoding::encode(&err.to_string()));
            Ok(Redirect::to(&next).into_response())
        }
    }
}

async fn get_signup_oauth<St>(
    auth: AxumUser<St>,
    Path(ProviderPath { provider }): Path<ProviderPath>,
    Query(CodeStateQuery { code, state }): Query<CodeStateQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    match auth.oauth_signup_callback(provider, code, state).await {
        Ok((auth, next)) => {
            let next = next.unwrap_or("/user".into());
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            OAuthSignupCallbackError::Store(err) => Err(err),
            _ => {
                let next = format!("/signup?error={}", urlencoding::encode(&err.to_string()));
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

async fn get_user_logout<St>(auth: AxumUser<St>) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    let auth = auth.log_out().await?;

    Ok((auth, Redirect::to("/")))
}

async fn get_user_verify_session<St>(auth: AxumUser<St>) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    Ok(if auth.logged_in().await? {
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    })
}

async fn post_user_oauth_link<St>(
    auth: AxumUser<St>,
    Form(ProviderNextForm { provider, next }): Form<ProviderNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    if !auth.logged_in().await? {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }

    match auth.oauth_link_init(provider, next).await {
        Ok((auth, redirect_url)) => Ok((auth, Redirect::to(redirect_url.as_str())).into_response()),
        Err(err) => match err {
            OAuthLinkInitError::Store(err) => Err(err),
            _ => {
                let next = format!("/user?error={}", urlencoding::encode(&err.to_string()));
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

async fn get_user_oauth_link<St>(
    auth: AxumUser<St>,
    Path(ProviderPath { provider }): Path<ProviderPath>,
    Query(CodeStateQuery { code, state }): Query<CodeStateQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    match auth.oauth_link_callback(provider, code, state).await {
        Ok(next) => {
            let next = next.unwrap_or("/user".into());
            Ok((auth, Redirect::to(&next)).into_response())
        }
        Err(err) => match err {
            OAuthLinkCallbackError::Store(err) => Err(err),
            _ => {
                let next = format!("/signup?error={}", urlencoding::encode(&err.to_string()));
                Ok((auth, Redirect::to(&next)).into_response())
            }
        },
    }
}

async fn post_user_session_delete<St>(
    auth: AxumUser<St>,
    Form(IdForm { id }): Form<IdForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    if !auth.logged_in().await? {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store.delete_session(id).await?;

    Ok(Redirect::to("/user?message=Session deleted").into_response())
}

async fn post_user_oauth_refresh<St>(
    auth: AxumUser<St>,
    Form(IdForm { id: token_id }): Form<IdForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    if !auth.logged_in().await? {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    let token = match auth.store.oauth_get_token(token_id).await {
        Ok(Some(token)) => token,
        Ok(None) => {
            return Ok(StatusCode::NOT_FOUND.into_response());
        }
        Err(err) => {
            eprintln!("{err:#?}");
            return Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    };

    Ok(
        match auth
            .oauth_refresh_init(token, Some("/user?message=Token refreshed".to_string()))
            .await
        {
            Ok((auth, result)) => match result {
                RefreshInitResult::Ok => {
                    (auth, Redirect::to("/user?message=Token refreshed")).into_response()
                }
                RefreshInitResult::Redirect(redirect_url) => {
                    (auth, Redirect::to(redirect_url.as_str())).into_response()
                }
            },
            Err(err) => {
                let next = format!("/user?error={}", urlencoding::encode(&err.to_string()));
                Redirect::to(&next).into_response()
            }
        },
    )
}

async fn get_user_oauth_refresh<St>(
    auth: AxumUser<St>,
    Path(ProviderPath { provider }): Path<ProviderPath>,
    Query(CodeStateQuery { code, state }): Query<CodeStateQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    match auth
        .oauth_refresh_callback(provider.clone(), code, state)
        .await
    {
        Ok(next) => {
            let next = next.unwrap_or(format!("/user?message={} token refreshed!", provider));
            Ok(Redirect::to(&next).into_response())
        }
        Err(err) => match err {
            OAuthRefreshCallbackError::Store(err) => Err(err),
            _ => {
                let next = format!("/user?error={}", urlencoding::encode(&err.to_string()));
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

async fn get_user_email_verify<St>(
    auth: AxumUser<St>,
    Query(CodeQuery { code }): Query<CodeQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    match auth.email_verify_callback(code).await {
        Ok((address, next)) => {
            let next = match next {
                Some(next) => next,
                None => {
                    if auth.logged_in().await? {
                        format!("/user?message={} verified!", urlencoding::encode(&address))
                    } else {
                        format!("/login?message={} verified!", urlencoding::encode(&address))
                    }
                }
            };

            Ok(Redirect::to(&next))
        }
        Err(err) => match err {
            EmailVerifyCallbackError::Store(err) => Err(err),
            _ => {
                let next = format!("/login?error={}", urlencoding::encode(&err.to_string()));
                Ok(Redirect::to(&next))
            }
        },
    }
}

async fn post_user_email_verify<St>(
    auth: AxumUser<St>,
    Form(EmailNextForm { email, next }): Form<EmailNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    if !auth.logged_in().await? {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    match auth.email_verify_init(email.clone(), next).await {
        Ok(()) => {
            let next = format!(
                "/user?message=Verification mail sent to {}",
                urlencoding::encode(&email)
            );

            Ok(Redirect::to(&next).into_response())
        }
        Err(err) => match err {
            SendEmailChallengeError::Store(err) => Err(err),
            _ => {
                let next = format!("/user?error={}", urlencoding::encode(&err.to_string()));
                Ok(Redirect::to(&next).into_response())
            }
        },
    }
}

#[cfg(feature = "templates")]
async fn get_password_send_reset<St>(
    Query(query): Query<AddressMessageSentErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    Ok(SendResetPasswordTemplate {
        sent: query.sent.is_some_and(|sent| sent),
        address: query.address,
        error: query.error,
        message: query.message,
    }
    .into_response())
}

async fn post_password_send_reset<St>(
    auth: AxumUser<St>,
    Form(EmailNextForm { email, next }): Form<EmailNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    if let Err(err) = auth.email_reset_init(email.clone(), next).await {
        let next = format!(
            "/password/send-reset?error={}&address={}",
            urlencoding::encode(&err.to_string()),
            email
        );

        Ok(Redirect::to(&next).into_response())
    } else {
        let next = format!("/password/send-reset?sent=true&address={}", email);

        Ok(Redirect::to(&next).into_response())
    }
}

#[cfg(feature = "templates")]
async fn get_password_reset<St>(
    auth: AxumUser<St>,
    Query(query): Query<CodeQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    match auth.email_reset_callback(query.code).await {
        Ok(auth) => Ok((auth, ResetPasswordTemplate).into_response()),
        Err(err) => match err {
            EmailResetCallbackError::Store(err) => Err(err),
            EmailResetCallbackError::EmailResetError(EmailResetError::Store(err)) => Err(err),
            _ => Ok(
                Redirect::to(&format!("/login?err={}", encode(&err.to_string()))).into_response(),
            ),
        },
    }
}

pub struct Routes {
    login: &'static str,
    login_password: &'static str,
    login_email: &'static str,
    login_oauth: &'static str,
    login_oauth_provider: &'static str,
    signup: &'static str,
    signup_password: &'static str,
    signup_email: &'static str,
    signup_oauth: &'static str,
    signup_oauth_provider: &'static str,
    user: &'static str,
    user_delete: &'static str,
    logout: &'static str,
    user_verify_session: &'static str,
    user_password_set: &'static str,
    user_password_delete: &'static str,
    user_oauth_link: &'static str,
    user_oauth_link_provider: &'static str,
    user_session_delete: &'static str,
    user_oauth_refresh: &'static str,
    user_oauth_refresh_provider: &'static str,
    user_oauth_delete: &'static str,
    user_email_verify: &'static str,
    user_email_add: &'static str,
    user_email_delete: &'static str,
    user_email_enable_login: &'static str,
    user_email_disable_login: &'static str,
    password_send_reset: &'static str,
    password_reset: &'static str,
}

impl Default for Routes {
    fn default() -> Self {
        Routes {
            login: "/login",
            logout: "/logout",
            login_password: "/login/password",
            login_email: "/login/email",
            login_oauth: "/login/oauth",
            login_oauth_provider: "/login/oauth/:provider",
            signup: "/signup",
            signup_password: "/signup/password",
            signup_email: "/signup/email",
            signup_oauth: "/signup/oauth",
            signup_oauth_provider: "/signup/oauth/:provider",
            user: "/user",
            user_delete: "/user/delete",
            user_verify_session: "/user/verify-session",
            user_password_set: "/user/password/set",
            user_password_delete: "/user/password/delete",
            user_oauth_link: "/user/oauth/link",
            user_oauth_link_provider: "/user/oauth/link/:provider",
            user_session_delete: "/user/session/delete",
            user_oauth_refresh: "/user/oauth/refresh",
            user_oauth_refresh_provider: "/user/oauth/refresh/:provider",
            user_oauth_delete: "/user/oauth/delete",
            user_email_verify: "/user/email/verify",
            user_email_add: "/user/email/add",
            user_email_delete: "/user/email/delete",
            user_email_enable_login: "/user/email/enable_login",
            user_email_disable_login: "/user/email/disable_login",
            password_send_reset: "/password/send-reset",
            password_reset: "/password/reset",
        }
    }
}

impl AxumUserConfig {
    pub fn routes<St, S>(&self, routes: Routes) -> Router<S>
    where
        AxumUserConfig: FromRef<S>,
        S: Send + Sync + Clone + 'static,
        St: AxumUserStore + FromRef<S> + Send + Sync + 'static,
        St::Error: IntoResponse,
    {
        self.routes_with_prefix::<St, S>(routes, "")
    }

    pub fn routes_with_prefix<St, S>(&self, routes: Routes, prefix: &'static str) -> Router<S>
    where
        AxumUserConfig: FromRef<S>,
        S: Send + Sync + Clone + 'static,
        St: AxumUserStore + FromRef<S> + Send + Sync + 'static,
        St::Error: IntoResponse,
    {
        let mut router = Router::new();

        if !prefix.is_empty() && !prefix.starts_with('/') {
            panic!("Prefix must be empty or start with /");
        }

        if prefix.ends_with('/') {
            panic!("Prefix must not end with /")
        }

        let prefixed_route = |route: &str| format!("{}{}", prefix, route);

        #[cfg(feature = "templates")]
        {
            router = router
                .route(prefixed_route(routes.login).as_str(), get(get_login::<St>))
                .route(
                    prefixed_route(routes.signup).as_str(),
                    get(get_signup::<St>),
                )
                .route(
                    prefixed_route(routes.password_send_reset).as_str(),
                    get(get_password_send_reset::<St>).post(post_password_send_reset::<St>),
                );

            #[cfg(feature = "extended")]
            {
                router = router
                    .route(prefixed_route(routes.user).as_str(), get(get_user::<St>))
                    .route(
                        prefixed_route(routes.password_reset).as_str(),
                        get(get_password_reset::<St>).post(post_password_reset::<St>),
                    );
            }
        }

        #[cfg(not(feature = "templates"))]
        {
            router = router.route(
                prefixed_route(routes.password_send_reset).as_str(),
                post(post_password_send_reset::<St>),
            );

            #[cfg(feature = "extended")]
            {
                router = router.route(
                    prefixed_route(routes.password_reset).as_str(),
                    post(post_password_reset::<St>),
                );
            }
        }

        router = router
            .route(
                prefixed_route(routes.login_password).as_str(),
                post(post_login_password::<St>),
            )
            .route(
                prefixed_route(routes.login_email).as_str(),
                post(post_login_email::<St>).get(get_login_email::<St>),
            )
            .route(
                prefixed_route(routes.login_oauth).as_str(),
                post(post_login_oauth::<St>),
            )
            .route(
                prefixed_route(routes.signup_password).as_str(),
                post(post_signup_password::<St>),
            )
            .route(
                prefixed_route(routes.signup_email).as_str(),
                post(post_signup_email::<St>).get(get_signup_email::<St>),
            )
            .route(
                prefixed_route(routes.signup_oauth).as_str(),
                post(post_signup_oauth::<St>),
            )
            .route(
                prefixed_route(routes.logout).as_str(),
                get(get_user_logout::<St>),
            )
            .route(
                prefixed_route(routes.user_verify_session).as_str(),
                get(get_user_verify_session::<St>),
            )
            .route(
                prefixed_route(routes.user_oauth_link).as_str(),
                post(post_user_oauth_link::<St>),
            )
            .route(
                prefixed_route(routes.user_session_delete).as_str(),
                post(post_user_session_delete::<St>),
            )
            .route(
                prefixed_route(routes.user_oauth_refresh).as_str(),
                post(post_user_oauth_refresh::<St>),
            )
            .route(
                prefixed_route(routes.user_email_verify).as_str(),
                get(get_user_email_verify::<St>).post(post_user_email_verify::<St>),
            );

        #[cfg(feature = "extended")]
        {
            router = router
                .route(
                    prefixed_route(routes.user_delete).as_str(),
                    post(post_user_delete::<St>),
                )
                .route(
                    prefixed_route(routes.user_password_set).as_str(),
                    post(post_user_password_set::<St>),
                )
                .route(
                    prefixed_route(routes.user_password_delete).as_str(),
                    post(post_user_password_delete::<St>),
                )
                .route(
                    prefixed_route(routes.user_oauth_delete).as_str(),
                    post(post_user_oauth_delete::<St>),
                )
                .route(
                    prefixed_route(routes.user_email_add).as_str(),
                    post(post_user_email_add::<St>),
                )
                .route(
                    prefixed_route(routes.user_email_delete).as_str(),
                    post(post_user_email_delete::<St>),
                )
                .route(
                    prefixed_route(routes.user_email_enable_login).as_str(),
                    post(post_user_email_enable_login::<St>),
                )
                .route(
                    prefixed_route(routes.user_email_disable_login).as_str(),
                    post(post_user_email_disable_login::<St>),
                );
        }

        if [
            routes.login_oauth_provider,
            routes.signup_oauth_provider,
            routes.user_oauth_link_provider,
            routes.user_oauth_refresh_provider,
        ]
        .into_iter()
        .any(|r| !r.contains("/:provider"))
        {
            panic!("All oauth callback routes must contain /:provider")
        };

        if routes.login_oauth_provider == routes.signup_oauth_provider
            || routes.login_oauth_provider == routes.user_oauth_link_provider
            || routes.login_oauth_provider == routes.user_oauth_refresh_provider
        {
            router = router.route(
                prefixed_route(routes.login_oauth_provider).as_str(),
                get(get_generic_oauth::<St>),
            );
        } else {
            router = router.route(
                prefixed_route(routes.login_oauth_provider).as_str(),
                get(get_login_oauth::<St>),
            );
        }

        if routes.signup_oauth_provider == routes.login_oauth_provider
            || routes.signup_oauth_provider == routes.user_oauth_link_provider
            || routes.signup_oauth_provider == routes.user_oauth_refresh_provider
        {
            router = router.route(
                prefixed_route(routes.signup_oauth_provider).as_str(),
                get(get_generic_oauth::<St>),
            );
        } else {
            router = router.route(
                prefixed_route(routes.signup_oauth_provider).as_str(),
                get(get_signup_oauth::<St>),
            );
        }

        if routes.user_oauth_link == routes.signup_oauth_provider
            || routes.user_oauth_link == routes.login_oauth_provider
            || routes.user_oauth_link == routes.user_oauth_refresh_provider
        {
            router = router.route(
                prefixed_route(routes.user_oauth_link).as_str(),
                get(get_generic_oauth::<St>),
            );
        } else {
            router = router.route(
                prefixed_route(routes.user_oauth_link).as_str(),
                get(get_user_oauth_link::<St>),
            );
        }

        if routes.user_oauth_refresh == routes.signup_oauth_provider
            || routes.user_oauth_refresh == routes.user_oauth_link_provider
            || routes.user_oauth_refresh == routes.login_oauth_provider
        {
            router = router.route(
                prefixed_route(routes.user_oauth_refresh).as_str(),
                get(get_generic_oauth::<St>),
            );
        } else {
            router = router.route(
                prefixed_route(routes.user_oauth_refresh).as_str(),
                get(get_user_oauth_refresh::<St>),
            );
        }

        router
    }
}
