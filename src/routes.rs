mod forms;
mod queries;
mod templates;

use askama_axum::IntoResponse;
use axum::{
    extract::{FromRef, Path, Query},
    response::Redirect,
    routing::{get, post},
    Form, Router,
};
use forms::*;
use queries::*;
use reqwest::StatusCode;
use templates::*;
use urlencoding::encode;

use crate::{
    email::{
        EmailLoginCallbackError, EmailLoginInitError, EmailResetCallbackError,
        EmailSignupCallbackError, EmailSignupInitError, EmailVerifyCallbackError,
        SendEmailChallengeError,
    },
    oauth::{
        OAuthLinkCallbackError, OAuthLinkInitError, OAuthLoginCallbackError,
        OAuthRefreshCallbackError, OAuthSignupCallbackError,
    },
    AxumUser, AxumUserConfig, AxumUserExtendedStore, EmailLoginError, EmailResetError,
    LoginSession, OAuthToken, PasswordLoginError, PasswordSignupError, RefreshInitResult, User,
};

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
    St: AxumUserExtendedStore,
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
    St: AxumUserExtendedStore,
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
    St: AxumUserExtendedStore,
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
    St: AxumUserExtendedStore,
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
    St: AxumUserExtendedStore,
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
    St: AxumUserExtendedStore,
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
    St: AxumUserExtendedStore,
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
    St: AxumUserExtendedStore,
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
    St: AxumUserExtendedStore,
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
    St: AxumUserExtendedStore,
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
    St: AxumUserExtendedStore,
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
    St: AxumUserExtendedStore,
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

async fn get_user<St>(
    auth: AxumUser<St>,
    Query(NextMessageErrorQuery { error, message, .. }): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserExtendedStore,
    St::Error: IntoResponse,
{
    Ok(if let Some(user) = auth.user().await? {
        let sessions = auth.store.get_user_sessions(user.get_id()).await?;
        let oauth_tokens = auth.store.get_user_oauth_tokens(user.get_id()).await?;
        let emails = auth.store.get_user_emails(user.get_id()).await?;

        UserTemplate {
            message,
            error,
            sessions: sessions.into_iter().map(|s| s.into()).collect(),
            has_password: user.get_password_hash().is_some(),
            emails: emails.into_iter().map(|e| e.into()).collect(),
            oauth_providers: auth
                .oauth_link_providers()
                .into_iter()
                .filter(|p| !oauth_tokens.iter().any(|t| t.provider_name() == p.name()))
                .map(|p| p.into())
                .collect(),
            oauth_tokens: oauth_tokens.into_iter().map(|t| t.into()).collect(),
        }
        .into_response()
    } else {
        println!("User not found in store");
        Redirect::to("/login?next=%UFuser").into_response()
    })
}

async fn post_user_delete<St>(auth: AxumUser<St>) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserExtendedStore,
    St::Error: IntoResponse,
{
    Ok(if let Some(user) = auth.user().await? {
        auth.store.delete_user(user.get_id()).await?;

        let auth = auth.log_out().await?;

        (auth, Redirect::to("/")).into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    })
}

async fn get_user_logout<St>(auth: AxumUser<St>) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserExtendedStore,
    St::Error: IntoResponse,
{
    let auth = auth.log_out().await?;

    Ok((auth, Redirect::to("/")))
}

async fn get_user_verify_session<St>(auth: AxumUser<St>) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserExtendedStore,
    St::Error: IntoResponse,
{
    Ok(if auth.logged_in().await? {
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    })
}

async fn post_user_password_set<St>(
    auth: AxumUser<St>,
    Form(NewPasswordForm { new_password }): Form<NewPasswordForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserExtendedStore,
    St::Error: IntoResponse,
{
    let mut user_session = auth.user_session().await?;

    if user_session.is_none() {
        user_session = auth.reset_user_session().await?;
    }

    let Some((user, session)) = user_session else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store
        .set_user_password(user.get_id(), new_password, session.get_id())
        .await?;

    Ok(Redirect::to("/user?message=The password has been set!").into_response())
}

async fn post_user_password_delete<St>(auth: AxumUser<St>) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserExtendedStore,
    St::Error: IntoResponse,
{
    let Some((user, session)) = auth.user_session().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store
        .clear_user_password(user.get_id(), session.get_id())
        .await?;

    Ok((auth, Redirect::to("/user?message=Password cleared")).into_response())
}

async fn post_user_oauth_link<St>(
    auth: AxumUser<St>,
    Form(ProviderNextForm { provider, next }): Form<ProviderNextForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserExtendedStore,
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
    St: AxumUserExtendedStore,
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
    St: AxumUserExtendedStore,
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
    St: AxumUserExtendedStore,
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
    St: AxumUserExtendedStore,
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

async fn post_user_oauth_delete<St>(
    auth: AxumUser<St>,
    Form(IdForm { id }): Form<IdForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserExtendedStore,
    St::Error: IntoResponse,
{
    if !auth.logged_in().await? {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store.delete_oauth_token(id).await?;

    Ok(Redirect::to("/user?message=Token deleted").into_response())
}

async fn get_user_email_verify<St>(
    auth: AxumUser<St>,
    Query(CodeQuery { code }): Query<CodeQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserExtendedStore,
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
    St: AxumUserExtendedStore,
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

async fn post_user_email_add<St>(
    auth: AxumUser<St>,
    Form(EmailForm { email }): Form<EmailForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserExtendedStore,
    St::Error: IntoResponse,
{
    let Some(user) = auth.user().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store.add_user_email(user.get_id(), email).await?;

    Ok(Redirect::to("/user?message=Email added").into_response())
}

async fn post_user_email_delete<St>(
    auth: AxumUser<St>,
    Form(EmailForm { email }): Form<EmailForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserExtendedStore,
    St::Error: IntoResponse,
{
    let Some(user) = auth.user().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store.delete_user_email(user.get_id(), email).await?;

    Ok(Redirect::to("/user?message=Email deleted").into_response())
}

async fn post_user_email_enable_login<St>(
    auth: AxumUser<St>,
    Form(EmailForm { email }): Form<EmailForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserExtendedStore,
    St::Error: IntoResponse,
{
    let Some(user) = auth.user().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store
        .set_user_email_allow_link_login(user.get_id(), email.clone(), true)
        .await?;

    Ok(Redirect::to(&format!(
        "/user?message={}",
        encode(&format!("You can now log in directly with {email}"))
    ))
    .into_response())
}

async fn post_user_email_disable_login<St>(
    auth: AxumUser<St>,
    Form(EmailForm { email }): Form<EmailForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserExtendedStore,
    St::Error: IntoResponse,
{
    let Some(user) = auth.user().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store
        .set_user_email_allow_link_login(user.get_id(), email.clone(), false)
        .await?;

    Ok(Redirect::to(&format!(
        "/user?message={}",
        encode(&format!("You can no longer log in directly with {email}"))
    ))
    .into_response())
}

async fn get_password_send_reset<St>(
    Query(query): Query<AddressMessageSentErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserExtendedStore,
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
    St: AxumUserExtendedStore,
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

async fn get_password_reset<St>(
    auth: AxumUser<St>,
    Query(query): Query<CodeQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserExtendedStore,
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

async fn post_password_reset<St>(
    auth: AxumUser<St>,
    Form(NewPasswordForm { new_password }): Form<NewPasswordForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserExtendedStore,
    St::Error: IntoResponse,
{
    if let Some((user, session)) = auth.reset_user_session().await? {
        auth.store
            .set_user_password(user.get_id(), new_password, session.get_id())
            .await?;
        Ok(Redirect::to("/login?message=Password has been reset").into_response())
    } else {
        Ok(StatusCode::UNAUTHORIZED.into_response())
    }
}

impl AxumUserConfig {
    pub fn routes<St, S>(&self) -> Router<S>
    where
        AxumUserConfig: FromRef<S>,
        S: Send + Sync + Clone + 'static,
        St: AxumUserExtendedStore + FromRef<S> + Send + Sync + 'static,
        St::Error: IntoResponse,
    {
        Router::new()
            .route("/login", get(get_login::<St>))
            .route("/login/password", post(post_login_password::<St>))
            .route(
                "/login/email",
                post(post_login_email::<St>).get(get_login_email::<St>),
            )
            .route("/login/oauth", post(post_login_oauth::<St>))
            .route("/login/oauth/:provider", get(get_login_oauth::<St>))
            .route("/signup", get(get_signup::<St>))
            .route("/signup/password", post(post_signup_password::<St>))
            .route(
                "/signup/email",
                post(post_signup_email::<St>).get(get_signup_email::<St>),
            )
            .route("/signup/oauth", post(post_signup_oauth::<St>))
            .route("/signup/oauth/:provider", get(get_signup_oauth::<St>))
            .route("/user", get(get_user::<St>))
            .route("/user/delete", post(post_user_delete::<St>))
            .route("/user/logout", get(get_user_logout::<St>))
            .route("/user/verify-session", get(get_user_verify_session::<St>))
            .route("/user/password/set", post(post_user_password_set::<St>))
            .route(
                "/user/password/delete",
                post(post_user_password_delete::<St>),
            )
            .route("/user/oauth/link", post(post_user_oauth_link::<St>))
            .route("/user/oauth/link/:provider", get(get_user_oauth_link::<St>))
            .route("/user/session/delete", post(post_user_session_delete::<St>))
            .route("/user/oauth/refresh", post(post_user_oauth_refresh::<St>))
            .route(
                "/user/oauth/refresh/:provider",
                get(get_user_oauth_refresh::<St>),
            )
            .route("/user/oauth/delete", post(post_user_oauth_delete::<St>))
            .route(
                "/user/email/verify",
                get(get_user_email_verify::<St>).post(post_user_email_verify::<St>),
            )
            .route("/user/email/add", post(post_user_email_add::<St>))
            .route("/user/email/delete", post(post_user_email_delete::<St>))
            .route(
                "/user/email/enable_login",
                post(post_user_email_enable_login::<St>),
            )
            .route(
                "/user/email/disable_login",
                post(post_user_email_disable_login::<St>),
            )
            .route(
                "/password/send-reset",
                get(get_password_send_reset::<St>).post(post_password_send_reset::<St>),
            )
            .route(
                "/password/reset",
                get(get_password_reset::<St>).post(post_password_reset::<St>),
            )
    }
}
