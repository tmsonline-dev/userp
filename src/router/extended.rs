use crate::{oauth::OAuthToken, AxumUser, AxumUserStore, LoginSession, User};

mod forms;
use super::forms::*;
use super::queries::*;
#[cfg(feature = "templates")]
use super::templates::*;
#[cfg(feature = "templates")]
use askama_axum::IntoResponse;
#[cfg(not(feature = "templates"))]
use axum::response::IntoResponse;
use axum::{extract::Query, response::Redirect, Form};
use forms::*;
use reqwest::StatusCode;
use urlencoding::encode;

#[cfg(feature = "templates")]
pub async fn get_user<St>(
    auth: AxumUser<St>,
    Query(NextMessageErrorQuery { error, message, .. }): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
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
            has_password: user.has_password(),
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
        Redirect::to("/login?next=%2Fuser").into_response()
    })
}

pub async fn post_user_delete<St>(auth: AxumUser<St>) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
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

pub async fn post_user_password_set<St>(
    auth: AxumUser<St>,
    Form(NewPasswordForm { new_password }): Form<NewPasswordForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
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

pub async fn post_user_password_delete<St>(
    auth: AxumUser<St>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
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

pub async fn post_user_oauth_delete<St>(
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

    auth.store.delete_oauth_token(id).await?;

    Ok(Redirect::to("/user?message=Token deleted").into_response())
}

pub async fn post_user_email_add<St>(
    auth: AxumUser<St>,
    Form(EmailForm { email }): Form<EmailForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    let Some(user) = auth.user().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store.add_user_email(user.get_id(), email).await?;

    Ok(Redirect::to("/user?message=Email added").into_response())
}

pub async fn post_user_email_delete<St>(
    auth: AxumUser<St>,
    Form(EmailForm { email }): Form<EmailForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
    St::Error: IntoResponse,
{
    let Some(user) = auth.user().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store.delete_user_email(user.get_id(), email).await?;

    Ok(Redirect::to("/user?message=Email deleted").into_response())
}

pub async fn post_user_email_enable_login<St>(
    auth: AxumUser<St>,
    Form(EmailForm { email }): Form<EmailForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
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

pub async fn post_user_email_disable_login<St>(
    auth: AxumUser<St>,
    Form(EmailForm { email }): Form<EmailForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
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

pub async fn post_password_reset<St>(
    auth: AxumUser<St>,
    Form(NewPasswordForm { new_password }): Form<NewPasswordForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: AxumUserStore,
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
