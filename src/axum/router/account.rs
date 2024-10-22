mod forms;

use super::forms::*;
use super::queries::*;
use crate::axum::AxumUserp;
#[cfg(feature = "axum-pages")]
use crate::pages::*;
use crate::traits::{LoginSession, User, UserpStore};
use axum::response::IntoResponse;
use axum::{extract::Query, http::StatusCode, response::Redirect, Form};
use forms::*;
use urlencoding::encode;

#[cfg(feature = "axum-pages")]
pub async fn get_user<St>(
    auth: AxumUserp<St>,
    Query(NextMessageErrorQuery { error, message, .. }): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let login_route = auth.routes.pages.login.clone();

    Ok(if let Some((user, session)) = auth.user_session().await? {
        let sessions = auth.store.get_user_sessions(user.get_id()).await?;
        #[cfg(feature = "email")]
        let emails = auth.store.get_user_emails(user.get_id()).await?;
        #[cfg(feature = "oauth")]
        let oauth_tokens = auth.store.get_user_oauth_tokens(user.get_id()).await?;

        UserTemplate::into_response_with(
            &auth,
            &user,
            &session,
            &sessions,
            message.as_deref(),
            error.as_deref(),
            #[cfg(feature = "email")]
            &emails,
            #[cfg(feature = "oauth")]
            &oauth_tokens,
        )
        .into_response()
    } else {
        Redirect::to(&format!("{login_route}?next=%2Fuser")).into_response()
    })
}

pub async fn post_user_delete<St>(auth: AxumUserp<St>) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    Ok(if let Some(user) = auth.user().await? {
        let signup_route = auth.routes.pages.signup.clone();
        auth.store.delete_user(user.get_id()).await?;

        (auth.log_out().await?, Redirect::to(&signup_route)).into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    })
}

#[cfg(feature = "password")]
pub async fn post_user_password_set<St>(
    auth: AxumUserp<St>,
    Form(NewPasswordForm { new_password }): Form<NewPasswordForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let mut user_session = auth.user_session().await?;

    #[cfg(all(feature = "password", feature = "email"))]
    if user_session.is_none() {
        user_session = auth.reset_user_session().await?;
    }

    let Some((user, session)) = user_session else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store
        .set_user_password(user.get_id(), new_password, session.get_id())
        .await?;

    let user_route = auth.routes.pages.user;

    Ok(Redirect::to(&format!("{user_route}?message=The password has been set!")).into_response())
}

#[cfg(feature = "password")]
pub async fn post_user_password_delete<St>(
    auth: AxumUserp<St>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let Some((user, session)) = auth.user_session().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store
        .clear_user_password(user.get_id(), session.get_id())
        .await?;

    let user_route = auth.routes.pages.user.clone();

    Ok((
        auth,
        Redirect::to(&format!("{user_route}?message=Password cleared")),
    )
        .into_response())
}

#[cfg(feature = "oauth")]
pub async fn post_user_oauth_delete<St>(
    auth: AxumUserp<St>,
    Form(IdForm { id }): Form<IdForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    if !auth.logged_in().await? {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store.delete_oauth_token(id).await?;

    let user_route = auth.routes.pages.user;

    Ok(Redirect::to(&format!("{user_route}?message=Token deleted")).into_response())
}

#[cfg(feature = "email")]
pub async fn post_user_email_add<St>(
    auth: AxumUserp<St>,
    Form(EmailForm { email }): Form<EmailForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let Some(user) = auth.user().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store.add_user_email(user.get_id(), email).await?;

    let user_route = auth.routes.pages.user;

    Ok(Redirect::to(&format!("{user_route}?message=Email added")).into_response())
}

#[cfg(feature = "email")]
pub async fn post_user_email_delete<St>(
    auth: AxumUserp<St>,
    Form(EmailForm { email }): Form<EmailForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let Some(user) = auth.user().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store.delete_user_email(user.get_id(), email).await?;

    let user_route = auth.routes.pages.user;

    Ok(Redirect::to(&format!("{user_route}?message=Email deleted")).into_response())
}

#[cfg(feature = "email")]
pub async fn post_user_email_enable_login<St>(
    auth: AxumUserp<St>,
    Form(EmailForm { email }): Form<EmailForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let Some(user) = auth.user().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store
        .set_user_email_allow_link_login(user.get_id(), email.clone(), true)
        .await?;

    let user_route = auth.routes.pages.user;

    Ok(Redirect::to(&format!(
        "{user_route}?message={}",
        encode(&format!("You can now log in directly with {email}"))
    ))
    .into_response())
}

#[cfg(feature = "email")]
pub async fn post_user_email_disable_login<St>(
    auth: AxumUserp<St>,
    Form(EmailForm { email }): Form<EmailForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let Some(user) = auth.user().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store
        .set_user_email_allow_link_login(user.get_id(), email.clone(), false)
        .await?;

    let user_route = auth.routes.pages.user;

    Ok(Redirect::to(&format!(
        "{user_route}?message={}",
        encode(&format!("You can no longer log in directly with {email}"))
    ))
    .into_response())
}

#[cfg(all(feature = "password", feature = "email"))]
pub async fn post_password_reset<St>(
    auth: AxumUserp<St>,
    Form(NewPasswordForm { new_password }): Form<NewPasswordForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    if let Some((user, session)) = auth.reset_user_session().await? {
        auth.store
            .set_user_password(user.get_id(), new_password, session.get_id())
            .await?;

        let login_route = auth.routes.pages.login;

        Ok(Redirect::to(&format!("{login_route}?message=Password has been reset")).into_response())
    } else {
        Ok(StatusCode::UNAUTHORIZED.into_response())
    }
}

pub async fn post_user_session_delete<St>(
    auth: AxumUserp<St>,
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

    let user_route = auth.routes.pages.user;

    Ok(Redirect::to(&format!("{user_route}?message=Session deleted")).into_response())
}
