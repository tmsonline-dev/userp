use crate::models::{LoginSession, User};
use crate::server::{axum::AxumUserp, config::UserpConfig, store::UserpStore};
use axum::response::IntoResponse;
use axum::{extract::FromRef, routing::post, Router};
use axum::{http::StatusCode, response::Redirect, Form};
use serde::Deserialize;
use urlencoding::encode;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct IdAccountForm {
    pub id: Uuid,
}

#[derive(Deserialize)]
pub struct NewPasswordAccountForm {
    pub new_password: String,
}

#[derive(Deserialize)]
pub struct EmailAccountForm {
    pub email: String,
}

impl UserpConfig {
    pub(crate) fn with_account_routes<St, S>(&self, mut router: Router<S>) -> Router<S>
    where
        UserpConfig: FromRef<S>,
        S: Send + Sync + Clone + 'static,
        St: UserpStore + FromRef<S> + Send + Sync + 'static,
        St::Error: IntoResponse,
    {
        {
            router = router
                .route(
                    self.routes.account.user_delete.as_str(),
                    post(post_user_delete::<St>),
                )
                .route(
                    self.routes.account.user_session_delete.as_str(),
                    post(post_user_session_delete::<St>),
                );

            #[cfg(feature = "server-password")]
            {
                router = router
                    .route(
                        self.routes.account.user_password_set.as_str(),
                        post(post_user_password_set::<St>),
                    )
                    .route(
                        self.routes.account.user_password_delete.as_str(),
                        post(post_user_password_delete::<St>),
                    );
            }

            #[cfg(feature = "server-oauth")]
            {
                router = router.route(
                    self.routes.account.user_oauth_delete.as_str(),
                    post(post_user_oauth_delete::<St>),
                );
            }

            #[cfg(feature = "server-email")]
            {
                router = router
                    .route(
                        self.routes.account.user_email_add.as_str(),
                        post(post_user_email_add::<St>),
                    )
                    .route(
                        self.routes.account.user_email_delete.as_str(),
                        post(post_user_email_delete::<St>),
                    )
                    .route(
                        self.routes.account.user_email_enable_login.as_str(),
                        post(post_user_email_enable_login::<St>),
                    )
                    .route(
                        self.routes.account.user_email_disable_login.as_str(),
                        post(post_user_email_disable_login::<St>),
                    );
            }

            router
        }
    }
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

#[cfg(feature = "server-password")]
pub async fn post_user_password_set<St>(
    auth: AxumUserp<St>,
    Form(NewPasswordAccountForm { new_password }): Form<NewPasswordAccountForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let mut user_session = auth.user_session().await?;

    #[cfg(all(feature = "server-password", feature = "server-email"))]
    if user_session.is_none() {
        user_session = auth.reset_user_session().await?;
    }

    let Some((user, session)) = user_session else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    let new_password_hash = auth.pass.hasher.genereate_hash(new_password).await;

    auth.store
        .set_user_password_hash(user.get_id(), new_password_hash, session.get_id())
        .await?;

    let user_route = auth.routes.pages.user;

    Ok(Redirect::to(&format!("{user_route}?message=The password has been set!")).into_response())
}

#[cfg(feature = "server-password")]
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
        .clear_user_password_hash(user.get_id(), session.get_id())
        .await?;

    let user_route = auth.routes.pages.user.clone();

    Ok((
        auth,
        Redirect::to(&format!("{user_route}?message=Password cleared")),
    )
        .into_response())
}

#[cfg(feature = "server-oauth")]
pub async fn post_user_oauth_delete<St>(
    auth: AxumUserp<St>,
    Form(IdAccountForm { id }): Form<IdAccountForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let Some(user) = auth.user().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store.delete_oauth_token(user.get_id(), id).await?;

    let user_route = auth.routes.pages.user;

    Ok(Redirect::to(&format!("{user_route}?message=Token deleted")).into_response())
}

#[cfg(feature = "server-email")]
pub async fn post_user_email_add<St>(
    auth: AxumUserp<St>,
    Form(EmailAccountForm { email }): Form<EmailAccountForm>,
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

#[cfg(feature = "server-email")]
pub async fn post_user_email_delete<St>(
    auth: AxumUserp<St>,
    Form(EmailAccountForm { email }): Form<EmailAccountForm>,
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

#[cfg(feature = "server-email")]
pub async fn post_user_email_enable_login<St>(
    auth: AxumUserp<St>,
    Form(EmailAccountForm { email }): Form<EmailAccountForm>,
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

#[cfg(feature = "server-email")]
pub async fn post_user_email_disable_login<St>(
    auth: AxumUserp<St>,
    Form(EmailAccountForm { email }): Form<EmailAccountForm>,
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

pub async fn post_user_session_delete<St>(
    auth: AxumUserp<St>,
    Form(IdAccountForm { id }): Form<IdAccountForm>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let Some(user) = auth.user().await? else {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    };

    auth.store.delete_session(user.get_id(), id).await?;

    #[cfg(feature = "axum-router-pages")]
    let user_route = auth.routes.pages.user;
    #[cfg(not(feature = "axum-router-pages"))]
    let user_route = auth.routes.pages.post_login;

    Ok(Redirect::to(&format!("{user_route}?message=Session deleted")).into_response())
}
