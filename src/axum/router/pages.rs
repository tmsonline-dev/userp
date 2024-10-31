use crate::pages::{LoginTemplate, SignupTemplate};
use crate::{axum::AxumUserp, config::UserpConfig, traits::UserpStore};
use axum::extract::Query;
use axum::routing::get;
use axum::{
    extract::FromRef,
    response::{IntoResponse, Redirect},
    Router,
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct NextMessageErrorQuery {
    pub next: Option<String>,
    pub message: Option<String>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct AddressMessageSentErrorQuery {
    pub address: Option<String>,
    pub message: Option<String>,
    pub sent: Option<bool>,
    pub error: Option<String>,
}

impl UserpConfig {
    pub(crate) fn with_pages_routes<St, S>(&self, mut router: Router<S>) -> Router<S>
    where
        UserpConfig: FromRef<S>,
        S: Send + Sync + Clone + 'static,
        St: UserpStore + FromRef<S> + Send + Sync + 'static,
        St::Error: IntoResponse,
    {
        router = router
            .route(self.routes.pages.login.as_str(), get(get_login::<St>))
            .route(self.routes.pages.signup.as_str(), get(get_signup::<St>));

        #[cfg(all(feature = "axum-router-email", feature = "axum-router-password"))]
        {
            router = router
                .route(
                    self.routes.pages.password_send_reset.as_str(),
                    get(get_password_send_reset::<St>),
                )
                .route(
                    self.routes.pages.password_reset.as_str(),
                    get(get_password_reset::<St>),
                );
        }

        #[cfg(feature = "axum-router-account")]
        {
            router = router.route(self.routes.pages.user.as_str(), get(get_user::<St>));
        }

        router
    }
}

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
        Redirect::to(&auth.routes.pages.post_login).into_response()
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

#[cfg(feature = "axum-router-account")]
pub async fn get_user<St>(
    auth: AxumUserp<St>,
    Query(NextMessageErrorQuery { error, message, .. }): Query<NextMessageErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    use crate::pages::UserTemplate;
    use crate::traits::User;

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
            #[cfg(feature = "oauth-action-routes")]
            &oauth_tokens,
        )
        .into_response()
    } else {
        Redirect::to(&format!("{login_route}?next=%2Fuser")).into_response()
    })
}

#[cfg(all(feature = "axum-router-password", feature = "axum-router-email"))]
async fn get_password_send_reset<St>(
    auth: AxumUserp<St>,
    Query(query): Query<AddressMessageSentErrorQuery>,
) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    use crate::pages::SendResetPasswordTemplate;

    Ok(SendResetPasswordTemplate {
        sent: query.sent.is_some_and(|sent| sent),
        address: query.address.as_deref(),
        error: query.error.as_deref(),
        message: query.message.as_deref(),
        send_reset_password_action_route: &auth.routes.email.password_send_reset,
    }
    .into_response())
}

#[cfg(all(feature = "axum-router-email", feature = "axum-router-password"))]
async fn get_password_reset<St>(auth: AxumUserp<St>) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    use crate::pages::ResetPasswordTemplate;
    use reqwest::StatusCode;

    if auth.is_reset_session().await? {
        Ok(ResetPasswordTemplate {
            reset_password_action_route: &auth.routes.email.password_reset,
        }
        .into_response())
    } else {
        Ok(StatusCode::UNAUTHORIZED.into_response())
    }
}
