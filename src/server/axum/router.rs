#[cfg(feature = "axum-router-account")]
pub mod account;
#[cfg(feature = "axum-router-email")]
pub mod email;
#[cfg(feature = "axum-router-oauth-callbacks")]
pub mod oauth;
#[cfg(feature = "axum-router-pages")]
pub mod pages;
#[cfg(feature = "axum-router-password")]
pub mod password;

use super::AxumUserp;
use crate::server::{config::UserpConfig, store::UserpStore};
use axum::response::IntoResponse;
use axum::{extract::FromRef, http::StatusCode, response::Redirect, routing::get, Router};

impl UserpConfig {
    pub fn router<St, S>(&self) -> Router<S>
    where
        UserpConfig: FromRef<S>,
        S: Send + Sync + Clone + 'static,
        St: UserpStore + FromRef<S> + Send + Sync + 'static,
        St::Error: IntoResponse,
    {
        let mut router = Router::new();

        router = router
            .route(self.routes.logout.as_str(), get(get_user_logout::<St>))
            .route(
                self.routes.user_verify_session.as_str(),
                get(get_user_verify_session::<St>),
            );

        #[cfg(feature = "axum-router-pages")]
        {
            router = self.with_pages_routes::<St, S>(router);
        }

        #[cfg(feature = "axum-router-account")]
        {
            router = self.with_account_routes::<St, S>(router);
        }

        #[cfg(feature = "axum-router-oauth-callbacks")]
        {
            router = self.with_oauth_routes::<St, S>(router);
        }

        #[cfg(feature = "axum-router-password")]
        {
            router = self.with_password_routes::<St, S>(router);
        }

        #[cfg(feature = "axum-router-email")]
        {
            router = self.with_email_routes::<St, S>(router);
        }

        router
    }
}

async fn get_user_logout<St>(auth: AxumUserp<St>) -> Result<impl IntoResponse, St::Error>
where
    St: UserpStore,
    St::Error: IntoResponse,
{
    let post_logout = auth.routes.pages.post_logout.clone();

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
