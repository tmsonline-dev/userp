use super::cookies::AxumUserpCookies;
use crate::server::{config::UserpConfig, core::CoreUserp, store::UserpStore};
use async_trait::async_trait;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
    response::IntoResponseParts,
};
use axum_extra::extract::cookie::{Key, PrivateCookieJar};
use std::convert::Infallible;

impl<S: UserpStore> IntoResponseParts for CoreUserp<S, AxumUserpCookies> {
    type Error = Infallible;

    fn into_response_parts(
        self,
        res: axum::response::ResponseParts,
    ) -> Result<axum::response::ResponseParts, Self::Error> {
        self.cookies.into_response_parts(res)
    }
}

#[async_trait]
impl<S, St> FromRequestParts<S> for CoreUserp<St, AxumUserpCookies>
where
    St: UserpStore,
    UserpConfig: FromRef<S>,
    S: Send + Sync,
    St: UserpStore + FromRef<S>,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Infallible> {
        let config = UserpConfig::from_ref(state);
        let cookies = AxumUserpCookies {
            jar: PrivateCookieJar::from_headers(&parts.headers, Key::from(config.key.as_bytes())),
            https_only: config.https_only,
        };
        let store = St::from_ref(state);

        return Ok(CoreUserp {
            allow_signup: config.allow_signup,
            allow_login: config.allow_login,
            routes: config.routes,
            cookies,
            store,
            #[cfg(feature = "server-email")]
            email: config.email,
            #[cfg(feature = "server-password")]
            pass: config.pass,
            #[cfg(feature = "server-oauth-callbacks")]
            oauth: config.oauth,
        });
    }
}
