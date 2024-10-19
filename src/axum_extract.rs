use async_trait::async_trait;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::request::Parts,
    response::IntoResponseParts,
};
use axum_extra::extract::cookie::{Cookie, Expiration, Key, PrivateCookieJar, SameSite};
use std::convert::Infallible;

use crate::{Userp, UserpConfig, UserpStore};

#[derive(Debug, Clone)]
pub struct CookieStore {
    jar: PrivateCookieJar,
    https_only: bool,
}

impl IntoResponseParts for CookieStore {
    type Error = Infallible;

    fn into_response_parts(
        self,
        res: axum::response::ResponseParts,
    ) -> Result<axum::response::ResponseParts, Self::Error> {
        self.jar.into_response_parts(res)
    }
}

impl CookieStore {
    pub fn add(&mut self, key: &str, value: &str) {
        self.jar = self.jar.clone().add(
            Cookie::build((key.to_owned(), value.to_owned()))
                .same_site(SameSite::Lax)
                .http_only(true)
                .expires(Expiration::Session)
                .secure(self.https_only)
                .path("/")
                .build(),
        );
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.jar.get(key).map(|c| c.value().to_owned())
    }

    pub fn remove(&mut self, key: &str) {
        self.jar = self.jar.clone().remove(key.to_owned());
    }

    pub fn list_encoded(&self) -> Vec<String> {
        self.jar.iter().map(|c| c.encoded().to_string()).collect()
    }
}

impl<S: UserpStore> IntoResponseParts for Userp<S> {
    type Error = Infallible;

    fn into_response_parts(
        self,
        res: axum::response::ResponseParts,
    ) -> Result<axum::response::ResponseParts, Self::Error> {
        self.cookies.into_response_parts(res)
    }
}

#[async_trait]
impl<S, St> FromRequestParts<S> for Userp<St>
where
    St: UserpStore,
    UserpConfig: FromRef<S>,
    S: Send + Sync,
    St: UserpStore + FromRef<S>,
{
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Infallible> {
        let config = UserpConfig::from_ref(state);
        let cookies = CookieStore {
            jar: PrivateCookieJar::from_headers(&parts.headers, Key::from(config.key.as_bytes())),
            https_only: config.https_only,
        };
        let store = St::from_ref(state);

        return Ok(Userp {
            allow_signup: config.allow_signup,
            allow_login: config.allow_login,
            routes: config.routes,
            cookies,
            store,
            #[cfg(feature = "email")]
            email: config.email,
            #[cfg(feature = "password")]
            pass: config.pass,
            #[cfg(feature = "oauth")]
            oauth: config.oauth,
        });
    }
}
