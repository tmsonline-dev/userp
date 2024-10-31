mod cookies;
mod extract;
#[cfg(any(
    feature = "axum-router-oauth-callbacks",
    feature = "axum-router-email",
    feature = "axum-router-password",
    feature = "axum-router-pages",
    feature = "axum-router-account"
))]
mod router;

use crate::core::CoreUserp;
use cookies::AxumUserpCookies;

pub type AxumUserp<S> = CoreUserp<S, AxumUserpCookies>;
