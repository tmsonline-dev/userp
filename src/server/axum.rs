pub mod cookies;
pub mod extract;
#[cfg(any(
    feature = "axum-router-oauth-callbacks",
    feature = "axum-router-email",
    feature = "axum-router-password",
    feature = "axum-router-pages",
    feature = "axum-router-account"
))]
pub mod router;

use crate::server::core::CoreUserp;
use cookies::AxumUserpCookies;

pub type AxumUserp<S> = CoreUserp<S, AxumUserpCookies>;
