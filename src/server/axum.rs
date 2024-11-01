pub(crate) mod cookies;
pub(crate) mod extract;
#[cfg(any(
    feature = "axum-router-oauth-callbacks",
    feature = "axum-router-email",
    feature = "axum-router-password",
    feature = "axum-router-pages",
    feature = "axum-router-account"
))]
pub(crate) mod router;

use crate::server::core::CoreUserp;
use cookies::AxumUserpCookies;

pub type AxumUserp<S> = CoreUserp<S, AxumUserpCookies>;
