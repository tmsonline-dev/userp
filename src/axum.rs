mod cookies;
mod extract;
#[cfg(feature = "axum-router")]
mod router;

use crate::core::CoreUserp;
use cookies::AxumUserpCookies;

pub type AxumUserp<S> = CoreUserp<S, AxumUserpCookies>;
