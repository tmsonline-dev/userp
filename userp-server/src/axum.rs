pub mod cookies;
pub mod extract;

use crate::core::CoreUserp;
use cookies::AxumUserpCookies;

pub type AxumUserp<S> = CoreUserp<S, AxumUserpCookies>;
