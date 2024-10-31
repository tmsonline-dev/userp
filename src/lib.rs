#![cfg_attr(not(feature = "default"), allow(unused))]

pub mod config;
pub mod constants;
pub mod core;
pub mod enums;
pub mod prelude;
pub mod routes;
pub mod traits;

#[cfg(feature = "axum-extract")]
pub mod axum;
#[cfg(feature = "email")]
pub mod email;
#[cfg(feature = "oauth")]
pub mod oauth;
#[cfg(feature = "pages")]
pub mod pages;
#[cfg(feature = "password")]
pub mod password;

#[cfg(feature = "axum-extract")]
pub use axum::AxumUserp as Userp;
#[cfg(not(feature = "axum-extract"))]
pub use core::CoreUserp as Userp;

#[cfg(any(feature = "email", feature = "oauth"))]
pub use chrono;
#[cfg(feature = "oauth")]
pub use oauth2;
pub use thiserror;
#[cfg(any(feature = "email", feature = "oauth"))]
pub use url;
pub use uuid;
