#![cfg_attr(not(feature = "default"), allow(unused))]

pub mod config;
pub mod constants;
pub mod core;
pub mod models;
pub mod prelude;
pub mod reexports;
pub mod store;

#[cfg(feature = "email")]
pub mod email;
#[cfg(feature = "oauth-callbacks")]
pub mod oauth;
#[cfg(feature = "password")]
pub mod password;

#[cfg(feature = "axum")]
pub mod axum;

#[cfg(feature = "axum")]
pub use axum::AxumUserp as Userp;
#[cfg(not(feature = "axum"))]
pub use core::CoreUserp as Userp;
