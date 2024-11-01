#![cfg_attr(not(feature = "default"), allow(unused))]

pub(crate) mod config;
pub(crate) mod constants;
pub(crate) mod core;
pub(crate) mod store;

pub(crate) mod prelude {
    #[cfg(feature = "axum-router-account")]
    pub use crate::server::axum::router::account::*;
    #[cfg(feature = "axum-router-email")]
    pub use crate::server::axum::router::email::*;
    #[cfg(feature = "axum-router-oauth-callbacks")]
    pub use crate::server::axum::router::oauth::*;
    #[cfg(feature = "axum-router-pages")]
    pub use crate::server::axum::router::pages::*;
    #[cfg(feature = "axum-router-password")]
    pub use crate::server::axum::router::password::*;
    #[cfg(feature = "axum-extract")]
    pub use crate::server::axum::{cookies::*, *};

    #[cfg(all(feature = "server-email", feature = "server-password"))]
    pub use crate::server::email::reset::*;

    #[cfg(feature = "server-email")]
    pub use crate::server::email::{login::*, signup::*, verify::*, *};

    #[cfg(feature = "server-pages")]
    pub use crate::server::pages::*;

    #[cfg(feature = "server-password")]
    pub use crate::server::password::{hasher::*, login::*, signup::*, *};

    #[cfg(feature = "server-oauth")]
    pub use crate::server::oauth::{
        client::*,
        link::*,
        login::*,
        provider::{custom::*, github::*, gitlab::*, google::*, oidc::*, spotify::*, *},
        refresh::*,
        signup::*,
        *,
    };

    pub use crate::server::{constants::*, core::*, store::*, *};
}

#[cfg(feature = "axum-extract")]
pub(crate) mod axum;
#[cfg(feature = "server-email")]
pub(crate) mod email;
#[cfg(feature = "server-oauth")]
pub(crate) mod oauth;
#[cfg(feature = "server-pages")]
pub(crate) mod pages;
#[cfg(feature = "server-password")]
pub(crate) mod password;

#[cfg(feature = "axum-extract")]
pub use axum::AxumUserp as Userp;
#[cfg(not(feature = "axum-extract"))]
pub use core::CoreUserp as Userp;

pub mod reexports {
    #[cfg(any(feature = "server-email", feature = "server-oauth"))]
    pub use chrono;
    #[cfg(feature = "server-oauth")]
    pub use oauth2;
    pub use thiserror;
    #[cfg(any(feature = "server-email", feature = "server-oauth"))]
    pub use url;
    pub use uuid;
}
