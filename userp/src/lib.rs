#![cfg_attr(not(feature = "default"), allow(unused))]

pub mod prelude;
pub mod reexports;

#[cfg(feature = "axum-router")]
pub use userp_axum_router as axum_router;

#[cfg(feature = "pages")]
pub use userp_pages as pages;

#[cfg(feature = "server")]
pub use userp_server as server;

pub use userp_client as client;
