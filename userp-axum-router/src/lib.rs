#![cfg_attr(not(feature = "default"), allow(unused))]

pub mod prelude;
pub mod router;

pub use router::AxumRouter;
