#[cfg(feature = "oauth")]
pub mod actions;
pub mod callbacks;

#[cfg(feature = "oauth")]
use self::actions::*;
use self::callbacks::*;

use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OAuthRoutes<T = &'static str> {
    #[cfg(feature = "oauth")]
    pub actions: OAuthActionRoutes<T>,
    pub callbacks: OAuthCallbackRoutes<T>,
}

impl Default for OAuthRoutes<&'static str> {
    fn default() -> Self {
        Self {
            #[cfg(feature = "oauth")]
            actions: OAuthActionRoutes::default(),
            callbacks: OAuthCallbackRoutes::default(),
        }
    }
}

impl<'a> From<&'a OAuthRoutes<String>> for OAuthRoutes<&'a str> {
    fn from(value: &'a OAuthRoutes<String>) -> Self {
        Self {
            #[cfg(feature = "oauth")]
            actions: value.actions.as_ref().into(),
            callbacks: value.callbacks.as_ref().into(),
        }
    }
}

impl From<OAuthRoutes<&str>> for OAuthRoutes<String> {
    fn from(value: OAuthRoutes<&str>) -> Self {
        value.with_prefix("")
    }
}

impl<T: Sized> AsRef<OAuthRoutes<T>> for OAuthRoutes<T> {
    fn as_ref(&self) -> &OAuthRoutes<T> {
        self
    }
}

impl<T: Display> OAuthRoutes<T> {
    pub fn with_prefix(self, prefix: impl Display) -> OAuthRoutes<String> {
        OAuthRoutes {
            #[cfg(feature = "oauth")]
            actions: self.actions.with_prefix(&prefix),
            callbacks: self.callbacks.with_prefix(prefix),
        }
    }
}
