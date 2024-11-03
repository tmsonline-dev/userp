pub mod pages;
use pages::*;

#[cfg(feature = "client-account")]
pub mod account;
#[cfg(feature = "client-account")]
use account::*;
#[cfg(feature = "client-email")]
pub mod email;
#[cfg(feature = "client-email")]
use email::*;
#[cfg(feature = "client-oauth")]
pub mod oauth;
#[cfg(feature = "client-oauth")]
use oauth::*;
#[cfg(feature = "client-password")]
pub mod password;
#[cfg(feature = "client-password")]
use password::*;
use serde::{Deserialize, Serialize};

use std::fmt::Display;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Routes<T = String> {
    pub pages: PageRoutes<T>,
    #[cfg(feature = "client-oauth")]
    pub oauth: OAuthRoutes<T>,
    #[cfg(feature = "client-email")]
    pub email: EmailActionRoutes<T>,
    #[cfg(feature = "client-password")]
    pub password: PasswordActionRoutes<T>,
    #[cfg(feature = "client-account")]
    pub account: AccountActionRoutes<T>,
    pub logout: T,
    pub user_verify_session: T,
}

impl Default for Routes<&'static str> {
    fn default() -> Self {
        Routes {
            pages: PageRoutes::default(),
            #[cfg(feature = "client-oauth")]
            oauth: OAuthRoutes::default(),
            #[cfg(feature = "client-email")]
            email: EmailActionRoutes::default(),
            #[cfg(feature = "client-password")]
            password: PasswordActionRoutes::default(),
            #[cfg(feature = "client-account")]
            account: AccountActionRoutes::default(),
            user_verify_session: "/verify-session",
            logout: "/logout",
        }
    }
}

impl From<Routes<&'static str>> for Routes<String> {
    fn from(value: Routes<&'static str>) -> Self {
        value.with_prefix("")
    }
}

impl<T: Sized> AsRef<Routes<T>> for Routes<T> {
    fn as_ref(&self) -> &Routes<T> {
        self
    }
}

impl<'a> From<&'a Routes<String>> for Routes<&'a str> {
    fn from(value: &'a Routes<String>) -> Self {
        Self {
            pages: value.pages.as_ref().into(),
            #[cfg(feature = "client-oauth")]
            oauth: value.oauth.as_ref().into(),
            #[cfg(feature = "client-email")]
            email: value.email.as_ref().into(),
            #[cfg(feature = "client-password")]
            password: value.password.as_ref().into(),
            #[cfg(feature = "client-account")]
            account: value.account.as_ref().into(),
            user_verify_session: &value.user_verify_session,
            logout: &value.logout,
        }
    }
}

impl<T: Display> Routes<T> {
    pub fn with_prefix(self, prefix: impl Display) -> Routes<String> {
        Routes {
            pages: self.pages.with_prefix(&prefix),
            #[cfg(feature = "client-oauth")]
            oauth: self.oauth.with_prefix(&prefix),
            #[cfg(feature = "client-email")]
            email: self.email.with_prefix(&prefix),
            #[cfg(feature = "client-password")]
            password: self.password.with_prefix(&prefix),
            #[cfg(feature = "client-account")]
            account: self.account.with_prefix(&prefix),
            user_verify_session: format!("{prefix}{}", self.user_verify_session),
            logout: format!("{prefix}{}", self.logout),
        }
    }
}
