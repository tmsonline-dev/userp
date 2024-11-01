pub(crate) mod pages;
use pages::*;

#[cfg(feature = "account")]
pub(crate) mod account;
#[cfg(feature = "account")]
use account::*;
#[cfg(feature = "email")]
pub(crate) mod email;
#[cfg(feature = "email")]
use email::*;
#[cfg(feature = "oauth")]
pub(crate) mod oauth;
#[cfg(feature = "oauth")]
use oauth::*;
#[cfg(feature = "password")]
pub(crate) mod password;
#[cfg(feature = "password")]
use password::*;

use std::fmt::Display;

#[derive(Debug, Clone)]
pub struct Routes<T = &'static str> {
    pub pages: PageRoutes<T>,
    #[cfg(feature = "oauth")]
    pub oauth: OAuthRoutes<T>,
    #[cfg(feature = "email")]
    pub email: EmailActionRoutes<T>,
    #[cfg(feature = "password")]
    pub password: PasswordActionRoutes<T>,
    #[cfg(feature = "account")]
    pub account: AccountActionRoutes<T>,
    pub logout: T,
    pub user_verify_session: T,
}

impl Default for Routes<&'static str> {
    fn default() -> Self {
        Routes {
            pages: PageRoutes::default(),
            #[cfg(feature = "oauth")]
            oauth: OAuthRoutes::default(),
            #[cfg(feature = "email")]
            email: EmailActionRoutes::default(),
            #[cfg(feature = "password")]
            password: PasswordActionRoutes::default(),
            #[cfg(feature = "account")]
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
            #[cfg(feature = "oauth")]
            oauth: value.oauth.as_ref().into(),
            #[cfg(feature = "email")]
            email: value.email.as_ref().into(),
            #[cfg(feature = "password")]
            password: value.password.as_ref().into(),
            #[cfg(feature = "account")]
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
            #[cfg(feature = "oauth")]
            oauth: self.oauth.with_prefix(&prefix),
            #[cfg(feature = "email")]
            email: self.email.with_prefix(&prefix),
            #[cfg(feature = "password")]
            password: self.password.with_prefix(&prefix),
            #[cfg(feature = "account")]
            account: self.account.with_prefix(&prefix),
            user_verify_session: format!("{prefix}{}", self.user_verify_session),
            logout: format!("{prefix}{}", self.logout),
        }
    }
}
