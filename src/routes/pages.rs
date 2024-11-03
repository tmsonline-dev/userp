use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PageRoutes<T = &'static str> {
    pub post_login: T,
    pub post_logout: T,
    pub login: T,
    pub signup: T,
    #[cfg(feature = "client-account")]
    pub user: T,
    #[cfg(feature = "client-account")]
    pub home: T,
    #[cfg(all(feature = "client-password", feature = "client-email"))]
    pub password_send_reset: T,
    #[cfg(all(feature = "client-password", feature = "client-email"))]
    pub password_reset: T,
}

impl Default for PageRoutes {
    fn default() -> Self {
        Self {
            post_login: "/",
            post_logout: "/",
            login: "/login",
            signup: "/signup",
            #[cfg(feature = "client-account")]
            user: "/user",
            #[cfg(feature = "client-account")]
            home: "/",
            #[cfg(all(feature = "client-password", feature = "client-email"))]
            password_send_reset: "/password/send-reset",
            #[cfg(all(feature = "client-password", feature = "client-email"))]
            password_reset: "/password/reset",
        }
    }
}

impl<'a> From<&'a PageRoutes<String>> for PageRoutes<&'a str> {
    fn from(value: &'a PageRoutes<String>) -> Self {
        Self {
            post_login: &value.post_login,
            post_logout: &value.post_logout,
            login: &value.login,
            signup: &value.signup,
            #[cfg(feature = "client-account")]
            user: &value.user,
            #[cfg(feature = "client-account")]
            home: &value.home,
            #[cfg(all(feature = "client-password", feature = "client-email"))]
            password_send_reset: &value.password_send_reset,
            #[cfg(all(feature = "client-password", feature = "client-email"))]
            password_reset: &value.password_reset,
        }
    }
}

impl From<PageRoutes<&str>> for PageRoutes<String> {
    fn from(value: PageRoutes<&str>) -> Self {
        value.with_prefix("")
    }
}

impl<T: Sized> AsRef<PageRoutes<T>> for PageRoutes<T> {
    fn as_ref(&self) -> &PageRoutes<T> {
        self
    }
}

impl<T: Display> PageRoutes<T> {
    pub fn with_prefix(self, prefix: impl Display) -> PageRoutes<String> {
        PageRoutes {
            post_login: format!("{prefix}{}", self.post_login),
            post_logout: format!("{prefix}{}", self.post_logout),
            login: format!("{prefix}{}", self.login),
            signup: format!("{prefix}{}", self.signup),
            #[cfg(feature = "client-account")]
            user: format!("{prefix}{}", self.user),
            #[cfg(feature = "client-account")]
            home: format!("{prefix}{}", self.home),
            #[cfg(all(feature = "client-password", feature = "client-email"))]
            password_send_reset: format!("{prefix}{}", self.password_send_reset),
            #[cfg(all(feature = "client-password", feature = "client-email"))]
            password_reset: format!("{prefix}{}", self.password_reset),
        }
    }
}
