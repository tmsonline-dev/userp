use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PasswordActionRoutes<T = &'static str> {
    pub login_password: T,
    pub signup_password: T,
}

impl Default for PasswordActionRoutes {
    fn default() -> Self {
        Self {
            login_password: "/login/password",
            signup_password: "/signup/password",
        }
    }
}

impl<'a> From<&'a PasswordActionRoutes<String>> for PasswordActionRoutes<&'a str> {
    fn from(value: &'a PasswordActionRoutes<String>) -> Self {
        Self {
            login_password: &value.login_password,
            signup_password: &value.signup_password,
        }
    }
}

impl From<PasswordActionRoutes<&str>> for PasswordActionRoutes<String> {
    fn from(value: PasswordActionRoutes<&str>) -> Self {
        value.with_prefix("")
    }
}

impl<T: Sized> AsRef<PasswordActionRoutes<T>> for PasswordActionRoutes<T> {
    fn as_ref(&self) -> &PasswordActionRoutes<T> {
        self
    }
}

impl<T: Display> PasswordActionRoutes<T> {
    pub fn with_prefix(self, prefix: impl Display) -> PasswordActionRoutes<String> {
        PasswordActionRoutes {
            login_password: format!("{prefix}{}", self.login_password),
            signup_password: format!("{prefix}{}", self.signup_password),
        }
    }
}
