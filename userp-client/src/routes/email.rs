use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EmailActionRoutes<T = &'static str> {
    pub login_email: T,
    pub signup_email: T,
    pub user_email_verify: T,
    #[cfg(feature = "password")]
    pub password_reset: T,
    #[cfg(feature = "password")]
    pub password_reset_callback: T,
    #[cfg(feature = "password")]
    pub password_send_reset: T,
}

impl Default for EmailActionRoutes {
    fn default() -> Self {
        Self {
            login_email: "/login/email",
            signup_email: "/signup/email",
            user_email_verify: "/user/email/verify",
            #[cfg(feature = "password")]
            password_reset: "/password/reset",
            #[cfg(feature = "password")]
            password_reset_callback: "/password/reset-callback",
            #[cfg(feature = "password")]
            password_send_reset: "/password/send-reset",
        }
    }
}

impl<'a> From<&'a EmailActionRoutes<String>> for EmailActionRoutes<&'a str> {
    fn from(value: &'a EmailActionRoutes<String>) -> Self {
        Self {
            login_email: &value.login_email,
            signup_email: &value.signup_email,
            user_email_verify: &value.user_email_verify,
            #[cfg(feature = "password")]
            password_reset: &value.password_reset,
            #[cfg(feature = "password")]
            password_reset_callback: &value.password_reset_callback,
            #[cfg(feature = "password")]
            password_send_reset: &value.password_send_reset,
        }
    }
}

impl From<EmailActionRoutes<&str>> for EmailActionRoutes<String> {
    fn from(value: EmailActionRoutes<&str>) -> Self {
        value.with_prefix("")
    }
}

impl<T: Sized> AsRef<EmailActionRoutes<T>> for EmailActionRoutes<T> {
    fn as_ref(&self) -> &EmailActionRoutes<T> {
        self
    }
}

impl<T: Display> EmailActionRoutes<T> {
    pub fn with_prefix(self, prefix: impl Display) -> EmailActionRoutes<String> {
        EmailActionRoutes {
            login_email: format!("{prefix}{}", self.login_email),
            signup_email: format!("{prefix}{}", self.signup_email),
            user_email_verify: format!("{prefix}{}", self.user_email_verify),
            #[cfg(feature = "password")]
            password_send_reset: format!("{prefix}{}", self.password_send_reset),
            #[cfg(feature = "password")]
            password_reset: format!("{prefix}{}", self.password_reset),
            #[cfg(feature = "password")]
            password_reset_callback: format!("{prefix}{}", self.password_reset_callback),
        }
    }
}
