use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountActionRoutes<T = &'static str> {
    pub user_delete: T,
    pub user_session_delete: T,
    #[cfg(feature = "client-email")]
    pub user_email_add: T,
    #[cfg(feature = "client-email")]
    pub user_email_delete: T,
    #[cfg(feature = "client-email")]
    pub user_email_disable_login: T,
    #[cfg(feature = "client-email")]
    pub user_email_enable_login: T,
    #[cfg(feature = "client-oauth")]
    pub user_oauth_delete: T,
    #[cfg(feature = "client-password")]
    pub user_password_delete: T,
    #[cfg(feature = "client-password")]
    pub user_password_set: T,
}

impl Default for AccountActionRoutes {
    fn default() -> Self {
        Self {
            user_delete: "/user/delete",
            user_session_delete: "/user/session/delete",
            #[cfg(feature = "client-email")]
            user_email_add: "/user/email/add",
            #[cfg(feature = "client-email")]
            user_email_delete: "/user/email/delete",
            #[cfg(feature = "client-email")]
            user_email_disable_login: "/user/email/disable_login",
            #[cfg(feature = "client-email")]
            user_email_enable_login: "/user/email/enable_login",
            #[cfg(feature = "client-oauth")]
            user_oauth_delete: "/user/oauth/delete",
            #[cfg(feature = "client-password")]
            user_password_delete: "/user/password/delete",
            #[cfg(feature = "client-password")]
            user_password_set: "/user/password/set",
        }
    }
}

impl<'a> From<&'a AccountActionRoutes<String>> for AccountActionRoutes<&'a str> {
    fn from(value: &'a AccountActionRoutes<String>) -> Self {
        Self {
            user_delete: &value.user_delete,
            user_session_delete: &value.user_session_delete,
            #[cfg(feature = "client-email")]
            user_email_add: &value.user_email_add,
            #[cfg(feature = "client-email")]
            user_email_delete: &value.user_email_delete,
            #[cfg(feature = "client-email")]
            user_email_disable_login: &value.user_email_disable_login,
            #[cfg(feature = "client-email")]
            user_email_enable_login: &value.user_email_enable_login,
            #[cfg(feature = "client-oauth")]
            user_oauth_delete: &value.user_oauth_delete,
            #[cfg(feature = "client-password")]
            user_password_delete: &value.user_password_delete,
            #[cfg(feature = "client-password")]
            user_password_set: &value.user_password_set,
        }
    }
}

impl From<AccountActionRoutes<&str>> for AccountActionRoutes<String> {
    fn from(value: AccountActionRoutes<&str>) -> Self {
        value.with_prefix("")
    }
}

impl<T: Sized> AsRef<AccountActionRoutes<T>> for AccountActionRoutes<T> {
    fn as_ref(&self) -> &AccountActionRoutes<T> {
        self
    }
}

impl<T: Display> AccountActionRoutes<T> {
    pub fn with_prefix(self, prefix: impl Display) -> AccountActionRoutes<String> {
        AccountActionRoutes {
            user_delete: format!("{prefix}{}", self.user_delete),
            user_session_delete: format!("{prefix}{}", self.user_session_delete),
            #[cfg(feature = "client-password")]
            user_password_set: format!("{prefix}{}", self.user_password_set),
            #[cfg(feature = "client-password")]
            user_password_delete: format!("{prefix}{}", self.user_password_delete),
            #[cfg(feature = "client-oauth")]
            user_oauth_delete: format!("{prefix}{}", self.user_oauth_delete),
            #[cfg(feature = "client-email")]
            user_email_add: format!("{prefix}{}", self.user_email_add),
            #[cfg(feature = "client-email")]
            user_email_delete: format!("{prefix}{}", self.user_email_delete),
            #[cfg(feature = "client-email")]
            user_email_enable_login: format!("{prefix}{}", self.user_email_enable_login),
            #[cfg(feature = "client-email")]
            user_email_disable_login: format!("{prefix}{}", self.user_email_disable_login),
        }
    }
}
