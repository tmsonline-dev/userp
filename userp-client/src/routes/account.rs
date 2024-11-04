//! Contains AccountActionRoutes and associated helper functions

use serde::{Deserialize, Serialize};
use std::fmt::Display;

/// Contains routes used to control the user account and associated entities
/// that are not specifically required by the login/signup flows
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountActionRoutes<T = &'static str> {
    /// Post route to delete a user account
    pub user_delete: T,
    /// Post route to delete a login session
    pub user_session_delete: T,
    /// Post route to add a user email
    #[cfg(feature = "email")]
    pub user_email_add: T,
    /// Post route to delete a user email
    #[cfg(feature = "email")]
    pub user_email_delete: T,
    /// Post route to disable Email login for a User Email
    #[cfg(feature = "email")]
    pub user_email_disable_login: T,
    /// Post route to enable Email login for a User Email
    #[cfg(feature = "email")]
    pub user_email_enable_login: T,
    /// Post route to delete an OAuth token
    #[cfg(feature = "oauth-callbacks")]
    pub user_oauth_delete: T,
    #[cfg(feature = "password")]
    /// Post route to remove the users password
    pub user_password_delete: T,
    #[cfg(feature = "password")]
    /// Post route to set the users password
    pub user_password_set: T,
}

impl Default for AccountActionRoutes {
    fn default() -> Self {
        Self {
            user_delete: "/user/delete",
            user_session_delete: "/user/session/delete",
            #[cfg(feature = "email")]
            user_email_add: "/user/email/add",
            #[cfg(feature = "email")]
            user_email_delete: "/user/email/delete",
            #[cfg(feature = "email")]
            user_email_disable_login: "/user/email/disable_login",
            #[cfg(feature = "email")]
            user_email_enable_login: "/user/email/enable_login",
            #[cfg(feature = "oauth-callbacks")]
            user_oauth_delete: "/user/oauth/delete",
            #[cfg(feature = "password")]
            user_password_delete: "/user/password/delete",
            #[cfg(feature = "password")]
            user_password_set: "/user/password/set",
        }
    }
}

impl<'a> From<&'a AccountActionRoutes<String>> for AccountActionRoutes<&'a str> {
    fn from(value: &'a AccountActionRoutes<String>) -> Self {
        Self {
            user_delete: &value.user_delete,
            user_session_delete: &value.user_session_delete,
            #[cfg(feature = "email")]
            user_email_add: &value.user_email_add,
            #[cfg(feature = "email")]
            user_email_delete: &value.user_email_delete,
            #[cfg(feature = "email")]
            user_email_disable_login: &value.user_email_disable_login,
            #[cfg(feature = "email")]
            user_email_enable_login: &value.user_email_enable_login,
            #[cfg(feature = "oauth-callbacks")]
            user_oauth_delete: &value.user_oauth_delete,
            #[cfg(feature = "password")]
            user_password_delete: &value.user_password_delete,
            #[cfg(feature = "password")]
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
    /// Adds a prefix to all routes. Unless empty, a prefix needs to start with a slash, and can not end with one.
    pub fn with_prefix(self, prefix: impl Display) -> AccountActionRoutes<String> {
        AccountActionRoutes {
            user_delete: format!("{prefix}{}", self.user_delete),
            user_session_delete: format!("{prefix}{}", self.user_session_delete),
            #[cfg(feature = "password")]
            user_password_set: format!("{prefix}{}", self.user_password_set),
            #[cfg(feature = "password")]
            user_password_delete: format!("{prefix}{}", self.user_password_delete),
            #[cfg(feature = "oauth-callbacks")]
            user_oauth_delete: format!("{prefix}{}", self.user_oauth_delete),
            #[cfg(feature = "email")]
            user_email_add: format!("{prefix}{}", self.user_email_add),
            #[cfg(feature = "email")]
            user_email_delete: format!("{prefix}{}", self.user_email_delete),
            #[cfg(feature = "email")]
            user_email_enable_login: format!("{prefix}{}", self.user_email_enable_login),
            #[cfg(feature = "email")]
            user_email_disable_login: format!("{prefix}{}", self.user_email_disable_login),
        }
    }
}
