use std::fmt::Display;

#[derive(Debug, Clone)]
pub struct PageRoutes<T = &'static str> {
    pub login: T,
    pub signup: T,
    #[cfg(feature = "account")]
    pub user: T,
    #[cfg(feature = "account")]
    pub home: T,
    #[cfg(all(feature = "password", feature = "email"))]
    pub password_send_reset: T,
    #[cfg(all(feature = "password", feature = "email"))]
    pub password_reset: T,
}

impl Default for PageRoutes {
    fn default() -> Self {
        Self {
            login: "/login",
            signup: "/signup",
            #[cfg(feature = "account")]
            user: "/user",
            #[cfg(feature = "account")]
            home: "/",
            #[cfg(all(feature = "password", feature = "email"))]
            password_send_reset: "/password/send-reset",
            #[cfg(all(feature = "password", feature = "email"))]
            password_reset: "/password/reset",
        }
    }
}

impl<'a> From<&'a PageRoutes<String>> for PageRoutes<&'a str> {
    fn from(value: &'a PageRoutes<String>) -> Self {
        Self {
            login: &value.login,
            signup: &value.signup,
            #[cfg(feature = "account")]
            user: &value.user,
            #[cfg(feature = "account")]
            home: &value.home,
            #[cfg(all(feature = "password", feature = "email"))]
            password_send_reset: &value.password_send_reset,
            #[cfg(all(feature = "password", feature = "email"))]
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
            login: format!("{prefix}{}", self.login),
            signup: format!("{prefix}{}", self.signup),
            #[cfg(feature = "account")]
            user: format!("{prefix}{}", self.user),
            #[cfg(feature = "account")]
            home: format!("{prefix}{}", self.home),
            #[cfg(all(feature = "password", feature = "email"))]
            password_send_reset: format!("{prefix}{}", self.password_send_reset),
            #[cfg(all(feature = "password", feature = "email"))]
            password_reset: format!("{prefix}{}", self.password_reset),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RedirectRoutes<T = &'static str> {
    pub post_login: T,
    pub post_logout: T,
}

impl Default for RedirectRoutes {
    fn default() -> Self {
        Self {
            post_login: "/",
            post_logout: "/",
        }
    }
}

impl<'a> From<&'a RedirectRoutes<String>> for RedirectRoutes<&'a str> {
    fn from(value: &'a RedirectRoutes<String>) -> Self {
        Self {
            post_login: &value.post_login,
            post_logout: &value.post_logout,
        }
    }
}

impl From<RedirectRoutes<&str>> for RedirectRoutes<String> {
    fn from(value: RedirectRoutes<&str>) -> Self {
        value.with_prefix("")
    }
}

impl<T: Sized> AsRef<RedirectRoutes<T>> for RedirectRoutes<T> {
    fn as_ref(&self) -> &RedirectRoutes<T> {
        self
    }
}

impl<T: Display> RedirectRoutes<T> {
    pub fn with_prefix(self, prefix: impl Display) -> RedirectRoutes<String> {
        RedirectRoutes {
            post_login: format!("{prefix}{}", self.post_login),
            post_logout: format!("{prefix}{}", self.post_logout),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ActionRoutes<T = &'static str> {
    #[cfg(feature = "email")]
    pub login_email: T,
    #[cfg(feature = "oauth")]
    pub login_oauth: T,
    #[cfg(feature = "oauth")]
    pub login_oauth_provider: T,
    #[cfg(feature = "password")]
    pub login_password: T,
    pub logout: T,
    #[cfg(feature = "email")]
    pub signup_email: T,
    #[cfg(feature = "oauth")]
    pub signup_oauth: T,
    #[cfg(feature = "oauth")]
    pub signup_oauth_provider: T,
    #[cfg(feature = "password")]
    pub signup_password: T,
    #[cfg(feature = "account")]
    pub user_delete: T,
    #[cfg(all(feature = "email", feature = "account"))]
    pub user_email_add: T,
    #[cfg(all(feature = "email", feature = "account"))]
    pub user_email_delete: T,
    #[cfg(all(feature = "email", feature = "account"))]
    pub user_email_disable_login: T,
    #[cfg(all(feature = "email", feature = "account"))]
    pub user_email_enable_login: T,
    #[cfg(feature = "email")]
    pub user_email_verify: T,
    #[cfg(all(feature = "oauth", feature = "account"))]
    pub user_oauth_delete: T,
    #[cfg(feature = "oauth")]
    pub user_oauth_link: T,
    #[cfg(feature = "oauth")]
    pub user_oauth_link_provider: T,
    #[cfg(feature = "oauth")]
    pub user_oauth_refresh: T,
    #[cfg(feature = "oauth")]
    pub user_oauth_refresh_provider: T,
    #[cfg(feature = "account")]
    pub user_password_delete: T,
    #[cfg(feature = "account")]
    pub user_password_set: T,
    #[cfg(feature = "account")]
    pub user_session_delete: T,
    pub user_verify_session: T,
    #[cfg(all(feature = "password", feature = "email"))]
    pub password_reset: T,
    #[cfg(all(feature = "password", feature = "email"))]
    pub password_send_reset: T,
}

impl Default for ActionRoutes {
    fn default() -> Self {
        Self {
            #[cfg(feature = "email")]
            login_email: "/login/email",
            #[cfg(feature = "oauth")]
            login_oauth: "/login/oauth",
            #[cfg(feature = "oauth")]
            login_oauth_provider: "/login/oauth/:provider",
            #[cfg(feature = "password")]
            login_password: "/login/password",
            logout: "/logout",
            #[cfg(feature = "email")]
            signup_email: "/signup/email",
            #[cfg(feature = "oauth")]
            signup_oauth: "/signup/oauth",
            #[cfg(feature = "oauth")]
            signup_oauth_provider: "/signup/oauth/:provider",
            #[cfg(feature = "password")]
            signup_password: "/signup/password",
            #[cfg(feature = "account")]
            user_delete: "/user/delete",
            #[cfg(all(feature = "email", feature = "account"))]
            user_email_add: "/user/email/add",
            #[cfg(all(feature = "email", feature = "account"))]
            user_email_delete: "/user/email/delete",
            #[cfg(all(feature = "email", feature = "account"))]
            user_email_disable_login: "/user/email/disable_login",
            #[cfg(all(feature = "email", feature = "account"))]
            user_email_enable_login: "/user/email/enable_login",
            #[cfg(feature = "email")]
            user_email_verify: "/user/email/verify",
            #[cfg(all(feature = "oauth", feature = "account"))]
            user_oauth_delete: "/user/oauth/delete",
            #[cfg(feature = "oauth")]
            user_oauth_link: "/user/oauth/link",
            #[cfg(feature = "oauth")]
            user_oauth_link_provider: "/user/oauth/link/:provider",
            #[cfg(feature = "oauth")]
            user_oauth_refresh: "/user/oauth/refresh",
            #[cfg(feature = "oauth")]
            user_oauth_refresh_provider: "/user/oauth/refresh/:provider",
            #[cfg(feature = "account")]
            user_password_delete: "/user/password/delete",
            #[cfg(feature = "account")]
            user_password_set: "/user/password/set",
            #[cfg(feature = "account")]
            user_session_delete: "/user/session/delete",
            user_verify_session: "/user/verify-session",
            #[cfg(all(feature = "password", feature = "email"))]
            password_reset: "/password/reset",
            #[cfg(all(feature = "password", feature = "email"))]
            password_send_reset: "/password/send-reset",
        }
    }
}

impl<'a> From<&'a ActionRoutes<String>> for ActionRoutes<&'a str> {
    fn from(value: &'a ActionRoutes<String>) -> Self {
        Self {
            #[cfg(feature = "email")]
            login_email: &value.login_email,
            #[cfg(feature = "oauth")]
            login_oauth: &value.login_oauth,
            #[cfg(feature = "oauth")]
            login_oauth_provider: &value.login_oauth_provider,
            #[cfg(feature = "password")]
            login_password: &value.login_password,
            logout: &value.logout,
            #[cfg(feature = "email")]
            signup_email: &value.signup_email,
            #[cfg(feature = "oauth")]
            signup_oauth: &value.signup_oauth,
            #[cfg(feature = "oauth")]
            signup_oauth_provider: &value.signup_oauth_provider,
            #[cfg(feature = "password")]
            signup_password: &value.signup_password,
            #[cfg(feature = "account")]
            user_delete: &value.user_delete,
            #[cfg(all(feature = "email", feature = "account"))]
            user_email_add: &value.user_email_add,
            #[cfg(all(feature = "email", feature = "account"))]
            user_email_delete: &value.user_email_delete,
            #[cfg(all(feature = "email", feature = "account"))]
            user_email_disable_login: &value.user_email_disable_login,
            #[cfg(all(feature = "email", feature = "account"))]
            user_email_enable_login: &value.user_email_enable_login,
            #[cfg(feature = "email")]
            user_email_verify: &value.user_email_verify,
            #[cfg(all(feature = "oauth", feature = "account"))]
            user_oauth_delete: &value.user_oauth_delete,
            #[cfg(feature = "oauth")]
            user_oauth_link: &value.user_oauth_link,
            #[cfg(feature = "oauth")]
            user_oauth_link_provider: &value.user_oauth_link_provider,
            #[cfg(feature = "oauth")]
            user_oauth_refresh: &value.user_oauth_refresh,
            #[cfg(feature = "oauth")]
            user_oauth_refresh_provider: &value.user_oauth_refresh_provider,
            #[cfg(feature = "account")]
            user_password_delete: &value.user_password_delete,
            #[cfg(feature = "account")]
            user_password_set: &value.user_password_set,
            #[cfg(feature = "account")]
            user_session_delete: &value.user_session_delete,
            user_verify_session: &value.user_verify_session,
            #[cfg(all(feature = "password", feature = "email"))]
            password_reset: &value.password_reset,
            #[cfg(all(feature = "password", feature = "email"))]
            password_send_reset: &value.password_send_reset,
        }
    }
}

impl From<ActionRoutes<&str>> for ActionRoutes<String> {
    fn from(value: ActionRoutes<&str>) -> Self {
        value.with_prefix("")
    }
}

impl<T: Sized> AsRef<ActionRoutes<T>> for ActionRoutes<T> {
    fn as_ref(&self) -> &ActionRoutes<T> {
        self
    }
}

impl<T: Display> ActionRoutes<T> {
    pub fn with_prefix(self, prefix: impl Display) -> ActionRoutes<String> {
        ActionRoutes {
            #[cfg(feature = "password")]
            login_password: format!("{prefix}{}", self.login_password),
            #[cfg(feature = "email")]
            login_email: format!("{prefix}{}", self.login_email),
            #[cfg(feature = "oauth")]
            login_oauth: format!("{prefix}{}", self.login_oauth),
            #[cfg(feature = "oauth")]
            login_oauth_provider: format!("{prefix}{}", self.login_oauth_provider),
            #[cfg(feature = "password")]
            signup_password: format!("{prefix}{}", self.signup_password),
            #[cfg(feature = "email")]
            signup_email: format!("{prefix}{}", self.signup_email),
            #[cfg(feature = "oauth")]
            signup_oauth: format!("{prefix}{}", self.signup_oauth),
            #[cfg(feature = "oauth")]
            signup_oauth_provider: format!("{prefix}{}", self.signup_oauth_provider),
            #[cfg(feature = "account")]
            user_delete: format!("{prefix}{}", self.user_delete),
            logout: format!("{prefix}{}", self.logout),
            user_verify_session: format!("{prefix}{}", self.user_verify_session),
            #[cfg(feature = "account")]
            user_password_set: format!("{prefix}{}", self.user_password_set),
            #[cfg(feature = "account")]
            user_password_delete: format!("{prefix}{}", self.user_password_delete),
            #[cfg(feature = "oauth")]
            user_oauth_link: format!("{prefix}{}", self.user_oauth_link),
            #[cfg(feature = "oauth")]
            user_oauth_link_provider: format!("{prefix}{}", self.user_oauth_link_provider),
            #[cfg(feature = "account")]
            user_session_delete: format!("{prefix}{}", self.user_session_delete),
            #[cfg(feature = "oauth")]
            user_oauth_refresh: format!("{prefix}{}", self.user_oauth_refresh),
            #[cfg(feature = "oauth")]
            user_oauth_refresh_provider: format!("{prefix}{}", self.user_oauth_refresh_provider),
            #[cfg(all(feature = "oauth", feature = "account"))]
            user_oauth_delete: format!("{prefix}{}", self.user_oauth_delete),
            #[cfg(feature = "email")]
            user_email_verify: format!("{prefix}{}", self.user_email_verify),
            #[cfg(all(feature = "email", feature = "account"))]
            user_email_add: format!("{prefix}{}", self.user_email_add),
            #[cfg(all(feature = "email", feature = "account"))]
            user_email_delete: format!("{prefix}{}", self.user_email_delete),
            #[cfg(all(feature = "email", feature = "account"))]
            user_email_enable_login: format!("{prefix}{}", self.user_email_enable_login),
            #[cfg(all(feature = "email", feature = "account"))]
            user_email_disable_login: format!("{prefix}{}", self.user_email_disable_login),
            #[cfg(all(feature = "password", feature = "email"))]
            password_send_reset: format!("{prefix}{}", self.password_send_reset),
            #[cfg(all(feature = "password", feature = "email"))]
            password_reset: format!("{prefix}{}", self.password_reset),
        }
    }
}

#[cfg(feature = "oauth")]
impl<T: AsRef<str>> ActionRoutes<T> {
    pub fn validate_oauth_callback_routes(self) -> Self {
        if [
            self.login_oauth_provider.as_ref(),
            self.signup_oauth_provider.as_ref(),
            self.user_oauth_link_provider.as_ref(),
            self.user_oauth_refresh_provider.as_ref(),
        ]
        .into_iter()
        .any(|r| !r.contains("/:provider"))
        {
            panic!("All oauth callback routes must contain /:provider")
        };

        self
    }
}

#[derive(Debug, Clone)]
pub struct Routes<T = &'static str> {
    pub pages: PageRoutes<T>,
    pub redirects: RedirectRoutes<T>,
    pub actions: ActionRoutes<T>,
}

impl Default for Routes<&'static str> {
    fn default() -> Self {
        Routes {
            pages: PageRoutes::default(),
            redirects: RedirectRoutes::default(),
            actions: ActionRoutes::default(),
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
            redirects: value.redirects.as_ref().into(),
            actions: value.actions.as_ref().into(),
        }
    }
}

impl<T: Display> Routes<T> {
    pub fn with_prefix(self, prefix: impl Display) -> Routes<String> {
        Routes {
            pages: self.pages.with_prefix(&prefix),
            redirects: self.redirects.with_prefix(&prefix),
            actions: self.actions.with_prefix(prefix),
        }
    }
}
