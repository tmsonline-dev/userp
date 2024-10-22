#[derive(Debug, Clone)]
pub struct Routes<T = &'static str> {
    pub home: T,
    pub login: T,
    pub login_password: T,
    pub login_email: T,
    pub login_oauth: T,
    pub login_oauth_provider: T,
    pub signup: T,
    pub signup_password: T,
    pub signup_email: T,
    pub signup_oauth: T,
    pub signup_oauth_provider: T,
    pub user: T,
    pub user_delete: T,
    pub logout: T,
    pub post_logout: T,
    pub post_login: T,
    pub user_verify_session: T,
    pub user_password_set: T,
    pub user_password_delete: T,
    pub user_oauth_link: T,
    pub user_oauth_link_provider: T,
    pub user_session_delete: T,
    pub user_oauth_refresh: T,
    pub user_oauth_refresh_provider: T,
    pub user_oauth_delete: T,
    pub user_email_verify: T,
    pub user_email_add: T,
    pub user_email_delete: T,
    pub user_email_enable_login: T,
    pub user_email_disable_login: T,
    pub password_send_reset: T,
    pub password_reset: T,
}

impl Default for Routes<&'static str> {
    fn default() -> Self {
        Routes {
            home: "/",
            login: "/login",
            logout: "/logout",
            post_logout: "/",
            post_login: "/",
            login_password: "/login/password",
            login_email: "/login/email",
            login_oauth: "/login/oauth",
            login_oauth_provider: "/login/oauth/:provider",
            signup: "/signup",
            signup_password: "/signup/password",
            signup_email: "/signup/email",
            signup_oauth: "/signup/oauth",
            signup_oauth_provider: "/signup/oauth/:provider",
            user: "/user",
            user_delete: "/user/delete",
            user_verify_session: "/user/verify-session",
            user_password_set: "/user/password/set",
            user_password_delete: "/user/password/delete",
            user_oauth_link: "/user/oauth/link",
            user_oauth_link_provider: "/user/oauth/link/:provider",
            user_session_delete: "/user/session/delete",
            user_oauth_refresh: "/user/oauth/refresh",
            user_oauth_refresh_provider: "/user/oauth/refresh/:provider",
            user_oauth_delete: "/user/oauth/delete",
            user_email_verify: "/user/email/verify",
            user_email_add: "/user/email/add",
            user_email_delete: "/user/email/delete",
            user_email_enable_login: "/user/email/enable_login",
            user_email_disable_login: "/user/email/disable_login",
            password_send_reset: "/password/send-reset",
            password_reset: "/password/reset",
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
            home: &value.home,
            login: &value.login,
            login_password: &value.login_password,
            login_email: &value.login_email,
            login_oauth: &value.login_oauth,
            login_oauth_provider: &value.login_oauth_provider,
            signup: &value.signup,
            signup_password: &value.signup_password,
            signup_email: &value.signup_email,
            signup_oauth: &value.signup_oauth,
            signup_oauth_provider: &value.signup_oauth_provider,
            user: &value.user,
            user_delete: &value.user_delete,
            logout: &value.logout,
            post_logout: &value.post_logout,
            post_login: &value.post_login,
            user_verify_session: &value.user_verify_session,
            user_password_set: &value.user_password_set,
            user_password_delete: &value.user_password_delete,
            user_oauth_link: &value.user_oauth_link,
            user_oauth_link_provider: &value.user_oauth_link_provider,
            user_session_delete: &value.user_session_delete,
            user_oauth_refresh: &value.user_oauth_refresh,
            user_oauth_refresh_provider: &value.user_oauth_refresh_provider,
            user_oauth_delete: &value.user_oauth_delete,
            user_email_verify: &value.user_email_verify,
            user_email_add: &value.user_email_add,
            user_email_delete: &value.user_email_delete,
            user_email_enable_login: &value.user_email_enable_login,
            user_email_disable_login: &value.user_email_disable_login,
            password_send_reset: &value.password_send_reset,
            password_reset: &value.password_reset,
        }
    }
}

impl Routes<&'static str> {
    /// Adds a prefix to all routes EXCEPT home, post_logout or post_login
    pub fn with_prefix(self, prefix: &'static str) -> Routes<String> {
        if !prefix.is_empty() && !prefix.starts_with('/') {
            panic!("Prefix must be empty or start with /");
        }

        if prefix.ends_with('/') {
            panic!("Prefix must not end with /")
        }

        if [
            self.login_oauth_provider,
            self.signup_oauth_provider,
            self.user_oauth_link_provider,
            self.user_oauth_refresh_provider,
        ]
        .into_iter()
        .any(|r| !r.contains("/:provider"))
        {
            panic!("All oauth callback routes must contain /:provider")
        };

        Routes {
            home: self.home.to_string(),
            post_logout: self.post_logout.to_string(),
            post_login: self.post_login.to_string(),

            login: format!("{prefix}{}", self.login),
            login_password: format!("{prefix}{}", self.login_password),
            login_email: format!("{prefix}{}", self.login_email),
            login_oauth: format!("{prefix}{}", self.login_oauth),
            login_oauth_provider: format!("{prefix}{}", self.login_oauth_provider),
            signup: format!("{prefix}{}", self.signup),
            signup_password: format!("{prefix}{}", self.signup_password),
            signup_email: format!("{prefix}{}", self.signup_email),
            signup_oauth: format!("{prefix}{}", self.signup_oauth),
            signup_oauth_provider: format!("{prefix}{}", self.signup_oauth_provider),
            user: format!("{prefix}{}", self.user),
            user_delete: format!("{prefix}{}", self.user_delete),
            logout: format!("{prefix}{}", self.logout),
            user_verify_session: format!("{prefix}{}", self.user_verify_session),
            user_password_set: format!("{prefix}{}", self.user_password_set),
            user_password_delete: format!("{prefix}{}", self.user_password_delete),
            user_oauth_link: format!("{prefix}{}", self.user_oauth_link),
            user_oauth_link_provider: format!("{prefix}{}", self.user_oauth_link_provider),
            user_session_delete: format!("{prefix}{}", self.user_session_delete),
            user_oauth_refresh: format!("{prefix}{}", self.user_oauth_refresh),
            user_oauth_refresh_provider: format!("{prefix}{}", self.user_oauth_refresh_provider),
            user_oauth_delete: format!("{prefix}{}", self.user_oauth_delete),
            user_email_verify: format!("{prefix}{}", self.user_email_verify),
            user_email_add: format!("{prefix}{}", self.user_email_add),
            user_email_delete: format!("{prefix}{}", self.user_email_delete),
            user_email_enable_login: format!("{prefix}{}", self.user_email_enable_login),
            user_email_disable_login: format!("{prefix}{}", self.user_email_disable_login),
            password_send_reset: format!("{prefix}{}", self.password_send_reset),
            password_reset: format!("{prefix}{}", self.password_reset),
        }
    }
}
