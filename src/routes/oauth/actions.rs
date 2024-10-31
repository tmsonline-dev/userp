use std::fmt::Display;

#[derive(Debug, Clone)]
pub struct OAuthActionRoutes<T = &'static str> {
    pub login_oauth: T,
    pub signup_oauth: T,
    pub user_oauth_link: T,
    pub user_oauth_refresh: T,
}

impl Default for OAuthActionRoutes {
    fn default() -> Self {
        Self {
            login_oauth: "/login/oauth",
            signup_oauth: "/signup/oauth",
            user_oauth_link: "/user/oauth/link",
            user_oauth_refresh: "/user/oauth/refresh",
        }
    }
}

impl<'a> From<&'a OAuthActionRoutes<String>> for OAuthActionRoutes<&'a str> {
    fn from(value: &'a OAuthActionRoutes<String>) -> Self {
        Self {
            login_oauth: &value.login_oauth,
            signup_oauth: &value.signup_oauth,
            user_oauth_link: &value.user_oauth_link,
            user_oauth_refresh: &value.user_oauth_refresh,
        }
    }
}

impl From<OAuthActionRoutes<&str>> for OAuthActionRoutes<String> {
    fn from(value: OAuthActionRoutes<&str>) -> Self {
        value.with_prefix("")
    }
}

impl<T: Sized> AsRef<OAuthActionRoutes<T>> for OAuthActionRoutes<T> {
    fn as_ref(&self) -> &OAuthActionRoutes<T> {
        self
    }
}

impl<T: Display> OAuthActionRoutes<T> {
    pub fn with_prefix(self, prefix: impl Display) -> OAuthActionRoutes<String> {
        OAuthActionRoutes {
            login_oauth: format!("{prefix}{}", self.login_oauth),
            signup_oauth: format!("{prefix}{}", self.signup_oauth),
            user_oauth_link: format!("{prefix}{}", self.user_oauth_link),
            user_oauth_refresh: format!("{prefix}{}", self.user_oauth_refresh),
        }
    }
}
