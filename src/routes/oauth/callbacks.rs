use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OAuthCallbackRoutes<T = &'static str> {
    pub login_oauth_provider: T,
    pub signup_oauth_provider: T,
    pub user_oauth_link_provider: T,
    pub user_oauth_refresh_provider: T,
}

impl Default for OAuthCallbackRoutes {
    fn default() -> Self {
        Self {
            login_oauth_provider: "/login/oauth/:provider",
            signup_oauth_provider: "/signup/oauth/:provider",
            user_oauth_link_provider: "/user/oauth/link/:provider",
            user_oauth_refresh_provider: "/user/oauth/refresh/:provider",
        }
    }
}

impl<'a> From<&'a OAuthCallbackRoutes<String>> for OAuthCallbackRoutes<&'a str> {
    fn from(value: &'a OAuthCallbackRoutes<String>) -> Self {
        Self {
            login_oauth_provider: &value.login_oauth_provider,
            signup_oauth_provider: &value.signup_oauth_provider,
            user_oauth_link_provider: &value.user_oauth_link_provider,
            user_oauth_refresh_provider: &value.user_oauth_refresh_provider,
        }
    }
}

impl From<OAuthCallbackRoutes<&str>> for OAuthCallbackRoutes<String> {
    fn from(value: OAuthCallbackRoutes<&str>) -> Self {
        value.with_prefix("")
    }
}

impl<T: Sized> AsRef<OAuthCallbackRoutes<T>> for OAuthCallbackRoutes<T> {
    fn as_ref(&self) -> &OAuthCallbackRoutes<T> {
        self
    }
}

impl<T: Display> OAuthCallbackRoutes<T> {
    pub fn with_prefix(self, prefix: impl Display) -> OAuthCallbackRoutes<String> {
        OAuthCallbackRoutes {
            login_oauth_provider: format!("{prefix}{}", self.login_oauth_provider),
            signup_oauth_provider: format!("{prefix}{}", self.signup_oauth_provider),
            user_oauth_link_provider: format!("{prefix}{}", self.user_oauth_link_provider),
            user_oauth_refresh_provider: format!("{prefix}{}", self.user_oauth_refresh_provider),
        }
    }
}

impl<T: AsRef<str>> OAuthCallbackRoutes<T> {
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
