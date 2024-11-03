#[cfg(feature = "server-email")]
use crate::server::email::EmailConfig;
#[cfg(feature = "server-oauth-callbacks")]
use crate::server::oauth::OAuthConfig;
#[cfg(feature = "server-password")]
use crate::server::password::PasswordConfig;
use crate::{models::Allow, routes::Routes};

#[derive(Clone)]
pub struct UserpConfig {
    pub key: String,
    pub allow_signup: Allow,
    pub allow_login: Allow,
    pub https_only: bool,
    pub routes: Routes<String>,
    #[cfg(feature = "server-password")]
    pub pass: PasswordConfig,
    #[cfg(feature = "server-email")]
    pub email: EmailConfig,
    #[cfg(feature = "server-oauth-callbacks")]
    pub oauth: OAuthConfig,
}

impl UserpConfig {
    pub fn new(
        key: String,
        routes: impl Into<Routes<String>>,
        #[cfg(feature = "server-password")] pass: PasswordConfig,
        #[cfg(feature = "server-email")] email: EmailConfig,
        #[cfg(feature = "server-oauth-callbacks")] oauth: OAuthConfig,
    ) -> Self {
        Self {
            key,
            https_only: true,
            allow_signup: Allow::OnSelf,
            allow_login: Allow::OnSelf,
            routes: routes.into(),
            #[cfg(feature = "server-password")]
            pass,
            #[cfg(feature = "server-email")]
            email,
            #[cfg(feature = "server-oauth-callbacks")]
            oauth,
        }
    }

    pub fn with_https_only(mut self, https_only: bool) -> Self {
        self.https_only = https_only;
        self
    }

    pub fn with_allow_signup(mut self, allow_signup: Allow) -> Self {
        self.allow_signup = allow_signup;
        self
    }

    pub fn with_allow_login(mut self, allow_login: Allow) -> Self {
        self.allow_login = allow_login;
        self
    }
}
