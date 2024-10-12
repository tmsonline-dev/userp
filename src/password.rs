mod login;
mod signup;

pub use login::*;
pub use signup::*;

use crate::Allow;

#[cfg(feature = "email")]
#[derive(Clone, PartialEq, Eq)]
pub enum PasswordReset {
    Never,
    VerifiedEmailOnly,
    AnyUserEmail,
}

#[derive(Clone)]
pub struct PasswordConfig {
    pub allow_login: Option<Allow>,
    pub allow_signup: Option<Allow>,
    #[cfg(feature = "email")]
    pub allow_reset: PasswordReset,
}

impl PasswordConfig {
    pub fn new() -> Self {
        Self {
            allow_login: None,
            allow_signup: None,
            #[cfg(feature = "email")]
            allow_reset: PasswordReset::VerifiedEmailOnly,
        }
    }

    pub fn with_allow_signup(mut self, allow_signup: Allow) -> Self {
        self.allow_signup = Some(allow_signup);
        self
    }

    pub fn with_allow_login(mut self, allow_login: Allow) -> Self {
        self.allow_login = Some(allow_login);
        self
    }

    #[cfg(feature = "email")]
    pub fn with_allow_reset(mut self, allow_reset: PasswordReset) -> Self {
        self.allow_reset = allow_reset;
        self
    }
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self::new()
    }
}
