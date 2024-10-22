pub use crate::config::*;
#[cfg(all(feature = "password", feature = "email"))]
pub use crate::email::reset::EmailResetError;
#[cfg(feature = "email")]
pub use crate::email::{
    login::EmailLoginError, signup::EmailSignupError, verify::EmailVerifyError, EmailChallenge,
    EmailConfig, SmtpSettings, UserEmail,
};
pub use crate::enums::*;
#[cfg(feature = "oauth")]
pub use crate::oauth::{
    link::OAuthLinkError,
    login::OAuthLoginError,
    provider::{github::GitHubOAuthProvider, spotify::SpotifyOAuthProvider},
    signup::OAuthSignupError,
    OAuthConfig, OAuthProviderUser, OAuthProviders, OAuthToken, RefreshInitResult,
    UnmatchedOAuthToken,
};
#[cfg(all(feature = "password", feature = "email"))]
pub use crate::password::PasswordReset;
#[cfg(feature = "password")]
pub use crate::password::{login::PasswordLoginError, signup::PasswordSignupError, PasswordConfig};
pub use crate::routes::*;
pub use crate::traits::*;
