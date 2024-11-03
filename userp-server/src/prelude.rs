#[cfg(feature = "axum")]
pub use crate::axum::{cookies::*, AxumUserp};

#[cfg(all(feature = "email", feature = "password"))]
pub use crate::email::reset::*;
#[cfg(all(feature = "email", feature = "password"))]
pub use crate::password::PasswordReset;

#[cfg(feature = "email")]
pub use crate::email::{
    login::*, signup::*, verify::*, EmailConfig, SendEmailChallengeError, SmtpSettings,
};

#[cfg(feature = "password")]
pub use crate::password::{hasher::*, login::*, signup::*, PasswordConfig};

#[cfg(feature = "oauth-callbacks")]
pub use crate::oauth::{
    client::*,
    link::*,
    login::*,
    provider::{
        custom::*, github::*, gitlab::*, google::*, oidc::*, spotify::*, ExchangeResult,
        OAuthProvider,
    },
    refresh::*,
    signup::*,
    OAuthCallbackError, OAuthConfig, OAuthFlow, OAuthGenericCallbackError, OAuthProviders,
    RefreshInitResult,
};

#[cfg(feature = "email")]
pub use crate::models::email::*;
#[cfg(feature = "oauth-callbacks")]
pub use crate::models::oauth::*;
pub use crate::models::{LoginSession, User, UserpCookies};

pub use crate::{config::*, constants::*, core::*, reexports::*, store::*, Userp};
