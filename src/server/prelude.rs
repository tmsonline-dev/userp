#[cfg(feature = "axum-router-account")]
pub use crate::server::axum::router::account::*;
#[cfg(feature = "axum-router-email")]
pub use crate::server::axum::router::email::*;
#[cfg(feature = "axum-router-oauth-callbacks")]
pub use crate::server::axum::router::oauth::*;
#[cfg(feature = "axum-router-pages")]
pub use crate::server::axum::router::pages::*;
#[cfg(feature = "axum-router-password")]
pub use crate::server::axum::router::password::*;
#[cfg(feature = "axum")]
pub use crate::server::axum::{cookies::*, AxumUserp};

#[cfg(all(feature = "server-email", feature = "server-password"))]
pub use crate::server::email::reset::*;
#[cfg(all(feature = "server-email", feature = "server-password"))]
pub use crate::server::password::PasswordReset;

#[cfg(feature = "server-email")]
pub use crate::server::email::{
    login::*, signup::*, verify::*, EmailConfig, SendEmailChallengeError, SmtpSettings,
};

#[cfg(feature = "server-pages")]
pub use crate::server::pages::*;

#[cfg(feature = "server-password")]
pub use crate::server::password::{hasher::*, login::*, signup::*, PasswordConfig};

#[cfg(feature = "server-oauth-callbacks")]
pub use crate::server::oauth::{
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

pub use crate::server::{config::*, constants::*, core::*, reexports::*, store::*, Userp};
