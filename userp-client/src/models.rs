use serde::{Deserialize, Serialize};
use std::fmt::Display;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Copy)]
pub enum Allow {
    Never,
    OnSelf,
    OnEither,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum LoginMethod {
    #[cfg(feature = "password")]
    Password,
    #[cfg(all(feature = "password", feature = "email"))]
    PasswordReset { address: String },
    #[cfg(feature = "email")]
    Email { address: String },
    #[cfg(feature = "oauth-callbacks")]
    OAuth { token_id: Uuid },
}

impl Display for LoginMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{self:#?}"))
    }
}
