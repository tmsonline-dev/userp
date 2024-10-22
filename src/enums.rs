use std::fmt::Display;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginMethod {
    #[cfg(feature = "password")]
    Password,
    #[cfg(all(feature = "password", feature = "email"))]
    PasswordReset { address: String },
    #[cfg(feature = "email")]
    Email { address: String },
    #[cfg(feature = "oauth")]
    OAuth { token_id: Uuid },
}

impl Display for LoginMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{self:#?}"))
    }
}
