use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct NewPasswordForm {
    pub new_password: String,
}

#[derive(Serialize, Deserialize)]
pub struct EmailForm {
    pub email: String,
}
