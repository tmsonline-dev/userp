use password_auth::{generate_hash, verify_password};
use tokio::task;

pub async fn verify(password: String, hash: String) -> bool {
    task::spawn_blocking(move || verify_password(password, hash.as_str()).is_ok())
        .await
        .expect("Join error")
}

pub async fn hash(password: String) -> String {
    task::spawn_blocking(|| generate_hash(password))
        .await
        .expect("Join error")
}
