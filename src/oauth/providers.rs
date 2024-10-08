mod github;
mod spotify;

use crate::Allow;
pub use github::GitHubOAuthProvider;
pub use spotify::SpotifyOAuthProvider;

pub trait IncludedProvider {
    fn with_allow_signup(self, allow_signup: Allow) -> Self;
    fn with_allow_login(self, allow_login: Allow) -> Self;
    fn with_allow_linking(self, allow_linking: bool) -> Self;
    fn with_scopes(self, scopes: Vec<String>) -> Self;
}
