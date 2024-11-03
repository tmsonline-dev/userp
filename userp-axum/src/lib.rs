pub mod cookies;
pub mod extract;
#[cfg(any(
    feature = "oauth-callbacks",
    feature = "email",
    feature = "password",
    feature = "pages",
    feature = "account"
))]
pub mod router;

use cookies::AxumUserpCookies;
use userp_server::Userp as CoreUserp;

pub type Userp<S> = CoreUserp<S, AxumUserpCookies>;
