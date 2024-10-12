mod store;

use self::store::MemoryStore;

use askama_axum::IntoResponse;
use axum::{extract::State, response::Redirect, routing::get, serve, Router};
use axum_macros::FromRef;
use axum_user::{
    chrono::{DateTime, Utc},
    provider::{GitHubOAuthProvider, SpotifyOAuthProvider},
    url::Url,
    uuid::Uuid,
    AxumUser, AxumUserConfig, EmailChallenge, EmailConfig, EmailPaths, Key, LoginMethod,
    LoginSession, OAuthConfig, OAuthPaths, OAuthToken, PasswordConfig, SmtpSettings, User,
    UserEmail,
};
use dotenv::var;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;

#[derive(Debug, Clone)]
pub struct MyUser {
    id: Uuid,
    password: Option<String>,
    emails: Vec<MyUserEmail>,
}

impl User for MyUser {
    fn get_password_hash(&self) -> Option<String> {
        self.password.clone()
    }

    fn get_id(&self) -> Uuid {
        self.id
    }
}

#[derive(Debug, Clone)]
pub struct MyUserEmail {
    email: String,
    verified: bool,
    allow_link_login: bool,
}

impl UserEmail for MyUserEmail {
    fn address(&self) -> String {
        self.email.clone()
    }

    fn verified(&self) -> bool {
        self.verified
    }

    fn allow_link_login(&self) -> bool {
        self.allow_link_login
    }
}

#[derive(Debug, Clone)]
pub struct MyLoginSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub method: LoginMethod,
}

impl LoginSession for MyLoginSession {
    fn get_id(&self) -> Uuid {
        self.id
    }

    fn get_user_id(&self) -> Uuid {
        self.user_id
    }

    fn get_method(&self) -> LoginMethod {
        self.method.clone()
    }
}

#[derive(Clone, Debug)]
pub struct MyEmailChallenge {
    pub address: String,
    pub code: String,
    pub next: Option<String>,
    pub expires: DateTime<Utc>,
}

impl EmailChallenge for MyEmailChallenge {
    fn address(&self) -> String {
        self.address.clone()
    }

    fn code(&self) -> String {
        self.code.clone()
    }

    fn next(&self) -> Option<String> {
        self.next.clone()
    }

    fn expires(&self) -> DateTime<Utc> {
        self.expires
    }
}

#[derive(Clone, Debug)]
pub struct MyOAuthToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider_name: String,
    pub provider_user_id: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
}

impl OAuthToken for MyOAuthToken {
    fn id(&self) -> Uuid {
        self.id
    }

    fn user_id(&self) -> Uuid {
        self.user_id
    }

    fn provider_name(&self) -> String {
        self.provider_name.clone()
    }

    fn provider_user_id(&self) -> String {
        self.provider_user_id.clone()
    }

    fn access_token(&self) -> String {
        self.access_token.clone()
    }

    fn refresh_token(&self) -> Option<String> {
        self.refresh_token.clone()
    }

    fn expires(&self) -> Option<DateTime<Utc>> {
        self.expires
    }

    fn scopes(&self) -> Vec<String> {
        self.scopes.clone()
    }
}

#[derive(Clone, FromRef)]
struct AppState {
    store: MemoryStore,
    auth: AxumUserConfig,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let req_var = |name: &'static str| {
        var(name).unwrap_or_else(|_| panic!("Missing required env var: {name}"))
    };

    let base_url = Url::parse("http://localhost:3000").unwrap();

    let key = Key::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes());

    let auth = AxumUserConfig::new(
        key,
        PasswordConfig::new().with_allow_reset(axum_user::PasswordReset::AnyUserEmail),
        EmailConfig::new(
            base_url.clone(),
            EmailPaths {
                login: "login/email",
                verify: "user/email/verify",
                signup: "signup/email",
                reset_pw: "password/reset",
            },
            SmtpSettings {
                server_url: req_var("SMTP_URL"),
                username: req_var("SMTP_USERNAME"),
                password: req_var("SMTP_PASSWORD"),
                from: req_var("SMTP_FROM"),
                starttls: true,
            },
        ),
        OAuthConfig::new(
            base_url,
            OAuthPaths {
                login: "login/oauth",
                signup: "signup/oauth",
                refresh: "user/oauth/refresh",
                link: "user/oauth/link",
            },
        )
        .with_client(SpotifyOAuthProvider::new(
            req_var("SPOTIFY_CLIENT_ID"),
            req_var("SPOTIFY_CLIENT_SECRET"),
        ))
        .with_client(GitHubOAuthProvider::new(
            req_var("GITHUB_CLIENT_ID"),
            req_var("GITHUB_CLIENT_SECRET"),
        )),
    )
    .with_https_only(false);

    let routes = auth.routes::<MemoryStore, AppState>();

    let state = AppState {
        store: MemoryStore::default(),
        auth,
    };

    let app = Router::new()
        .merge(routes)
        .route("/store", get(get_store_handler))
        .route("/protected", get(get_protected_handler))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let tcp = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    serve(tcp, app.into_make_service()).await.unwrap();
}

async fn get_store_handler(State(state): State<AppState>) -> impl IntoResponse {
    format!("{:#?}", state.store).into_response()
}

async fn get_protected_handler(auth: AxumUser<MemoryStore>) -> impl IntoResponse {
    let Some((user, session)) = auth.user_session().await else {
        return Redirect::to(&format!(
            "/login?next={}",
            urlencoding::encode("/protected")
        ))
        .into_response();
    };

    format!(
        "You are logged in as {:#?} using session {:#?}",
        user, session
    )
    .into_response()
}
