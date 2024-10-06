mod forms;
mod store;
mod templates;

use askama_axum::IntoResponse;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Redirect,
    routing::{get, post, put},
    serve, Form, Router,
};
use axum_extra::extract::cookie::Key;
use axum_macros::{debug_handler, FromRef};
use axum_user::{
    Allow, AxumUser as BaseAxumUser, AxumUserConfig, EmailConfig, EmailTrait, OAuthConfig,
    PasswordConfig, SmtpSettings, UserTrait,
};
use chrono::Duration;
use serde::Deserialize;
use tokio::net::TcpListener;
use url::Url;
use uuid::Uuid;

use self::forms::*;
use self::store::MemoryStore;
use self::templates::*;

type AxumUser = BaseAxumUser<MemoryStore>;

#[derive(Clone)]
pub struct MyUser {
    id: Uuid,
    name: String,
    password: Option<String>,
    emails: Vec<MyUserEmail>,
}

impl UserTrait for MyUser {
    fn get_password_hash(&self) -> Option<String> {
        self.password.clone()
    }

    fn get_id(&self) -> Uuid {
        self.id
    }
}

#[derive(Clone)]
pub struct MyUserEmail {
    email: String,
    verified: bool,
}

impl EmailTrait for MyUserEmail {
    fn address(&self) -> String {
        self.email.clone()
    }

    fn verified(&self) -> bool {
        self.verified
    }

    fn allow_login(&self) -> bool {
        true
    }
}

#[derive(Deserialize)]
pub struct CommonQuery {
    next: Option<String>,
    message: Option<String>,
    error: Option<String>,
}

#[derive(Clone, FromRef)]
struct AppState {
    store: MemoryStore,
    auth: AxumUserConfig,
}

#[tokio::main]
async fn main() {
    let state = AppState {
        store: MemoryStore::default(),
        auth: AxumUserConfig {
            key: Key::generate(),
            pass: PasswordConfig {
                allow_login: Allow::OnSelf,
                allow_signup: Allow::OnSelf,
            },
            email: EmailConfig {
                allow_login: Allow::OnSelf,
                allow_signup: Allow::OnSelf,
                challenge_lifetime: Duration::minutes(5),
                base_url: Url::parse("http://localhost:3000").unwrap(),
                login_path: "login/email".into(),
                verify_path: "user/verify-email".into(),
                signup_path: "signup/email".into(),
                reset_pw_path: "reset-password".into(),
                smtp: SmtpSettings {
                    server_url: "".into(),
                    username: "".into(),
                    password: "".into(),
                    from: "".into(),
                    starttls: true,
                },
            },
            oauth: OAuthConfig {
                base_redirect_url: Url::parse("http://localhost:3000/login").unwrap(),
                allow_login: Allow::OnSelf,
                allow_signup: Allow::OnEither,
                clients: Default::default(),
            },
        },
    };

    let app = Router::new()
        .route("/", get(get_index_handler))
        .route("/login", get(get_login_handler))
        .route("/login/password", post(post_login_password_handler))
        .route(
            "/login/email",
            post(post_login_email_handler).get(get_login_email_handler),
        )
        .route("/login/oauth", post(post_login_oauth_handler))
        .route(
            "/login/oauth/:provider",
            get(get_login_oauth_provider_handler),
        )
        .route("/signup", get(get_signup_handler))
        .route("/signup/password", post(post_signup_password_handler))
        .route(
            "/signup/email",
            post(post_signup_email_handler).get(get_signup_email_handler),
        )
        .route("/signup/oauth", post(post_signup_oauth_handler))
        .route(
            "/signup/oauth/:provier",
            get(get_signup_oauth_provider_handler),
        )
        .route("/user", get(get_user_handler).delete(delete_user_handler))
        .route("/user/logout", get(get_logout_handler))
        .route("/user/verify-session", get(get_verify_handler))
        .route(
            "/user/password",
            put(put_user_password_handler).delete(delete_user_password_handler),
        )
        .route("/user/link-oauth", post(post_user_link_oauth_handler))
        .route(
            "/user/link-oauth/:provider",
            get(get_link_oauth_provider_handler),
        )
        .route(
            "/user/verify-email",
            get(get_user_verify_email_handler).post(post_user_verify_email_handler),
        )
        .route(
            "/reset-password",
            post(post_reset_password_handler).get(get_reset_password_handler),
        )
        .with_state(state);

    let tcp = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    serve(tcp, app.into_make_service()).await.unwrap();
}

async fn post_reset_password_handler(
    auth: AxumUser,
    Form(EmailResetForm { email, next }): Form<EmailResetForm>,
) -> impl IntoResponse {
    auth.email_reset_init(email.clone(), next).await;

    EmailSentTemplate { address: email }.into_response()
}

async fn get_reset_password_handler(
    auth: AxumUser,
    Query(CodeQuery { code }): Query<CodeQuery>,
) -> impl IntoResponse {
    if !auth.is_reset_session().await {
        return (auth, StatusCode::UNAUTHORIZED).into_response();
    }

    match auth.email_reset_callback(code).await {
        Ok((auth, next)) => {
            let next = next.unwrap_or("/login?message=Password reset successfull".into());
            (auth, Redirect::to(&next)).into_response()
        }
        Err((auth, err)) => {
            let next = format!("/login?error={}", urlencoding::encode(err));
            (auth, Redirect::to(&next)).into_response()
        }
    }
}

async fn delete_user_password_handler(
    auth: AxumUser,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let Some((user, session)) = auth.user_session().await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    state.store.clear_user_password(user.id, session.id).await;

    StatusCode::OK.into_response()
}

async fn post_login_oauth_handler(
    auth: AxumUser,
    Form(OauthLoginForm { provider, next }): Form<OauthLoginForm>,
) -> impl IntoResponse {
    match auth.oauth_login_init(provider, next).await {
        Ok((auth, redirect_url)) => (auth, Redirect::to(redirect_url.as_str())),
        Err((auth, err)) => {
            let next = format!("/login?error={}", urlencoding::encode(err));
            (auth, Redirect::to(&next))
        }
    }
}

async fn post_user_link_oauth_handler(
    auth: AxumUser,
    Form(OauthLoginForm { provider, next }): Form<OauthLoginForm>,
) -> impl IntoResponse {
    if !auth.logged_in().await {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    match auth.oauth_link_init(provider, next).await {
        Ok((auth, redirect_url)) => (auth, Redirect::to(redirect_url.as_str())).into_response(),
        Err((auth, err)) => {
            let next = format!("/user?error={}", urlencoding::encode(err));
            (auth, Redirect::to(&next)).into_response()
        }
    }
}

async fn post_signup_oauth_handler(
    auth: AxumUser,
    Form(OauthSignUpForm { provider, next }): Form<OauthSignUpForm>,
) -> impl IntoResponse {
    match auth.oauth_signup_init(provider, next).await {
        Ok((auth, redirect_url)) => (auth, Redirect::to(redirect_url.as_str())),
        Err((auth, err)) => {
            let next = format!("/signup?error={}", urlencoding::encode(err));
            (auth, Redirect::to(&next))
        }
    }
}

async fn get_signup_oauth_provider_handler(
    auth: AxumUser,
    Path(OAuthCallbackPath { provider }): Path<OAuthCallbackPath>,
    Query(OAuthCallbackQuery { code, state }): Query<OAuthCallbackQuery>,
) -> impl IntoResponse {
    match auth.oauth_signup_callback(provider, code, state).await {
        Ok((auth, next)) => {
            let next = next.unwrap_or("/user".into());
            (auth, Redirect::to(&next)).into_response()
        }
        Err((auth, err)) => {
            let next = format!("/signup?error={}", urlencoding::encode(err));
            (auth, Redirect::to(&next)).into_response()
        }
    }
}

async fn get_link_oauth_provider_handler(
    auth: AxumUser,
    Path(OAuthCallbackPath { provider }): Path<OAuthCallbackPath>,
    Query(OAuthCallbackQuery { code, state }): Query<OAuthCallbackQuery>,
) -> impl IntoResponse {
    match auth.oauth_link_callback(provider, code, state).await {
        Ok((auth, next)) => {
            let next = next.unwrap_or("/user".into());
            (auth, Redirect::to(&next)).into_response()
        }
        Err((auth, err)) => {
            let next = format!("/signup?error={}", urlencoding::encode(err));
            (auth, Redirect::to(&next)).into_response()
        }
    }
}

async fn post_signup_email_handler(
    auth: AxumUser,
    Form(EmailSignUpForm { email }): Form<EmailSignUpForm>,
) -> impl IntoResponse {
    auth.email_signup_init(email.clone(), None).await;

    EmailSentTemplate { address: email }.into_response()
}

async fn post_user_verify_email_handler(
    auth: AxumUser,
    Form(EmailVerifyForm { email }): Form<EmailVerifyForm>,
) -> impl IntoResponse {
    if !auth.logged_in().await {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    auth.email_verify_init(email.clone(), None).await;

    Redirect::to("/user?message=Email sent").into_response()
}

async fn get_user_verify_email_handler(
    auth: AxumUser,
    Query(CodeQuery { code }): Query<CodeQuery>,
) -> impl IntoResponse {
    if !auth.logged_in().await {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    match auth.email_signup_callback(code).await {
        Ok((auth, next)) => {
            let next = next.unwrap_or("/user".into());
            (auth, Redirect::to(&next)).into_response()
        }
        Err((auth, err)) => {
            let next = format!("/user?error={}", urlencoding::encode(err));
            (auth, Redirect::to(&next)).into_response()
        }
    }
}

async fn get_signup_email_handler(
    auth: AxumUser,
    Query(CodeQuery { code }): Query<CodeQuery>,
) -> impl IntoResponse {
    match auth.email_signup_callback(code).await {
        Ok((auth, next)) => {
            let next = next.unwrap_or("/user".into());
            (auth, Redirect::to(&next)).into_response()
        }
        Err((auth, err)) => {
            let next = format!("/signup?error={}", urlencoding::encode(err));
            (auth, Redirect::to(&next)).into_response()
        }
    }
}

#[derive(Deserialize)]
struct OAuthCallbackQuery {
    code: String,
    state: String,
}

#[derive(Deserialize)]
struct OAuthCallbackPath {
    provider: String,
}

async fn get_login_oauth_provider_handler(
    auth: AxumUser,
    Path(OAuthCallbackPath { provider }): Path<OAuthCallbackPath>,
    Query(OAuthCallbackQuery { code, state }): Query<OAuthCallbackQuery>,
) -> impl IntoResponse {
    match auth.oauth_login_callback(provider, code, state).await {
        Ok((auth, next)) => {
            let next = next.unwrap_or("/user".into());
            (auth, Redirect::to(&next)).into_response()
        }
        Err((auth, err)) => {
            let next = format!("/login?error={}", urlencoding::encode(err));
            (auth, Redirect::to(&next)).into_response()
        }
    }
}

#[debug_handler(state = AppState)]
async fn post_login_email_handler(
    auth: AxumUser,
    Form(EmailLoginForm { email, next }): Form<EmailLoginForm>,
) -> impl IntoResponse {
    auth.email_login_init(email.clone(), next).await;

    EmailSentTemplate { address: email }.into_response()
}

#[derive(Deserialize)]
struct CodeQuery {
    code: String,
}

async fn get_login_email_handler(
    auth: AxumUser,
    Query(CodeQuery { code }): Query<CodeQuery>,
) -> impl IntoResponse {
    match auth.email_login_callback(code).await {
        Ok((auth, next)) => {
            let next = next.unwrap_or("/user".into());
            (auth, Redirect::to(&next)).into_response()
        }
        Err((auth, err)) => {
            let next = format!("/login?error={}", urlencoding::encode(err));
            (auth, Redirect::to(&next)).into_response()
        }
    }
}

#[debug_handler(state = AppState)]
async fn get_signup_handler(
    Query(CommonQuery { error, .. }): Query<CommonQuery>,
) -> impl IntoResponse {
    SignupTemplate { error }.into_response()
}

#[debug_handler(state = AppState)]
async fn post_signup_password_handler(
    auth: AxumUser,
    Form(PasswordSignUpForm { email, password }): Form<PasswordSignUpForm>,
) -> impl IntoResponse {
    if password.len() <= 3 {
        return Redirect::to("/signup?error=Password must include more than 3 letters")
            .into_response();
    }

    match auth.password_signup(email, password).await {
        Err((auth, err)) => {
            // Signup didn't work. Let's give the user the error.
            let next = format!("/signup?error={}", urlencoding::encode(err));
            (auth, Redirect::to(&next)).into_response()
        }
        Ok(auth) => {
            // Hooray! Signup was succesfull. Let's redirect the user to their new User page.
            // Once again, it's very important to pass auth along with the response - this enables the cookie to be set.
            (auth, Redirect::to("/user")).into_response()
        }
    }
}

#[debug_handler(state = AppState)]
async fn get_verify_handler(auth: AxumUser) -> impl IntoResponse {
    // If the auth cookie is never modified, it's ok to return without it.
    if auth.logged_in().await {
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    }
}

#[debug_handler]
async fn delete_user_handler(auth: AxumUser, State(state): State<AppState>) -> impl IntoResponse {
    if let Some(user) = auth.user().await {
        state.store.delete_user(user.id).await;

        let auth = auth.log_out().await;

        (auth, Redirect::to("/")).into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

#[debug_handler]
async fn put_user_password_handler(
    auth: AxumUser,
    State(state): State<AppState>,
    Form(ChangePasswordForm { new_password }): Form<ChangePasswordForm>,
) -> impl IntoResponse {
    // Looking for a logged in user and the current session.
    let mut user_session = auth.user_session().await;

    if user_session.is_none() {
        // No logged in user found, but maybe there is a password reset session available?
        user_session = auth.reset_user_session().await;
    }

    let Some((user, session)) = user_session else {
        // Nope! Bail.
        return StatusCode::UNAUTHORIZED.into_response();
    };

    // Since the password has changed, all sessions but the current one that are logged in with password must be deleted. That's why we need the session id!
    state
        .store
        .set_user_password(user.id, new_password, session.id)
        .await;

    Redirect::to("/login?message=The password has been reset!").into_response()
}

#[debug_handler(state = AppState)]
async fn get_user_handler(
    x: AxumUser,
    Query(CommonQuery { error, message, .. }): Query<CommonQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if let Some(user) = x.user().await {
        let sessions = state.store.get_sessions(user.id).await;
        let oauth_tokens = state.store.get_oauth_tokens(user.id).await;

        UserTemplate {
            name: user.name,
            message,
            error,
            sessions,
            password: user.password.is_some(),
            emails: user.emails,
            oauth_tokens,
        }
        .into_response()
    } else {
        Redirect::to("/login?next=%UFuser").into_response()
    }
}

#[debug_handler(state = AppState)]
async fn get_login_handler(auth: AxumUser, Query(query): Query<CommonQuery>) -> impl IntoResponse {
    if auth.logged_in().await {
        Redirect::to("/User").into_response()
    } else {
        LoginTemplate {
            message: query.message,
            next: query.next,
        }
        .into_response()
    }
}

#[debug_handler(state = AppState)]
async fn post_login_password_handler(
    auth: AxumUser,
    Form(PasswordLoginForm {
        email,
        password,
        next,
    }): Form<PasswordLoginForm>,
) -> impl IntoResponse {
    match auth.password_login(email, password).await {
        Err((auth, err)) => {
            // Login didn´t work. Let's give the user the error.
            let next = format!("/login?error={}", urlencoding::encode(err));
            (auth, Redirect::to(&next)).into_response()
        }
        Ok(auth) => {
            let next = next.unwrap_or("/user".into());
            (auth, Redirect::to(&next)).into_response()
        }
    }
}

#[debug_handler(state = AppState)]
async fn get_logout_handler(auth: AxumUser) -> impl IntoResponse {
    let auth = auth.log_out().await;

    (auth, Redirect::to("/"))
}

#[debug_handler(state = AppState)]
async fn get_index_handler(auth: AxumUser) -> impl IntoResponse {
    let name = auth.user().await.map(|user| user.name);

    IndexTemplate { name }.into_response()
}
