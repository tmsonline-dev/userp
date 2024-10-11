mod forms;
mod store;
mod templates;

use askama_axum::IntoResponse;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Redirect,
    routing::{get, post},
    serve, Form, Router,
};
use axum_extra::extract::cookie::Key;
use axum_macros::{debug_handler, FromRef};
use axum_user::{
    provider::{GitHubOAuthProvider, SpotifyOAuthProvider},
    AuthorizationCode, AxumUser as BaseAxumUser, AxumUserConfig, AxumUserStore, CsrfToken,
    EmailConfig, EmailPaths, EmailTrait, LoginMethod, LoginSession, OAuthConfig, OAuthPaths,
    PasswordConfig, RefreshInitResult, SmtpSettings, UserTrait,
};
use dotenv::var;
use serde::Deserialize;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use url::Url;
use urlencoding::encode;
use uuid::Uuid;

use self::forms::*;
use self::store::MemoryStore;
use self::templates::*;

type AxumUser = BaseAxumUser<MemoryStore>;

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct MyUserEmail {
    email: String,
    verified: bool,
    allow_login: bool,
}

impl EmailTrait for MyUserEmail {
    fn address(&self) -> String {
        self.email.clone()
    }

    fn verified(&self) -> bool {
        self.verified
    }

    fn allow_login(&self) -> bool {
        self.allow_login
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

#[derive(Deserialize)]
pub struct CommonQuery {
    next: Option<String>,
    message: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct ResetPasswordQuery {
    code: Option<String>,
}

#[derive(Deserialize)]
struct SendResetPasswordQuery {
    address: Option<String>,
    message: Option<String>,
    sent: Option<bool>,
    error: Option<String>,
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

    let state = AppState {
        store: MemoryStore::default(),
        auth: AxumUserConfig::new(
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
        .with_https_only(false),
    };

    let app = Router::new()
        .route("/store", get(get_store_handler))
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
            "/signup/oauth/:provider",
            get(get_signup_oauth_provider_handler),
        )
        .route("/user", get(get_user_handler))
        .route("/user/delete", post(post_user_delete_handler))
        .route("/user/logout", get(get_logout_handler))
        .route("/user/verify-session", get(get_user_verify_session_handler))
        .route("/user/password/set", post(post_user_password_set_handler))
        .route(
            "/user/password/delete",
            post(post_user_password_delete_handler),
        )
        .route("/user/oauth/link", post(post_user_oauth_link_handler))
        .route(
            "/user/oauth/link/:provider",
            get(get_oauth_link_provider_handler),
        )
        .route(
            "/user/session/delete",
            post(post_user_session_delete_handler),
        )
        .route("/user/oauth/refresh", post(post_user_oauth_refresh_handler))
        .route(
            "/user/oauth/refresh/:provider",
            get(get_user_oauth_refresh_provider_handler),
        )
        .route("/user/oauth/delete", post(post_user_oauth_delete_handler))
        .route(
            "/user/email/verify",
            get(get_user_verify_email_handler).post(post_user_verify_email_handler),
        )
        .route("/user/email/add", post(post_user_email_handler))
        .route("/user/email/delete", post(post_user_email_delete_handler))
        .route(
            "/user/email/enable_login",
            post(post_user_email_enable_login),
        )
        .route(
            "/user/email/disable_login",
            post(post_user_email_disable_login),
        )
        .route(
            "/password/send-reset",
            get(get_password_send_reset_handler).post(post_password_send_reset_handler),
        )
        .route(
            "/password/reset",
            get(get_password_reset_handler).post(post_password_reset_handler),
        )
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let tcp = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    serve(tcp, app.into_make_service()).await.unwrap();
}

async fn post_user_email_enable_login(
    auth: AxumUser,
    State(state): State<AppState>,
    Form(EmailSignUpForm { email }): Form<EmailSignUpForm>,
) -> impl IntoResponse {
    let Some(user) = auth.user().await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    state
        .store
        .set_user_email_allow_login(user.id, email.clone(), true)
        .await;

    Redirect::to(&format!(
        "/user?message={}",
        encode(&format!("You can now log in directly with {email}"))
    ))
    .into_response()
}

async fn post_user_email_disable_login(
    auth: AxumUser,
    State(state): State<AppState>,
    Form(EmailSignUpForm { email }): Form<EmailSignUpForm>,
) -> impl IntoResponse {
    let Some(user) = auth.user().await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    state
        .store
        .set_user_email_allow_login(user.id, email.clone(), false)
        .await;

    Redirect::to(&format!(
        "/user?message={}",
        encode(&format!("You can no longer log in directly with {email}"))
    ))
    .into_response()
}

async fn get_password_send_reset_handler(
    Query(query): Query<SendResetPasswordQuery>,
) -> impl IntoResponse {
    SendResetPasswordTemplate {
        sent: query.sent.is_some_and(|sent| sent),
        address: query.address,
        error: query.error,
        message: query.message,
    }
    .into_response()
}

async fn post_password_send_reset_handler(
    auth: AxumUser,
    Form(EmailResetForm { email, next }): Form<EmailResetForm>,
) -> impl IntoResponse {
    if let Err(err) = auth.email_reset_init(email.clone(), next).await {
        let next = format!(
            "/password/send-reset?error={}&address={}",
            urlencoding::encode(&err.to_string()),
            email
        );

        Redirect::to(&next)
    } else {
        let next = format!("/password/send-reset?sent=true&address={}", email);

        Redirect::to(&next)
    }
}

async fn get_password_reset_handler(
    auth: AxumUser,
    Query(query): Query<ResetPasswordQuery>,
) -> impl IntoResponse {
    if let Some(code) = query.code {
        match auth.email_reset_callback(code).await {
            Ok(auth) => (auth, ResetPasswordTemplate).into_response(),
            Err((auth, err)) => {
                (auth, Redirect::to(&format!("/login?err={}", encode(err)))).into_response()
            }
        }
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

async fn post_password_reset_handler(
    auth: AxumUser,
    State(state): State<AppState>,
    Form(ChangePasswordForm { new_password }): Form<ChangePasswordForm>,
) -> impl IntoResponse {
    if let Some((user, session)) = auth.reset_user_session().await {
        state
            .store
            .set_user_password(user.id, new_password, session.id)
            .await;
        Redirect::to("/login?message=Password has been reset").into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

async fn get_store_handler(State(state): State<AppState>) -> impl IntoResponse {
    format!("{:#?}", state.store).into_response()
}

#[debug_handler(state = AppState)]
async fn post_user_email_handler(
    auth: AxumUser,
    State(state): State<AppState>,
    Form(EmailAddForm { email }): Form<EmailAddForm>,
) -> impl IntoResponse {
    let Some(user) = auth.user().await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    state.store.add_user_email(user.id, email).await;

    Redirect::to("/user?message=Email added").into_response()
}

#[debug_handler(state = AppState)]
async fn post_user_email_delete_handler(
    auth: AxumUser,
    State(state): State<AppState>,
    Form(EmailAddForm { email }): Form<EmailAddForm>,
) -> impl IntoResponse {
    let Some(user) = auth.user().await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    state.store.delete_user_email(user.id, email).await;

    Redirect::to("/user?message=Email deleted").into_response()
}

async fn get_user_oauth_refresh_provider_handler(
    auth: AxumUser,
    Path(OAuthCallbackPath { provider }): Path<OAuthCallbackPath>,
    Query(OAuthCallbackQuery { code, state }): Query<OAuthCallbackQuery>,
) -> impl IntoResponse {
    match auth.oauth_refresh_callback(provider, code, state).await {
        Ok(next) => {
            let next = next.unwrap_or("/user".into());
            (auth, Redirect::to(&next)).into_response()
        }
        Err(err) => {
            let next = format!("/signup?error={}", urlencoding::encode(&err.to_string()));
            (auth, Redirect::to(&next)).into_response()
        }
    }
}

async fn post_user_session_delete_handler(
    auth: AxumUser,
    State(state): State<AppState>,
    Form(IdForm { id }): Form<IdForm>,
) -> impl IntoResponse {
    if !auth.logged_in().await {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    state.store.delete_session(id).await;

    Redirect::to("/user?message=Session deleted").into_response()
}

async fn post_user_oauth_delete_handler(
    auth: AxumUser,
    State(state): State<AppState>,
    Form(IdForm { id }): Form<IdForm>,
) -> impl IntoResponse {
    let Some(user) = auth.user().await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    state.store.delete_oauth_token(user.id, id).await;

    Redirect::to("/user?message=Token deleted").into_response()
}

async fn post_user_oauth_refresh_handler(
    auth: AxumUser,
    State(state): State<AppState>,
    Form(IdForm { id }): Form<IdForm>,
) -> impl IntoResponse {
    let Some(user) = auth.user().await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    let Some(token) = state.store.get_oauth_token(user.id, id).await else {
        return StatusCode::NOT_FOUND.into_response();
    };

    match auth
        .oauth_refresh_init(token, Some("/user?message=Token refreshed".to_string()))
        .await
    {
        Ok((auth, result)) => match result {
            RefreshInitResult::Ok => {
                (auth, Redirect::to("/user?message=Token refreshed")).into_response()
            }
            RefreshInitResult::Redirect(redirect_url) => {
                (auth, Redirect::to(redirect_url.as_str())).into_response()
            }
        },
        Err(err) => {
            let next = format!("/user?error={}", urlencoding::encode(&err.to_string()));
            Redirect::to(&next).into_response()
        }
    }
}

async fn post_user_password_delete_handler(
    auth: AxumUser,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let Some((user, session)) = auth.user_session().await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    state.store.clear_user_password(user.id, session.id).await;

    (auth, Redirect::to("/user?message=Password cleared")).into_response()
}

async fn post_login_oauth_handler(
    auth: AxumUser,
    Form(OauthLoginForm { provider, next }): Form<OauthLoginForm>,
) -> impl IntoResponse {
    match auth.oauth_login_init(provider, next).await {
        Ok((auth, redirect_url)) => (auth, Redirect::to(redirect_url.as_str())).into_response(),
        Err(err) => {
            let next = format!("/login?error={}", urlencoding::encode(&err.to_string()));
            Redirect::to(&next).into_response()
        }
    }
}

async fn post_user_oauth_link_handler(
    auth: AxumUser,
    Form(OauthLoginForm { provider, next }): Form<OauthLoginForm>,
) -> impl IntoResponse {
    if !auth.logged_in().await {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    match auth.oauth_link_init(provider, next).await {
        Ok((auth, redirect_url)) => (auth, Redirect::to(redirect_url.as_str())).into_response(),
        Err(err) => {
            let next = format!("/user?error={}", urlencoding::encode(&err.to_string()));
            Redirect::to(&next).into_response()
        }
    }
}

async fn post_signup_oauth_handler(
    auth: AxumUser,
    Form(OauthSignUpForm { provider, next }): Form<OauthSignUpForm>,
) -> impl IntoResponse {
    match auth.oauth_signup_init(provider, next).await {
        Ok((auth, redirect_url)) => (auth, Redirect::to(redirect_url.as_str())).into_response(),
        Err(err) => {
            let next = format!("/signup?error={}", urlencoding::encode(&err.to_string()));
            Redirect::to(&next).into_response()
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
        Err(err) => {
            let next = format!("/signup?error={}", urlencoding::encode(&err.to_string()));
            Redirect::to(&next).into_response()
        }
    }
}

async fn get_oauth_link_provider_handler(
    auth: AxumUser,
    Path(OAuthCallbackPath { provider }): Path<OAuthCallbackPath>,
    Query(OAuthCallbackQuery { code, state }): Query<OAuthCallbackQuery>,
) -> impl IntoResponse {
    match auth.oauth_link_callback(provider, code, state).await {
        Ok(next) => {
            let next = next.unwrap_or("/user".into());
            (auth, Redirect::to(&next)).into_response()
        }
        Err(err) => {
            let next = format!("/signup?error={}", urlencoding::encode(&err.to_string()));
            (auth, Redirect::to(&next)).into_response()
        }
    }
}

async fn post_signup_email_handler(
    auth: AxumUser,
    Form(EmailSignUpForm { email }): Form<EmailSignUpForm>,
) -> impl IntoResponse {
    match auth.email_signup_init(email.clone(), None).await {
        Ok(()) => {
            let next = format!(
                "/signup?message=Signup email sent to {}!",
                urlencoding::encode(&email)
            );

            Redirect::to(&next)
        }
        Err(err) => {
            let next = format!("/signup?error={}", urlencoding::encode(&err.to_string()));
            Redirect::to(&next)
        }
    }
}

async fn post_user_verify_email_handler(
    auth: AxumUser,
    Form(EmailVerifyForm { email }): Form<EmailVerifyForm>,
) -> impl IntoResponse {
    if !auth.logged_in().await {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    match auth.email_verify_init(email.clone(), None).await {
        Ok(()) => {
            let next = format!(
                "/user?message=Verification mail sent to {}",
                urlencoding::encode(&email)
            );

            Redirect::to(&next).into_response()
        }
        Err(err) => {
            let next = format!("/user?error={}", urlencoding::encode(&err.to_string()));
            Redirect::to(&next).into_response()
        }
    }
}

async fn get_user_verify_email_handler(
    auth: AxumUser,
    Query(CodeQuery { code }): Query<CodeQuery>,
) -> impl IntoResponse {
    match auth.email_verify_callback(code).await {
        Ok((address, next)) => {
            if let Some(next) = next {
                (auth, Redirect::to(&next)).into_response()
            } else {
                EmailVerifiedTemplate { address }.into_response()
            }
        }
        Err(err) => {
            let next = format!("/login?error={}", urlencoding::encode(err));
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
        Err(err) => {
            let next = format!("/signup?error={}", urlencoding::encode(&err.to_string()));
            Redirect::to(&next).into_response()
        }
    }
}

#[derive(Deserialize)]
struct OAuthCallbackQuery {
    code: AuthorizationCode,
    state: CsrfToken,
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
        Err(err) => {
            let next = format!("/login?error={}", urlencoding::encode(&err.to_string()));
            Redirect::to(&next).into_response()
        }
    }
}

#[debug_handler(state = AppState)]
async fn post_login_email_handler(
    auth: AxumUser,
    Form(EmailLoginForm { email, next }): Form<EmailLoginForm>,
) -> impl IntoResponse {
    match auth.email_login_init(email.clone(), next).await {
        Ok(()) => {
            let next = format!(
                "/login?message=Login link sent to {}!",
                urlencoding::encode(&email)
            );

            Redirect::to(&next)
        }
        Err(err) => {
            let next = format!("/login?error={}", urlencoding::encode(&err.to_string()));
            Redirect::to(&next)
        }
    }
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
        Err(err) => {
            let next = format!("/login?error={}", urlencoding::encode(&err.to_string()));
            Redirect::to(&next).into_response()
        }
    }
}

#[debug_handler(state = AppState)]
async fn get_signup_handler(
    auth: AxumUser,
    Query(CommonQuery {
        error,
        message,
        next,
        ..
    }): Query<CommonQuery>,
) -> impl IntoResponse {
    SignupTemplate {
        error,
        message,
        next,
        oauth_providers: auth.oauth_signup_providers(),
    }
    .into_response()
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
        Ok(auth) => {
            // Hooray! Signup was succesfull. Let's redirect the user to their new User page.
            // Once again, it's very important to pass auth along with the response - this enables the cookie to be set.
            (auth, Redirect::to("/user")).into_response()
        }
        Err(err) => {
            // Signup didn't work. Let's give the user the error.
            let next = format!("/signup?error={}", urlencoding::encode(&err.to_string()));
            Redirect::to(&next).into_response()
        }
    }
}

#[debug_handler(state = AppState)]
async fn get_user_verify_session_handler(auth: AxumUser) -> impl IntoResponse {
    // If the auth cookie is never modified, it's ok to return without it.
    if auth.logged_in().await {
        StatusCode::OK
    } else {
        StatusCode::UNAUTHORIZED
    }
}

#[debug_handler]
async fn post_user_delete_handler(
    auth: AxumUser,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if let Some(user) = auth.user().await {
        state.store.delete_user(user.id).await;

        let auth = auth.log_out().await;

        (auth, Redirect::to("/")).into_response()
    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}

#[debug_handler]
async fn post_user_password_set_handler(
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

    Redirect::to("/user?message=The password has been set!").into_response()
}

#[debug_handler(state = AppState)]
async fn get_user_handler(
    auth: AxumUser,
    Query(CommonQuery { error, message, .. }): Query<CommonQuery>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if let Some(user) = auth.user().await {
        let sessions = state.store.get_sessions(user.id).await;
        let oauth_tokens = state.store.get_oauth_tokens(user.id).await;

        UserTemplate {
            name: user.name,
            message,
            error,
            sessions,
            has_password: user.password.is_some(),
            emails: user.emails,
            oauth_providers: auth
                .oauth_link_providers()
                .into_iter()
                .filter(|p| !oauth_tokens.iter().any(|t| t.provider_name == p.name))
                .collect(),
            oauth_tokens,
        }
        .into_response()
    } else {
        println!("User not found in store: {:#?}", state.store);
        Redirect::to("/login?next=%UFuser").into_response()
    }
}

#[debug_handler(state = AppState)]
async fn get_login_handler(
    auth: AxumUser,
    Query(CommonQuery {
        next,
        message,
        error,
        ..
    }): Query<CommonQuery>,
) -> impl IntoResponse {
    if auth.logged_in().await {
        Redirect::to("/user").into_response()
    } else {
        LoginTemplate {
            next,
            message,
            error,
            oauth_providers: auth.oauth_login_providers(),
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
        Ok(auth) => {
            let next = next.unwrap_or("/user".into());
            (auth, Redirect::to(&next)).into_response()
        }
        Err(err) => {
            // Login didn´t work. Let's give the user the error.
            let next = format!("/login?error={}", urlencoding::encode(&err.to_string()));
            Redirect::to(&next).into_response()
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
