mod mem;

use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{delete, get, put},
    serve, Form, Router,
};
use axum_extra::extract::cookie::Key;
use axum_macros::{debug_handler, FromRef};
use axum_user::{
    Allow, AxumUser, AxumUserConfig, EmailConfig, EmailTrait, OAuthConfig, PasswordConfig,
    SmtpSettings, UserTrait,
};
use chrono::Duration;
use mem::MemoryStore;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use url::Url;
use uuid::Uuid;

#[derive(Clone)]
pub struct MyUser {
    id: Uuid,
    name: String,
    password: String,
    emails: Vec<MyUserEmail>,
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

impl UserTrait for MyUser {
    fn get_password_hash(&self) -> Option<String> {
        Some(self.password.clone())
    }

    fn get_id(&self) -> Uuid {
        self.id
    }
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
                base_url: Url::parse("http://svt.se").unwrap(),
                login_path: "login/email".into(),
                verify_path: "verify/email".into(),
                signup_path: "signup/email".into(),
                reset_pw_path: "reset-pw".into(),
                smtp: SmtpSettings {
                    server_url: "".into(),
                    username: "".into(),
                    password: "".into(),
                    from: "".into(),
                    starttls: true,
                },
            },
            oauth: OAuthConfig {
                base_redirect_url: Url::parse("https://localhost:3000/login").unwrap(),
                allow_login: Allow::OnSelf,
                allow_signup: Allow::OnEither,
                clients: Default::default(),
            },
        },
    };

    let app = Router::new()
        .route("/secure", get(get_secure_handler))
        .route("/login", get(get_login_handler).post(post_login_handler))
        .route("/logout", get(get_logout_handler))
        .route("/verify", get(get_verify_handler))
        .route("/signup", get(get_signup_handler).post(post_signup_handler))
        .route("/delete_user", delete(delete_user_handler))
        .route("/change_password", put(put_change_password_handler))
        .route("/", get(get_root_handler))
        .with_state(state);

    let tcp = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    serve(tcp, app.into_make_service()).await.unwrap();
}

#[derive(Serialize, Deserialize)]
struct SignUpForm {
    name: String,
    password: String,
}

#[debug_handler(state = AppState)]
async fn get_signup_handler() -> impl IntoResponse {
    Html::from(
        r#"
            <form method="post">
                <label for="name">User name</label>
                <input id="name" name="name">
                <input type="submit" value="Log in">
            </form>
            <p id="error"></p>
            <script>
                const error = new URLSearchParams(location.search).get("error");
                if (error) {
                    document.getElementById("error").innerText = "Error: " + error;
                }
            </script>
        "#,
    )
    .into_response()
}

#[debug_handler(state = AppState)]
async fn post_signup_handler(
    x: AxumUser<MemoryStore>,
    Form(SignUpForm { name, password }): Form<SignUpForm>,
) -> impl IntoResponse {
    if name.len() <= 3 {
        return Redirect::to("/signup?error=Username must include more than 3 letters")
            .into_response();
    }

    if password.len() <= 3 {
        return Redirect::to("/signup?error=Password must include more than 3 letters")
            .into_response();
    }

    let x = match x.password_signup(name, password).await {
        Err((x, err)) => {
            return (
                x,
                Redirect::to(&format!("/signup?error={}", urlencoding::encode(err))),
            )
                .into_response();
        }
        Ok(x) => x,
    };

    (x, Redirect::to("/secure")).into_response()
}

#[debug_handler(state = AppState)]
async fn get_verify_handler(x: AxumUser<MemoryStore>) -> impl IntoResponse {
    if x.logged_in().await {
        (x, StatusCode::OK)
    } else {
        (x, StatusCode::UNAUTHORIZED)
    }
}

#[debug_handler]
async fn delete_user_handler(
    x: AxumUser<MemoryStore>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if let Some(user) = x.user().await {
        state.store.delete_user(user.id).await;

        (x, Redirect::to("/")).into_response()
    } else {
        (x, StatusCode::UNAUTHORIZED).into_response()
    }
}

#[derive(Serialize, Deserialize)]
struct ChangePasswordForm {
    current_password: String,
    new_password: String,
}

#[debug_handler]
async fn put_change_password_handler(
    x: AxumUser<MemoryStore>,
    State(state): State<AppState>,
    Form(ChangePasswordForm {
        current_password,
        new_password,
    }): Form<ChangePasswordForm>,
) -> impl IntoResponse {
    let Some((user, session)) = x.user_session().await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    if user.password != current_password {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    state
        .store
        .set_user_password(user.id, new_password, session.id)
        .await;

    StatusCode::OK.into_response()
}

#[debug_handler(state = AppState)]
async fn get_secure_handler(x: AxumUser<MemoryStore>) -> impl IntoResponse {
    let Some(user) = x.user().await else {
        return Redirect::to("/login?next=%2Fsecure").into_response();
    };

    let name = user.name;

    Html::from(format!(
            r#"
                <p>Welcome {name}. <span id="status">Verifying..</span></p>
                <form action="/delete_user" method="delete">
                    <input type="submit" value="Delete user">                
                </form>
                <a href="/logout">Log out</a>
                <form action="/change_password" method="post">
                    <label for="current_password">Current password</label>
                    <input id="current_password" name="current_password" type="password">
                    <label for="new_password">New password</label>
                    <input id="new_password" name="new_password" type="password">
                    <input type="submit" value="Change password" />
                </form>
                <a href="/">Root</a>
                <script>
                    window.alert("Checking status")
                    fetch("/verify").then((res) => {{
                        if (res.ok) {{
                            document.getElementById("status").innerText = "Verified!"
                        }} else {{
                            location = "/login?next=" + encodeURIComponent(location.pathname + location.search)
                        }}
                    }})
                </script>
            "#
        ))
        .into_response()
}

#[debug_handler(state = AppState)]
async fn get_login_handler(x: AxumUser<MemoryStore>) -> impl IntoResponse {
    if x.logged_in().await {
        Redirect::to("/secure").into_response()
    } else {
        Html::from(
            r#"
                <form method="post">
                    <label for="name">User name</label>
                    <input id="name" name="name">
                    <input id="next" name="next">
                    <input type="submit" value="Log in">
                </form>
                <script>
                    const next = new URLSearchParams(location.search).get("next");
                    if (next) {
                        document.getElementById("next").value = next;
                    }
                </script>
            "#,
        )
        .into_response()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginForm {
    name: String,
    password: String,
    next: String,
}

#[debug_handler(state = AppState)]
async fn post_login_handler(
    x: AxumUser<MemoryStore>,
    Form(LoginForm {
        name,
        password,
        next,
    }): Form<LoginForm>,
) -> impl IntoResponse {
    let x = match x.password_login(name, password).await {
        Err((x, err)) => {
            return (
                x,
                Redirect::to(&format!("/login?error={}", urlencoding::encode(err))),
            )
                .into_response()
        }
        Ok(x) => x,
    };

    (
        x,
        Redirect::to(if next.is_empty() {
            "/secure"
        } else {
            next.as_str()
        }),
    )
        .into_response()
}

#[debug_handler(state = AppState)]
async fn get_logout_handler(x: AxumUser<MemoryStore>) -> impl IntoResponse {
    let x = x.log_out().await;

    (x, Redirect::to("/"))
}

#[debug_handler(state = AppState)]
async fn get_root_handler(x: AxumUser<MemoryStore>) -> impl IntoResponse {
    match x.user().await {
        Some(user) => {
            let name = user.name;

            Html::from(format!(
                r#"
                    <p>You are logged in as {name}</p>
                    <a href="/logout">Log out</a>
                    <a href="/secure">Secure</a>
                "#
            ))
        }
        None => Html::from(
            r#"
                <p>You are not logged in</p>
                <a href="/login?next=%2F">Log in</a>
                <a href="/login">Secure</a>
            "#
            .to_string(),
        ),
    }
}
