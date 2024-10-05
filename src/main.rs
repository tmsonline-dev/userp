mod auth;
mod mem;

use crate::auth::AuthSession;
use auth::{AuthUser, Email, OAuth, OAuthClients, Smtp};
use axum::{
    extract::{FromRef, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{delete, get, put},
    serve, Form, Router,
};
use axum_extra::extract::cookie::Key;
use axum_macros::{debug_handler, FromRef};
use mem::MemoryAuthStore;
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

impl Into<Email> for MyUserEmail {
    fn into(self) -> Email {
        Email {
            email: self.email,
            verified: self.verified,
            allow_login: true,
        }
    }
}

impl AuthUser for MyUser {
    async fn get_password_hash(&self) -> String {
        self.password.clone()
    }

    async fn get_id(&self) -> Uuid {
        self.id
    }
}

#[derive(Clone, FromRef)]
struct AppState {
    key: Key,
    auth: MemoryAuthStore,
    smtp_config: Smtp,
    oauth: OAuth,
}

#[tokio::main]
async fn main() {
    let state = AppState {
        key: Key::generate(),
        auth: MemoryAuthStore::default(),
        smtp_config: Smtp {
            server_url: "".into(),
            username: "".into(),
            password: "".into(),
            from: "".into(),
            starttls: true,
            base_url: Url::parse("http://svt.se").unwrap(),
            allow_login_on_signup: true,
            allow_signup_on_login: false,
            login_path: "login/email".into(),
            verify_path: "verify/email".into(),
            signup_path: "signup/email".into(),
        },
        oauth: OAuth {
            clients: Default::default(),
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

#[debug_handler]
async fn post_signup_handler(
    State(state): State<AppState>,
    x: AuthSession<MemoryAuthStore>,
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

    if state.auth.user_name_taken(name.as_str()).await {
        return Redirect::to("/signup?error=Username already exists").into_response();
    }

    let user_id = state.auth.create_user(name, password).await;

    let x = x.log_in("password".into(), user_id).await;

    (x, Redirect::to("/secure")).into_response()
}

#[debug_handler(state = AppState)]
async fn get_verify_handler(x: AuthSession<MemoryAuthStore>) -> impl IntoResponse {
    if x.logged_in().await {
        (x, StatusCode::OK)
    } else {
        (x, StatusCode::UNAUTHORIZED)
    }
}

#[debug_handler]
async fn delete_user_handler(
    x: AuthSession<MemoryAuthStore>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    if let Some(user) = x.user().await {
        state.auth.delete_user(user.id).await;

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
    x: AuthSession<MemoryAuthStore>,
    State(state): State<AppState>,
    Form(ChangePasswordForm {
        current_password,
        new_password,
    }): Form<ChangePasswordForm>,
) -> impl IntoResponse {
    let Some(user) = x.user().await else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    if user.password != current_password {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    state.auth.set_user_password(user.id, new_password).await;

    StatusCode::OK.into_response()
}

#[debug_handler(state = AppState)]
async fn get_secure_handler(x: AuthSession<MemoryAuthStore>) -> impl IntoResponse {
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
async fn get_login_handler(x: AuthSession<MemoryAuthStore>) -> impl IntoResponse {
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
    x: AuthSession<MemoryAuthStore>,
    State(state): State<AppState>,
    Form(LoginForm {
        name,
        password,
        next,
    }): Form<LoginForm>,
) -> impl IntoResponse {
    println!("{next:?}");

    let Some(user_id) = state.auth.login(name, password).await else {
        return Redirect::to("/login?error=Wrong password or username").into_response();
    };

    let x = x.log_in("password".into(), user_id).await;

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
async fn get_logout_handler(x: AuthSession<MemoryAuthStore>) -> impl IntoResponse {
    let x = x.log_out().await;

    (x, Redirect::to("/"))
    // let x = x.log_out().await;
    // (x, Redirect::to("/"))
}

#[debug_handler(state = AppState)]
async fn get_root_handler(x: AuthSession<MemoryAuthStore>) -> impl IntoResponse {
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
