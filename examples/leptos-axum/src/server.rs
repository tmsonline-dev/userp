mod models;
mod store;

use crate::app::*;
use crate::fileserv::file_and_error_handler;
use axum::{
    body::Body,
    extract::{FromRef, State},
    response::IntoResponse,
    routing::get,
    Router,
};
use dotenvy::var;
use leptos::*;
use leptos_axum::{generate_route_list, handle_server_fns_with_context, LeptosRoutes};
use store::MemoryStore;
use userp::{prelude::*, url::Url, Userp as BaseUserp};

pub type Userp = BaseUserp<MemoryStore>;

#[derive(Clone, FromRef)]
pub struct AppState {
    pub store: MemoryStore,
    pub auth_config: UserpConfig,
    pub leptos_options: LeptosOptions,
}

pub async fn leptos_routes_handler(
    auth: Userp,
    State(state): State<AppState>,
    req: http::Request<Body>,
) -> http::Response<Body> {
    let handler = leptos_axum::render_app_to_stream_with_context(
        state.leptos_options.clone(),
        move || {
            provide_context(auth.clone());
        },
        || view! { <App /> },
    );

    handler(req).await
}

pub async fn server_fn_handler(auth: Userp, request: http::Request<Body>) -> impl IntoResponse {
    handle_server_fns_with_context(
        move || {
            provide_context(auth.clone());
        },
        request,
    )
    .await
}

fn userp_setup() -> (UserpConfig, Router<AppState>) {
    let req_var = |name: &'static str| {
        var(name).unwrap_or_else(|_| panic!("Missing required env var: {name}"))
    };

    let base_url = Url::parse("http://localhost:3000").unwrap();

    let key = String::from("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    let config = UserpConfig::new(
        key,
        Routes::default(),
        PasswordConfig::new().with_allow_reset(PasswordReset::AnyUserEmail),
        EmailConfig::new(
            base_url.clone(),
            SmtpSettings {
                server_url: req_var("SMTP_URL"),
                username: req_var("SMTP_USERNAME"),
                password: req_var("SMTP_PASSWORD"),
                from: req_var("SMTP_FROM"),
                starttls: true,
            },
        ),
        OAuthConfig::new(base_url)
            .with_client(SpotifyOAuthProvider::new(
                req_var("SPOTIFY_CLIENT_ID"),
                req_var("SPOTIFY_CLIENT_SECRET"),
            ))
            .with_client(GitHubOAuthProvider::new(
                req_var("GITHUB_CLIENT_ID"),
                req_var("GITHUB_CLIENT_SECRET"),
            ))
            .with_client(GitLabOAuthProvider::new(
                req_var("GITLAB_CLIENT_ID"),
                req_var("GITLAB_CLIENT_SECRET"),
            ))
            .with_client(GoogleOAuthProvider::new(
                req_var("GOOGLE_CLIENT_ID"),
                req_var("GOOGLE_CLIENT_SECRET"),
            )),
    )
    .with_https_only(false);

    let router = config.router::<MemoryStore, AppState>();

    (config, router)
}

pub async fn serve() {
    // Setting get_configuration(None) means we'll be using cargo-leptos's env values
    // For deployment these variables are:
    // <https://github.com/leptos-rs/start-axum#executing-a-server-on-a-remote-machine-without-the-toolchain>
    // Alternately a file can be specified such as Some("Cargo.toml")
    // The file would need to be included with the executable when moved to deployment
    let conf = get_configuration(None).await.unwrap();
    let leptos_options = conf.leptos_options;
    let addr = leptos_options.site_addr;
    let leptos_routes = generate_route_list(App);

    let (auth_config, auth_router) = userp_setup();

    let state = AppState {
        store: MemoryStore::default(),
        auth_config,
        leptos_options,
    };

    // build our application with a route
    let app = Router::new()
        .merge(auth_router)
        .route(
            "/api/*fn_name",
            get(server_fn_handler).post(server_fn_handler),
        )
        .leptos_routes_with_handler(leptos_routes, get(leptos_routes_handler))
        .fallback(file_and_error_handler)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    logging::log!("listening on http://{}", &addr);
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}
