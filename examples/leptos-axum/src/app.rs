use crate::{
    error_template::{AppError, ErrorTemplate},
    models::{MyRoutes, MyUser},
};
use leptos::*;
use leptos_meta::*;
use leptos_router::*;

#[component]
pub fn App() -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context();

    view! {
        <Stylesheet id="leptos" href="/pkg/user-leptos-axum-example.css" />

        // sets the document title
        <Title text="Welcome to Leptos" />

        // content for this welcome page
        <Router fallback=|| {
            let mut outside_errors = Errors::default();
            outside_errors.insert_with_default_key(AppError::NotFound);
            view! { <ErrorTemplate outside_errors /> }.into_view()
        }>
            <main>
                <Routes>
                    <Route path="" view=HomePage />
                </Routes>
            </main>
        </Router>
    }
}

#[server]
pub async fn get_user_and_routes() -> Result<(Option<MyUser>, MyRoutes), ServerFnError> {
    let auth = expect_context::<crate::server::Userp>();

    let routes = MyRoutes {
        account: auth.routes.pages.user.clone(),
        log_in: auth.routes.pages.login.clone(),
        sign_up: auth.routes.pages.signup.clone(),
        log_out: auth.routes.logout.clone(),
    };

    Ok((auth.user().await?, routes))
}

/// Renders the home page of your application.
#[component]
fn HomePage() -> impl IntoView {
    // Creates a reactive value to update the button
    let (count, set_count) = create_signal(0);
    let on_click = move |_| set_count.update(|count| *count += 1);

    let user = create_resource(|| (), |_| get_user_and_routes());

    view! {
        <h1>"Welcome to Leptos/Userp!"</h1>
        <button on:click=on_click>"Click Me: " {count}</button>
        <div>
            <Suspense fallback=|| {
                view! { "Loading..." }
            }>
                {user()
                    .map(|res| {
                        res.map(|(user, routes)| match user {
                            Some(user) => {
                                view! {
                                    <p>
                                        "You are logged in with user id "
                                        <span>{user.id.to_string()}</span>
                                    </p>
                                    <a href=routes.log_out rel="external">
                                        "Log out"
                                    </a>
                                    <a href=routes.account rel="external">
                                        "Account"
                                    </a>
                                }
                            }
                            None => {
                                view! {
                                    <p>"You are not logged in"</p>
                                    <a href=routes.log_in rel="external">
                                        "Log in"
                                    </a>
                                    <a href=routes.sign_up rel="external">
                                        "Sign up"
                                    </a>
                                }
                            }
                        })
                    })}
            </Suspense>
        </div>
    }
}
