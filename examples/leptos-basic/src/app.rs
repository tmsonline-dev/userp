use crate::{
    error_template::{AppError, ErrorTemplate},
    models::MyUser,
};
use leptos::*;
use leptos_meta::*;
use leptos_router::*;
use userp::routes::Routes;

#[component]
pub fn App() -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context();

    view! {
        <Stylesheet id="leptos" href="/pkg/leptos-basic.css" />

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
pub async fn get_user() -> Result<Option<MyUser>, ServerFnError> {
    let auth = expect_context::<crate::store::Userp>();

    Ok(auth.user().await?)
}

/// Renders the home page of your application.
#[component]
fn HomePage() -> impl IntoView {
    // Creates a reactive value to update the button
    let (count, set_count) = create_signal(0);
    let on_click = move |_| set_count.update(|count| *count += 1);

    let user = create_resource(|| (), |_| get_user());

    view! {
        <h1>"Welcome to Leptos/Userp!"</h1>
        <button on:click=on_click>"Click Me: " {count}</button>
        <div>
            <Suspense fallback=|| {
                view! { "Loading..." }
            }>

                {match user() {
                    Some(Ok(Some(user))) => view! { <LoggedIn user=user /> },
                    Some(Ok(None)) => view! { <NotLoggedIn /> },
                    _ => view! { <div>"¯\\_(ツ)_/¯"</div> }.into_view(),
                }}
            </Suspense>
        </div>
    }
}

#[component]
fn LoggedIn(user: MyUser) -> impl IntoView {
    let routes = expect_context::<Routes>();

    view! {
        <p>"You are logged in with user id " <span>{user.id.to_string()}</span></p>
        <a href=routes.logout rel="external">
            "Log out"
        </a>
        <br />
        <a href=routes.pages.user rel="external">
            "Account"
        </a>
    }
}
#[component]
fn NotLoggedIn() -> impl IntoView {
    let routes = expect_context::<Routes>();

    view! {
        <p>"You are not logged in"</p>
        <a href=routes.pages.login rel="external">
            "Log in"
        </a>
        <br />
        <a href=routes.pages.signup rel="external">
            "Sign up"
        </a>
    }
}
