mod forms;
mod queries;
mod templates;

use askama_axum::IntoResponse;
use axum::{
    extract::{FromRef, Path, Query},
    response::Redirect,
    routing::{get, post},
    Form, Router,
};
use forms::*;
use queries::*;
use reqwest::StatusCode;
use templates::*;
use urlencoding::encode;

use crate::{
    AxumUser, AxumUserConfig, AxumUserExtendedStore, LoginSession, OAuthToken, RefreshInitResult,
    User,
};

impl AxumUserConfig {
    pub fn routes<St, S>(&self) -> Router<S>
    where
        AxumUserConfig: FromRef<S>,
        S: Send + Sync + Clone + 'static,
        St: AxumUserExtendedStore + FromRef<S> + Send + Sync + 'static,
    {
        Router::new()
            .route(
                "/",
                get(|auth: AxumUser<St>| async move {
                    let logged_in = auth.logged_in().await;

                    IndexTemplate { logged_in }
                }),
            )
            .route(
                "/login",
                get(
                    |auth: AxumUser<St>,
                     Query(NextMessageErrorQuery {
                         next,
                         message,
                         error,
                         ..
                     }): Query<NextMessageErrorQuery>| async move {
                        if auth.logged_in().await {
                            Redirect::to("/user").into_response()
                        } else {
                            LoginTemplate {
                                next,
                                message,
                                error,
                                oauth_providers: auth.oauth_login_providers().into_iter().map(|p| p.into()).collect(),
                            }
                            .into_response()
                        }
                    },
                ),
            )
            .route("/login/password", post(|auth: AxumUser<St>, Form(EmailPasswordNextForm { email, password, next }): Form<EmailPasswordNextForm>| async move {
                match auth.password_login(email, password).await {
                    Ok(auth) => {
                        let next = next.unwrap_or("/user".into());
                        (auth, Redirect::to(&next)).into_response()
                    }
                    Err(err) => {
                        let next = format!("/login?error={}", urlencoding::encode(&err.to_string()));
                        Redirect::to(&next).into_response()
                    }
                }
            }))
            .route(
                "/login/email",
                post(|auth: AxumUser<St>, Form(EmailNextForm { email, next }): Form<EmailNextForm>| async move {
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
                })
                .get(|auth: AxumUser<St>, Query(CodeQuery { code }): Query<CodeQuery>| async move {
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
                }),
            )
            .route("/login/oauth", post(|auth: AxumUser<St>, Form(ProviderNextForm { provider, next }): Form<ProviderNextForm>| async move {
                match auth.oauth_login_init(provider, next).await {
                    Ok((auth, redirect_url)) => (auth, Redirect::to(redirect_url.as_str())).into_response(),
                    Err(err) => {
                        let next = format!("/login?error={}", urlencoding::encode(&err.to_string()));
                        Redirect::to(&next).into_response()
                    }
                }
            }))
            .route(
                "/login/oauth/:provider",
                get(|auth: AxumUser<St>, Path(ProviderPath { provider }): Path<ProviderPath>, Query(CodeStateQuery { code, state }): Query<CodeStateQuery>| async move {
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
                }),
            )
            .route("/signup", get(|auth: AxumUser<St>, Query(NextMessageErrorQuery { error, message, next, .. }): Query<NextMessageErrorQuery>| async move {
                SignupTemplate {
                    error,
                    message,
                    next,
                    oauth_providers: auth.oauth_signup_providers().into_iter().map(|p| p.into()).collect(),
                }
                .into_response()
            }))
            .route("/signup/password", post(|auth: AxumUser<St>, Form(EmailPasswordNextForm { email, password, next }): Form<EmailPasswordNextForm>| async move {
                if password.len() <= 3 {
                    return Redirect::to("/signup?error=Password must include more than 3 letters")
                        .into_response();
                }

                match auth.password_signup(email, password).await {
                    Ok(auth) => {
                        let next = next.unwrap_or("/user".into());
                        (auth, Redirect::to(&next)).into_response()
                    }
                    Err(err) => {
                        let next = format!("/signup?error={}", urlencoding::encode(&err.to_string()));
                        Redirect::to(&next).into_response()
                    }
                }
            }))
            .route(
                "/signup/email",
                post(|auth: AxumUser<St>, Form(EmailNextForm { email, next }): Form<EmailNextForm>| async move {
                    match auth.email_signup_init(email.clone(), next).await {
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
                })
                .get(|auth: AxumUser<St>, Query(CodeQuery { code }): Query<CodeQuery>| async move {
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
                }),
            )
            .route("/signup/oauth", post(|auth: AxumUser<St>, Form(ProviderNextForm { provider, next }): Form<ProviderNextForm>| async move {
                match auth.oauth_signup_init(provider, next).await {
                    Ok((auth, redirect_url)) => (auth, Redirect::to(redirect_url.as_str())).into_response(),
                    Err(err) => {
                        let next = format!("/signup?error={}", urlencoding::encode(&err.to_string()));
                        Redirect::to(&next).into_response()
                    }
                }
            }))
            .route(
                "/signup/oauth/:provider",
                get(|auth: AxumUser<St>, Path(ProviderPath { provider }): Path<ProviderPath>, Query(CodeStateQuery { code, state }): Query<CodeStateQuery>| async move {
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
                }),
            )
            .route("/user", get(|auth: AxumUser<St>, Query(NextMessageErrorQuery { error, message, .. }): Query<NextMessageErrorQuery>| async move {
                if let Some(user) = auth.user().await {
                    let sessions = auth.store.get_sessions(user.get_id()).await;
                    let oauth_tokens = auth.store.get_oauth_tokens(user.get_id()).await;
                    let emails = auth.store.get_user_emails(user.get_id()).await;

                    UserTemplate {
                        message,
                        error,
                        sessions: sessions.into_iter().map(|s| s.into()).collect(),
                        has_password: user.get_password_hash().is_some(),
                        emails: emails.into_iter().map(|e| e.into()).collect(),
                        oauth_providers: auth
                            .oauth_link_providers()
                            .into_iter()
                            .filter(|p| !oauth_tokens.iter().any(|t| t.provider_name() == p.name()))
                            .map(|p| p.into())
                            .collect(),
                        oauth_tokens: oauth_tokens.into_iter().map(|t| t.into()).collect(),
                    }
                    .into_response()
                } else {
                    println!("User not found in store");
                    Redirect::to("/login?next=%UFuser").into_response()
                }
            }))
            .route("/user/delete", post(|auth: AxumUser<St>| async move {
                if let Some(user) = auth.user().await {
                    auth.store.delete_user(user.get_id()).await;

                    let auth = auth.log_out().await;

                    (auth, Redirect::to("/")).into_response()
                } else {
                    StatusCode::UNAUTHORIZED.into_response()
                }
            }))
            .route("/user/logout", get(|auth: AxumUser<St>| async move {
                let auth = auth.log_out().await;

                (auth, Redirect::to("/"))
            }))
            .route(
                "/user/verify-session",
                get(|auth: AxumUser<St>| async move {
                    if auth.logged_in().await {
                        StatusCode::OK
                    } else {
                        StatusCode::UNAUTHORIZED
                    }
                }),
            )
            .route(
                "/user/password/set",
                post(|auth: AxumUser<St>, Form(NewPasswordForm { new_password }): Form<NewPasswordForm>| async move {
                    let mut user_session = auth.user_session().await;

                    if user_session.is_none() {
                        user_session = auth.reset_user_session().await;
                    }

                    let Some((user, session)) = user_session else {
                        return StatusCode::UNAUTHORIZED.into_response();
                    };

                    auth.store
                        .set_user_password(user.get_id(), new_password, session.get_id())
                        .await;

                    Redirect::to("/user?message=The password has been set!").into_response()
                }),
            )
            .route(
                "/user/password/delete",
                post(|auth: AxumUser<St>| async move {
                    let Some((user, session)) = auth.user_session().await else {
                        return StatusCode::UNAUTHORIZED.into_response();
                    };

                    auth.store
                        .clear_user_password(user.get_id(), session.get_id())
                        .await;

                    (auth, Redirect::to("/user?message=Password cleared")).into_response()
                }),
            )
            .route("/user/oauth/link", post(|auth: AxumUser<St>, Form(ProviderNextForm { provider, next }): Form<ProviderNextForm>| async move {
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
            }))
            .route(
                "/user/oauth/link/:provider",
                get(|auth: AxumUser<St>, Path(ProviderPath { provider }): Path<ProviderPath>, Query(CodeStateQuery { code, state }): Query<CodeStateQuery>| async move {
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
                }),
            )
            .route(
                "/user/session/delete",
                post(|auth: AxumUser<St>, Form(IdForm { id }): Form<IdForm>| async move {
                    if !auth.logged_in().await {
                        return StatusCode::UNAUTHORIZED.into_response();
                    };

                    auth.store.delete_session(id).await;

                    Redirect::to("/user?message=Session deleted").into_response()
                }),
            )
            .route(
                "/user/oauth/refresh",
                post(|auth: AxumUser<St>, Form(IdForm { id: token_id }): Form<IdForm>| async move {
                    if !auth.logged_in().await {
                        return StatusCode::UNAUTHORIZED.into_response();
                    };

                    let Some(token) = auth.store.get_oauth_token(token_id).await else {
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
                }),
            )
            .route(
                "/user/oauth/refresh/:provider",
                get(|auth: AxumUser<St>, Path(ProviderPath { provider }): Path<ProviderPath>, Query(CodeStateQuery { code, state }): Query<CodeStateQuery>| async move {
                    match auth
                        .oauth_refresh_callback(provider.clone(), code, state)
                        .await
                    {
                        Ok(next) => {
                            let next = next.unwrap_or(format!("/user?message={} token refreshed!", provider));
                            Redirect::to(&next)
                        }
                        Err(err) => {
                            let next = format!("/user?error={}", urlencoding::encode(&err.to_string()));
                            Redirect::to(&next)
                        }
                    }
                }),
            )
            .route(
                "/user/oauth/delete",
                post(|auth: AxumUser<St>, Form(IdForm { id }): Form<IdForm>| async move {
                    if !auth.logged_in().await {
                        return StatusCode::UNAUTHORIZED.into_response();
                    };

                    auth.store.delete_oauth_token(id).await;

                    Redirect::to("/user?message=Token deleted").into_response()
                }),
            )
            .route(
                "/user/email/verify",
                get(|auth: AxumUser<St>, Query(CodeQuery { code }): Query<CodeQuery>| async move {
                    match auth.email_verify_callback(code).await {
                        Ok((address, next)) => {
                            let next = match next {
                                Some(next) => next,
                                None => {
                                    if auth.logged_in().await {
                                        format!("/user?message={} verified!", urlencoding::encode(&address))
                                    } else {
                                        format!("/login?message={} verified!", urlencoding::encode(&address))
                                    }
                                }
                            };

                            Redirect::to(&next)
                        }
                        Err(err) => {
                            let next = format!("/login?error={}", urlencoding::encode(err));
                            Redirect::to(&next)
                        }
                    }
                })
                .post(|auth: AxumUser<St>, Form(EmailForm { email }): Form<EmailForm>| async move {
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
                }),
            )
            .route("/user/email/add", post(|auth: AxumUser<St>, Form(EmailForm { email }): Form<EmailForm>| async move {
                let Some(user) = auth.user().await else {
                    return StatusCode::UNAUTHORIZED.into_response();
                };

                auth.store.add_user_email(user.get_id(), email).await;

                Redirect::to("/user?message=Email added").into_response()
            }))
            .route("/user/email/delete", post(|auth: AxumUser<St>, Form(EmailForm { email }): Form<EmailForm>| async move {
                let Some(user) = auth.user().await else {
                    return StatusCode::UNAUTHORIZED.into_response();
                };

                auth.store.delete_user_email(user.get_id(), email).await;

                Redirect::to("/user?message=Email deleted").into_response()
            }))
            .route("/user/email/enable_login", post(|auth: AxumUser<St>, Form(EmailForm { email }): Form<EmailForm>| async move {
                let Some(user) = auth.user().await else {
                    return StatusCode::UNAUTHORIZED.into_response();
                };

                auth.store
                    .set_user_email_allow_login(user.get_id(), email.clone(), true)
                    .await;

                Redirect::to(&format!(
                    "/user?message={}",
                    encode(&format!("You can now log in directly with {email}"))
                ))
                .into_response()
            }))
            .route("/user/email/disable_login", post(|auth: AxumUser<St>, Form(EmailForm { email }): Form<EmailForm>| async move {
                let Some(user) = auth.user().await else {
                    return StatusCode::UNAUTHORIZED.into_response();
                };

                auth.store
                    .set_user_email_allow_login(user.get_id(), email.clone(), false)
                    .await;

                Redirect::to(&format!(
                    "/user?message={}",
                    encode(&format!("You can no longer log in directly with {email}"))
                ))
                .into_response()
            }))
            .route(
                "/password/send-reset",
                get(|Query(query): Query<AddressMessageSentErrorQuery>| async move {
                    SendResetPasswordTemplate {
                        sent: query.sent.is_some_and(|sent| sent),
                        address: query.address,
                        error: query.error,
                        message: query.message,
                    }
                    .into_response()
                })
                .post(|auth: AxumUser<St>, Form(EmailNextForm { email, next }): Form<EmailNextForm>| async move {
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
                }),
            )
            .route(
                "/password/reset",
                get(|auth: AxumUser<St>, Query(query): Query<CodeQuery>| async move {
                    match auth.email_reset_callback(query.code).await {
                        Ok(auth) => (auth, ResetPasswordTemplate).into_response(),
                        Err((auth, err)) => {
                            (auth, Redirect::to(&format!("/login?err={}", encode(err)))).into_response()
                        }
                    }
                })
                .post(|auth: AxumUser<St>, Form(NewPasswordForm { new_password }): Form<NewPasswordForm>| async move {
                    if let Some((user, session)) = auth.reset_user_session().await {
                        auth.store
                            .set_user_password(user.get_id(), new_password, session.get_id())
                            .await;
                        Redirect::to("/login?message=Password has been reset").into_response()
                    } else {
                        StatusCode::UNAUTHORIZED.into_response()
                    }
                }),
            )
    }
}
