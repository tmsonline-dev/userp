# Axum-User

## Work in progress

Warning: This crate is heavily WIP! I'm holding off on doc-comments until I've worked out the module hierarchy and basic API to my satisfaction.

## Summary

This crate provides a high-level user, authentication and session handling system for Axum. The idea is to use it as a base for something like Next Auth but for Leptos, being easy to set up while heavy on features.

## Features

- Login types
  - Username / Password
  - Email magic link
  - Social logins (OAuth)
- Emails
  - Validation
  - Password reset
- Oauth
  - Ergonomic user info fetching
  - Optional split callback paths
  - Easily extendable with custom providers
- Batteries included
  - Askama based templates provide basic login/signup/account pages
  - Growing list of built-in social providers
  - Multiple sessions

## Todo
- [ ] Use configured paths in templates
- [ ] Granular feature-controlled templates
- [ ] Replacable templates (by typed Fns returning impl IntoResponse)
- [ ] Webauthn
- [ ] MFA
- [ ] Doc-comments
- [ ] Tests
- [ ] ???
- [ ] Publish!

