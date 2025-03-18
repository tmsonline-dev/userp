# Userp-Server

This crate contains most of the logic of Userp. It defines the traits to be implemented for integration with the app code, models not likely to be used in client code, all authentication flows, cookie handling logic, etc.

While it aims to be as close as reasonable to generic in terms of server ecosystem, it may include some code for a specific framework (like Axum) where it would have been impractical or impossible to break that out into its own crate. Like most other things in Userp, that will be behind a cargo feature flag.

## The Userp struct

This is the main construct with which you interact with Userp as a system. The crate includes logic to extract it from the app state behind the `axum` trait. From there, you can use it to access the store, configuration, the method actions (oauth login, email signup etc.), session information (including the current logged in user) and more.

## Features

| Name              | Function                                                                                                                                   |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `default`         | Enables the `account`, `email`, `password` and `oauth` features                                                                            |
| `account`         | Extends                                                                                                                                    |
| `email`           | Extends LoginMethod with the Email member (and if `password` is active, the PasswordReset member), along with adding its associated routes |
| `password`        | Extends LoginMethod with the Password member (and if `email` is active, the PasswordReset member), along with adding its associated routes |
| `oauth`           | Enables the OAuth action routes, ie login, signup, link and refresh. Requires and enables `oauth-callbacks`                                |
| `oauth-callbacks` | Extends LoginMethod with the Oauth member, along with adding its associated routes                                                         |
