# Userp-Client

This crate contains models likely to be used in client (browser) code, including LoginMethod, Routes etc.

## Features

| Name              | Function                                                                                                                                       |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `default`         | Enables the `account`, `email`, `password` and `oauth` features                                                                                |
| `account`         | Extends Routes and PageRoutes with required routes                                                                                             |
| `email`           | Extends LoginMethod with the Email member (and if `password` is active, the PasswordReset member), along with adding its associated routes |
| `password`        | Extends LoginMethod with the Password member (and if `email` is active, the PasswordReset member), along with adding its associated routes |
| `oauth`           | Enables the OAuth action routes, ie login, signup, link and refresh. Requires and enables `oauth-callbacks`                                    |
| `oauth-callbacks` | Extends LoginMethod with the Oauth member, along with adding its associated routes                                                         |
