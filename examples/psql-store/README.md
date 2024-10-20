# Userp PSQL example

To run...

1. Copty `.env.template` to `.env` and enter your GitHub and Spotify client credentials (or remove them from `src/main.rs:58`) and your SMTP settings
1. Set up a postgres instance and edit the connection string, or run `docker compose up`
1. Run `sqlx db setup` to apply the initial migration.
1. Run `cargo run` to start the server at `http://localhost:3000`
