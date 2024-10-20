CREATE TABLE users (
    id UUID PRIMARY KEY NOT NULL,
    name TEXT,
    password_hash TEXT    
);

CREATE TABLE user_email (
    id UUID PRIMARY KEY NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    verified BOOLEAN NOT NULL,
    allow_link_login BOOLEAN NOT NULL,

    UNIQUE(address)
);

CREATE TABLE email_challenge (
    id UUID PRIMARY KEY,
    address TEXT NOT NULL,
    code TEXT NOT NULL,
    next TEXT,
    expires TIMESTAMPTZ NOT NULL    
);

CREATE TABLE oauth_token (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_name TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    expires TIMESTAMPTZ,
    scopes TEXT[] NOT NULL,

    UNIQUE(user_id, provider_name),
    UNIQUE(provider_user_id, provider_name)
);

CREATE TABLE login_session (
    id UUID PRIMARY KEY NOT NULL,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method TEXT NOT NULL,
    oauth_token_id UUID REFERENCES oauth_token(id),
    email_address TEXT REFERENCES user_email(address)
);

CREATE INDEX idx_oauth_token_provider_name ON oauth_token(provider_name);
CREATE INDEX idx_user_email_address ON user_email(address);
CREATE INDEX idx_email_challenge_code ON email_challenge(code);
