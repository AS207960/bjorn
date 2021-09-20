CREATE TABLE nonces (
    nonce UUID PRIMARY KEY NOT NULL,
    issued_at timestamp with time zone NOT NULL
);