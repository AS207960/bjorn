CREATE TYPE account_status as ENUM ('valid', 'deactivated', 'revoked');

CREATE TABLE accounts (
    id UUID PRIMARY KEY NOT NULL,
    created_at timestamp with time zone NOT NULL,
    tos_agreed_at timestamp with time zone NOT NULL,
    status account_status NOT NULL,
    public_key bytea NOT NULL,
    eab_id varchar,
    eab_protected_header varchar,
    eab_payload varchar,
    eab_sig varchar
);

CREATE INDEX account_id_index on accounts(id);
CREATE INDEX account_key_index on accounts(public_key);

CREATE TYPE account_contact_type as ENUM ('email');

CREATE TABLE account_contacts (
    id UUID PRIMARY KEY NOT NULL,
    account UUID NOT NULL,
    contact_type account_contact_type NOT NULL,
    contact_value varchar NOT NULL,
    FOREIGN KEY (account) REFERENCES accounts(id)
);

CREATE INDEX account_contact_account_index on account_contacts(account);