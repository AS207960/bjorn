CREATE TABLE orders (
    id UUID PRIMARY KEY NOT NULL,
    account UUID NOT NULL,
    ca_id bytea UNIQUE NOT NULL,
    FOREIGN KEY (account) REFERENCES accounts(id)
);

CREATE INDEX order_id_index on orders(id);
CREATE INDEX order_account_index on orders(account);

CREATE TABLE authorizations (
    id UUID NOT NULL,
    account UUID NOT NULL,
    ca_id bytea NOT NULL,
    FOREIGN KEY (account) REFERENCES accounts(id),
    PRIMARY KEY (id, account),
    UNIQUE  (account, ca_id)
);

CREATE INDEX authorization_id_index on authorizations(id);
CREATE INDEX authorization_account_index on authorizations(account);

CREATE TABLE certificates (
    id UUID NOT NULL PRIMARY KEY,
    ca_id bytea NOT NULL UNIQUE
);

CREATE INDEX certificaes_id_index on certificates(id);
