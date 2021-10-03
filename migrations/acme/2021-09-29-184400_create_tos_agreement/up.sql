CREATE TABLE tos_agreement_tokens (
    id UUID PRIMARY KEY NOT NULL,
    account UUID NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    FOREIGN KEY (account) REFERENCES accounts(id)
);

CREATE INDEX tos_agreement_tokens_id_index on tos_agreement_tokens(id);
