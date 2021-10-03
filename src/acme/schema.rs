table! {
    account_contacts (id) {
        id -> Uuid,
        account -> Uuid,
        contact_type -> crate::acme::models::AccountContactTypeMapping,
        contact_value -> Varchar,
    }
}

table! {
    accounts (id) {
        id -> Uuid,
        created_at -> Timestamptz,
        tos_agreed_at -> Timestamptz,
        status -> crate::acme::models::AccountStatusMapping,
        public_key -> Bytea,
        eab_id -> Nullable<Varchar>,
        eab_protected_header -> Nullable<Varchar>,
        eab_payload -> Nullable<Varchar>,
        eab_sig -> Nullable<Varchar>,
    }
}

table! {
    nonces (nonce) {
        nonce -> Uuid,
        issued_at -> Timestamptz,
    }
}

table! {
    orders (id) {
        id -> Uuid,
        account -> Uuid,
        ca_id -> Bytea,
    }
}

table! {
    authorizations (id) {
        id -> Uuid,
        account -> Uuid,
        ca_id -> Bytea,
    }
}

table! {
    certificates (id) {
        id -> Uuid,
        ca_id -> Bytea,
    }
}

table! {
    tos_agreement_tokens (id) {
        id -> Uuid,
        account -> Uuid,
        expires_at -> Timestamptz,
    }
}

joinable!(account_contacts -> accounts (account));
joinable!(orders -> accounts (account));
joinable!(authorizations -> accounts (account));
joinable!(tos_agreement_tokens -> accounts (account));

allow_tables_to_appear_in_same_query!(
    account_contacts,
    accounts,
    nonces,
    orders,
    authorizations,
    certificates,
    tos_agreement_tokens,
);
