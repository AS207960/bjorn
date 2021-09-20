use diesel::prelude::*;
use std::convert::TryInto;
use crate::{types, DBConn};

pub mod jws;
mod responses;
mod links;
pub mod processing;
mod models;
mod schema;
mod replay;

pub type ACMEResult<I> = Result<I, types::error::Error>;

#[macro_export]
macro_rules! try_db_result {
    ($src:expr, $err:expr) => {
        (match ($src) {
            Ok(inner) => Ok(inner),
            Err(err) => {
                error!($err, err);
                Err(crate::internal_server_error!())
            }
        })
    }
}

#[macro_export]
macro_rules! internal_server_error {
    () => {
        crate::types::error::Error {
            error_type: crate::types::error::Type::ServerInternal,
            status: 500,
            title: String::from("Internal Server Error"),
            detail: "Something really went wrong there, we have no idea what it was".to_string(),
            sub_problems: vec ! [],
            instance: None,
            identifier: None,
        }
    }
}

#[inline]
fn try_tonic_result<T>(src: Result<T, tonic::Status>) -> ACMEResult<T> {
    src.map_err(|err| {
        match err.code() {
            tonic::Code::NotFound => types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 404,
                title: "Object does not exist".to_string(),
                detail: err.message().to_string(),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            },
            tonic::Code::PermissionDenied => types::error::Error {
                error_type: types::error::Type::Unauthorized,
                status: 403,
                title: "Permission denied".to_string(),
                detail: err.message().to_string(),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            },
            tonic::Code::InvalidArgument => types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 400,
                title: "Invalid data".to_string(),
                detail: err.message().to_string(),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            },
            _ => {
                error!("Unable to complete upstream CA request: {}", err);
                internal_server_error!()
            }
        }
    })
}

macro_rules! try_result {
    ($src:expr) => {
        (match ($src) {
            Ok(inner) => inner,
            Err(err) => {
                return responses::ACMEResponse::new_error(err);
            }
        })
    }
}

macro_rules! ensure_request_key_kid {
    ($src:expr) => {
        match $src {
            jws::JWSRequestKey::KID(k) => k,
            jws::JWSRequestKey::JWK { kid: _, key: _ } => {
                return responses::ACMEResponse::new_error(types::error::Error {
                    error_type: types::error::Type::Malformed,
                    status: 400,
                    title: "Bad request".to_string(),
                    detail: "'jwk' field cannot be used".to_string(),
                    sub_problems: vec![],
                    instance: None,
                    identifier: None,
                });
            }
        }
    }
}

macro_rules! ensure_request_key_jwk {
    ($src:expr) => {
        match $src {
            jws::JWSRequestKey::KID(_) => {
                return responses::ACMEResponse::new_error(types::error::Error {
                    error_type: types::error::Type::Malformed,
                    status: 400,
                    title: "Bad request".to_string(),
                    detail: "'kid' field cannot be used".to_string(),
                    sub_problems: vec![],
                    instance: None,
                    identifier: None,
                });
            }
            jws::JWSRequestKey::JWK { kid: _, key } => key
        }
    }
}

macro_rules! ensure_not_post_as_get {
    ($src:expr) => {
        match $src {
            Some(v) => v,
            None => {
                return responses::ACMEResponse::new_error(types::error::Error {
                    error_type: types::error::Type::Malformed,
                    status: 405,
                    title: "Method not allowed".to_string(),
                    detail: "POST-as-GET is not allowed".to_string(),
                    sub_problems: vec![],
                    instance: None,
                    identifier: None,
                });
            }
        }
    }
}

macro_rules! ensure_post_as_get {
    ($src:expr) => {
        match $src {
            None => {},
            Some(_) => {
                return responses::ACMEResponse::new_error(types::error::Error {
                    error_type: types::error::Type::Malformed,
                    status: 405,
                    title: "Method not allowed".to_string(),
                    detail: "POST-as-GET is required".to_string(),
                    sub_problems: vec![],
                    instance: None,
                    identifier: None,
                });
            }
        }
    }
}

macro_rules! decode_id {
    ($oid:expr) => {
        (match crate::util::b64_to_uuid($oid) {
            Some(v) => Ok(v),
            None => Err(types::error::Error {
                    error_type: types::error::Type::Malformed,
                    status: 400,
                    title: "Bad ID".to_string(),
                    detail: "Invalid ID format".to_string(),
                    sub_problems: vec![],
                    instance: None,
                    identifier: None,
                })
        })
    }
}

const DIRECTORY_URI: &'static str = "/directory";
const NEW_NONCE_URI: &'static str = "/acme/nonce";
const NEW_ACCOUNT_URI: &'static str = "/acme/new_account";
const KEY_CHANGE_URI: &'static str = "/acme/key_change";
const NEW_ORDER_URI: &'static str = "/acme/new_order";
const HOME_PAGE: &'static str = include_str!("index.html");

#[derive(Debug)]
pub struct Account {
    inner: models::Account,
    key: openssl::pkey::PKey<openssl::pkey::Public>,
}

fn lookup_account(kid: &str, db: &DBConn) -> ACMEResult<Option<Account>> {
    let kid_url = match url::Url::parse(kid) {
        Ok(v) => v,
        Err(err) => {
            return Err(types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 400,
                title: "Bad kid".to_string(),
                detail: format!("Invalid kid URL format: {}", err),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            });
        }
    };
    let kid_path = kid_url.path();
    let kid_str = match kid_path.strip_prefix("/acme/account/") {
        Some(v) => v,
        None => {
            return Err(types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 400,
                title: "Bad kid".to_string(),
                detail: "Invalid kid format".to_string(),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            });
        }
    };
    let kid_uuid = decode_id!(kid_str)?;

    let existing_account: Option<models::Account> = try_db_result!(schema::accounts::dsl::accounts.filter(
        schema::accounts::dsl::id.eq(&kid_uuid)
    ).first::<models::Account>(&db.0).optional(), "Unable to search for existing contact: {}")?;

    let existing_account = match existing_account {
        Some(v) => v,
        None => {
            return Ok(None);
        }
    };

    if existing_account.status == models::AccountStatus::Deactivated {
        return Err(types::error::Error {
            error_type: types::error::Type::Unauthorized,
            status: 401,
            title: "Unauthorized".to_string(),
            detail: format!("Account '{}' has been deactivated", kid),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        });
    } else if existing_account.status == models::AccountStatus::Revoked {
        return Err(types::error::Error {
            error_type: types::error::Type::Unauthorized,
            status: 401,
            title: "Unauthorized".to_string(),
            detail: format!("Account '{}' has been revoked by the sever", kid),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        });
    }

    let pkey = match openssl::pkey::PKey::public_key_from_der(&existing_account.public_key) {
        Ok(v) => v,
        Err(err) => {
            error!("Failed to decode public key from DB: {}", err);
            return Err(internal_server_error!());
        }
    };

    Ok(Some(Account {
        inner: existing_account,
        key: pkey,
    }))
}

pub struct ConfigFairing();

pub struct Config {
    external_uri: String,
    external_account_required: bool,
    caa_identities: Vec<String>,
    tos_uri: Option<String>,
    website_uri: Option<String>,
}

impl rocket::fairing::Fairing for ConfigFairing {
    fn info(&self) -> rocket::fairing::Info {
        rocket::fairing::Info {
            name: "Bj\u{f6}rn config loader",
            kind: rocket::fairing::Kind::Attach,
        }
    }

    fn on_attach(&self, rocket: rocket::Rocket) -> Result<rocket::Rocket, rocket::Rocket> {
        let external_uri = match rocket.config().get_string("external_uri") {
            Ok(v) => v,
            Err(e) => {
                error!("Unable to load external URI from config: {}", e);
                return Err(rocket);
            }
        };
        let external_account_required = match rocket.config().get_bool("external_account_required") {
            Ok(v) => v,
            Err(e) => {
                if let rocket::config::ConfigError::Missing(_) = e {
                    false
                } else {
                    error!("Unable to load external account required from config: {}", e);
                    return Err(rocket);
                }
            }
        };
        let caa_identities = match rocket.config().get_slice("caa_identities") {
            Ok(v) => match v.iter().map(|i| match i.as_str() {
                Some(i) => Ok(i.to_string()),
                None => {
                    error!("Unable to load CAA identities from config: array value not a string");
                    return Err(());
                }
            }).collect::<Result<Vec<_>, _>>() {
                Ok(v) => v,
                Err(_) => return Err(rocket)
            },
            Err(e) => {
                if let rocket::config::ConfigError::Missing(_) = e {
                    vec![]
                } else {
                    error!("Unable to load CAA identities from config: {}", e);
                    return Err(rocket);
                }
            }
        };
        let tos_uri = match rocket.config().get_string("tos_uri") {
            Ok(v) => Some(v),
            Err(e) => {
                if let rocket::config::ConfigError::Missing(_) = e {
                    None
                } else {
                    error!("Unable to load ToS URI from config: {}", e);
                    return Err(rocket);
                }
            }
        };
        let website_uri = match rocket.config().get_string("website_uri") {
            Ok(v) => Some(v),
            Err(e) => {
                if let rocket::config::ConfigError::Missing(_) = e {
                    None
                } else {
                    error!("Unable to load website URI from config: {}", e);
                    return Err(rocket);
                }
            }
        };

        Ok(
            rocket.manage(Config {
                external_uri,
                caa_identities,
                external_account_required,
                tos_uri,
                website_uri,
            })
        )
    }
}

embed_migrations!("migrations/acme");

pub struct DBMigrationFairing();

impl rocket::fairing::Fairing for DBMigrationFairing {
    fn info(&self) -> rocket::fairing::Info {
        rocket::fairing::Info {
            name: "DB Migration runner",
            kind: rocket::fairing::Kind::Attach,
        }
    }

    fn on_attach(&self, rocket: rocket::Rocket) -> Result<rocket::Rocket, rocket::Rocket> {
        let db_conn = match DBConn::get_one(&rocket) {
            Some(v) => v.0,
            None => {
                error!("Unable to get DB connection handle");
                return Err(rocket);
            }
        };

        if let Err(e) = embedded_migrations::run(&db_conn) {
            error!("Unable to run migrations: {}", e);
            return Err(rocket);
        }

        Ok(rocket)
    }
}

pub struct ClientData {
    user_agent: String,
    accept_languages: Vec<String>,
    accept: Option<rocket::http::Accept>,
}

impl<'a, 'r> rocket::request::FromRequest<'a, 'r> for ClientData {
    type Error = types::error::Error;

    fn from_request(request: &'a rocket::request::Request<'r>) -> rocket::request::Outcome<Self, Self::Error> {
        match request.headers().get_one("User-Agent") {
            Some(ua) => {
                let langs = match request.headers().get_one("Accept-Language") {
                    Some(l) => {
                        l.split(",").map(|l| {
                            let ls = l.trim().split_once(";");
                            let l = match ls {
                                None => l,
                                Some((lf, _)) => lf.trim()
                            };
                            l.to_string()
                        }).collect()
                    }
                    None => vec![]
                };
                rocket::request::Outcome::Success(ClientData {
                    user_agent: ua.to_string(),
                    accept_languages: langs,
                    accept: request.accept().map(|a| a.to_owned()),
                })
            }
            None => rocket::request::Outcome::Failure((rocket::http::Status::BadRequest, types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 400,
                title: "No User-Agent".to_string(),
                detail: "A User-Agent header is required to be set".to_string(),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            }))
        }
    }
}

#[get("/")]
pub fn index() -> rocket::response::content::Html<&'static str> {
    rocket::response::content::Html(HOME_PAGE)
}

#[get("/directory")]
pub fn directory(ua: ACMEResult<ClientData>, conf: rocket::State<Config>)
                 -> responses::InnerACMEResponse<'static, rocket_contrib::json::Json<types::directory::Directory>> {
    if let Err(err) = ua {
        return responses::InnerACMEResponse::Error(rocket_contrib::json::Json(err));
    }

    responses::InnerACMEResponse::Ok((rocket_contrib::json::Json(types::directory::Directory {
        new_nonce: format!("{}{}", conf.external_uri, NEW_NONCE_URI),
        new_account: Some(format!("{}{}", conf.external_uri, NEW_ACCOUNT_URI)),
        new_order: Some(format!("{}{}", conf.external_uri, NEW_ORDER_URI)),
        new_authz: None,
        revoke_cert: None,
        key_change: Some(format!("{}{}", conf.external_uri, KEY_CHANGE_URI)),
        meta: Some(types::directory::Meta {
            terms_of_service: conf.tos_uri.clone(),
            website: conf.website_uri.clone(),
            caa_identities: conf.caa_identities.clone(),
            external_account_required: Some(conf.external_account_required),
        }),
    }), rocket::http::Status::Ok))
}

#[post("/directory")]
pub fn directory_post() -> rocket::http::Status {
    rocket::http::Status::MethodNotAllowed
}

#[get("/acme/nonce")]
pub fn get_nonce() -> responses::ACMEResponse<'static, rocket::response::Response<'static>> {
    let response = rocket::response::Response::build()
        .status(rocket::http::Status::Ok)
        .raw_header("Cache-Control", "no-store")
        .finalize();
    responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
        (response, rocket::http::Status::Ok)
    ), vec![])
}

#[post("/acme/nonce")]
pub fn get_nonce_post() -> rocket::http::Status {
    rocket::http::Status::MethodNotAllowed
}

#[get("/acme/new_account")]
pub fn new_account() -> rocket::http::Status {
    rocket::http::Status::MethodNotAllowed
}

#[post("/acme/new_account", data = "<acct>")]
pub fn new_account_post(
    ua: ACMEResult<ClientData>,
    acct: ACMEResult<jws::JWSRequest<types::account::AccountCreate>>,
    db: DBConn,
    conf: rocket::State<Config>,
    client: rocket::State<processing::BlockingOrderClient>,
) -> responses::ACMEResponse<'static, responses::Headers<rocket_contrib::json::Json<types::account::Account>>> {
    try_result!(ua);
    let acct = try_result!(acct);
    let acct_key = ensure_request_key_jwk!(acct.key);
    let payload = ensure_not_post_as_get!(acct.payload);

    let acct_key_bytes = match acct_key.public_key_to_der() {
        Ok(v) => v,
        Err(_) => {
            return responses::ACMEResponse::new_error(internal_server_error!());
        }
    };

    let existing_account: Option<models::Account> = try_result!(try_db_result!(schema::accounts::dsl::accounts.filter(
        schema::accounts::dsl::public_key.eq(&acct_key_bytes)
    ).first::<models::Account>(&db.0).optional(), "Unable to search for existing account: {}"));

    if let Some(acct) = existing_account {
        let acct_obj = try_result!(acct.to_json(&db, &conf));
        return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
            (responses::Headers {
                responder: rocket_contrib::json::Json(acct_obj),
                headers: vec![("Location".to_string(), format!("{}{}", conf.external_uri, acct.kid()))],
            }, rocket::http::Status::Ok)
        ), vec![]);
    }

    if payload.only_return_existing {
        return responses::ACMEResponse::new_error(types::error::Error {
            error_type: types::error::Type::AccountDoesNotExist,
            status: 400,
            title: "Account does not exist".to_string(),
            detail: "Account with the provided key does not exist, and onlyReturnExisting field set".to_string(),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        });
    }

    if !payload.terms_of_service_agreed {
        return responses::ACMEResponse::new_error(types::error::Error {
            error_type: types::error::Type::Malformed,
            status: 400,
            title: "Bad request".to_string(),
            detail: "Terms of Service must be agreed to".to_string(),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        });
    }

    let account_id = uuid::Uuid::new_v4();
    let contacts = try_result!(models::parse_contacts(
        &payload.contact.iter().map(|c| c.as_ref()).collect::<Vec<_>>(), &account_id
    ));

    let now = chrono::Utc::now();
    let mut account = models::Account {
        id: account_id,
        created_at: now,
        tos_agreed_at: now,
        status: models::AccountStatus::Valid,
        public_key: acct_key_bytes,
        eab_id: None,
        eab_protected_header: None,
        eab_payload: None,
        eab_sig: None,
    };

    if let Some(eab) = payload.external_account_binding {
        let eab_id = try_result!(processing::verify_eab(&client, &eab, &acct.url, &acct_key));

        account.eab_id = Some(eab_id);
        account.eab_protected_header = Some(eab.protected);
        account.eab_payload = Some(eab.payload);
        account.eab_sig = Some(eab.signature);
    } else if conf.external_account_required {
        return responses::ACMEResponse::new_error(types::error::Error {
            error_type: types::error::Type::ExternalAccountRequired,
            status: 400,
            title: "External account required".to_string(),
            detail: "An external account must be used with this server".to_string(),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        });
    }

    try_result!(try_db_result!(db.0.transaction::<_, diesel::result::Error, _>(|| {
        diesel::insert_into(schema::accounts::dsl::accounts)
            .values(&account)
            .execute(&db.0)?;

        for contact in contacts {
            diesel::insert_into(schema::account_contacts::dsl::account_contacts)
                .values(contact)
                .execute(&db.0)?;
        }

        Ok(())
    }), "Unable to save account to database: {}"));

    let acct_obj = try_result!(account.to_json(&db, &conf));
    return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
        (responses::Headers {
            responder: rocket_contrib::json::Json(acct_obj),
            headers: vec![("Location".to_string(), format!("{}{}", conf.external_uri, account.kid()))],
        }, rocket::http::Status::Created)
    ), vec![]);
}


fn check_account(aid: &str, account: &Account) -> ACMEResult<()> {
    let aid_uuid = decode_id!(aid)?;

    if aid_uuid != account.inner.id {
        return Err(types::error::Error {
            error_type: types::error::Type::Unauthorized,
            status: 400,
            title: "Unauthorized".to_string(),
            detail: "Signing key does not match account URL".to_string(),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        });
    }

    Ok(())
}

#[get("/acme/account/<_aid>")]
pub fn account(_aid: String) -> rocket::http::Status {
    rocket::http::Status::MethodNotAllowed
}

#[post("/acme/account/<aid>", data = "<acct>")]
pub fn account_post(
    ua: ACMEResult<ClientData>,
    acct: ACMEResult<jws::JWSRequest<types::account::AccountUpdate>>,
    db: DBConn,
    conf: rocket::State<Config>,
    aid: String,
) -> responses::ACMEResponse<'static, rocket_contrib::json::Json<types::account::Account>> {
    try_result!(ua);
    let acct = try_result!(acct);
    let acct_key = ensure_request_key_kid!(acct.key);
    try_result!(check_account(&aid, &acct_key));

    let payload = match acct.payload {
        Some(v) => v,
        None => {
            let acct_obj = try_result!(acct_key.inner.to_json(&db, &conf));
            return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
                (rocket_contrib::json::Json(acct_obj), rocket::http::Status::Created)
            ), vec![]);
        }
    };


    if payload.status.is_some() {
        if payload.contact.is_some() {
            return responses::ACMEResponse::new_error(types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 400,
                title: "Update not allowed".to_string(),
                detail: "'status' can only be updated on its own".to_string(),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            });
        }

        let status = payload.status.unwrap();

        if status != types::account::Status::Deactivated {
            return responses::ACMEResponse::new_error(types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 400,
                title: "Update not allowed".to_string(),
                detail: "'status' can only be set to 'deactivated'".to_string(),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            });
        }

        let new_acct: models::Account = try_result!(try_db_result!(diesel::update(&acct_key.inner)
            .set(schema::accounts::dsl::status.eq(models::AccountStatus::Deactivated))
            .get_result(&db.0), "Unable to deactivate account: {}"));

        let acct_obj = try_result!(new_acct.to_json(&db, &conf));
        return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
            (rocket_contrib::json::Json(acct_obj), rocket::http::Status::Created)
        ), vec![]);
    }

    if let Some(new_contacts) = payload.contact {
        let contacts = try_result!(models::parse_contacts(
            &new_contacts.iter().map(|c| c.as_ref()).collect::<Vec<_>>(), &acct_key.inner.id
        ));

        try_result!(try_db_result!(db.0.transaction::<_, diesel::result::Error, _>(|| {
            diesel::delete(schema::account_contacts::dsl::account_contacts)
                .filter(schema::account_contacts::dsl::account.eq(&acct_key.inner.id))
                .execute(&db.0)?;

            for contact in contacts {
                diesel::insert_into(schema::account_contacts::dsl::account_contacts)
                    .values(contact)
                    .execute(&db.0)?;
            }

            Ok(())
        }), "Unable to save account to database: {}"));
    }

    let acct_obj = try_result!(acct_key.inner.to_json(&db, &conf));
    return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
        (rocket_contrib::json::Json(acct_obj), rocket::http::Status::Ok)
    ), vec![]);
}

#[get("/acme/account/<_aid>/orders")]
pub fn account_orders(_aid: String) -> rocket::http::Status {
    rocket::http::Status::MethodNotAllowed
}

#[post("/acme/account/<aid>/orders", data = "<acct>")]
pub fn account_orders_post(
    ua: ACMEResult<ClientData>,
    acct: ACMEResult<jws::JWSRequest<()>>,
    db: DBConn,
    conf: rocket::State<Config>,
    aid: String,
) -> responses::ACMEResponse<'static, rocket_contrib::json::Json<types::order::List>> {
    try_result!(ua);
    let acct = try_result!(acct);
    let acct_key = ensure_request_key_kid!(acct.key);
    ensure_post_as_get!(acct.payload);
    try_result!(check_account(&aid, &acct_key));

    let account_orders: Vec<models::Order> = try_result!(try_db_result!(schema::orders::dsl::orders.filter(
        schema::orders::dsl::account.eq(&acct_key.inner.id)
    ).load(&db.0), "Failed to get account orders: {}"));

    let list_obj = types::order::List {
        orders: account_orders.into_iter()
            .map(|o| format!("{}{}", conf.external_uri, o.url())).collect()
    };

    return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
        (rocket_contrib::json::Json(list_obj), rocket::http::Status::Ok)
    ), vec![]);
}

#[get("/acme/key_change")]
pub fn key_change() -> rocket::http::Status {
    rocket::http::Status::MethodNotAllowed
}

#[derive(Responder)]
pub enum KeyChangeResponse {
    Headers(responses::Headers<rocket_contrib::json::Json<types::error::Error>>),
    None(&'static str),
}

#[post("/acme/key_change", data = "<acct>")]
pub fn key_change_post(
    uri: &rocket::http::uri::Origin,
    ua: ACMEResult<ClientData>,
    acct: ACMEResult<jws::JWSRequest<types::jose::FlattenedJWS>>,
    db: DBConn,
    conf: rocket::State<Config>,
) -> responses::ACMEResponse<'static, KeyChangeResponse> {
    try_result!(ua);
    let acct = try_result!(acct);
    let acct_key = ensure_request_key_kid!(acct.key);
    let payload = ensure_not_post_as_get!(acct.payload);

    let inner_acct: jws::JWSRequestInner<types::account::KeyChange> = try_result!(jws::JWSRequestInner::from_jws(uri.path(), payload, &conf, &db));
    let new_acct_key = ensure_request_key_jwk!(inner_acct.key);

    let old_key: openssl::pkey::PKey<openssl::pkey::Public> = match (&inner_acct.payload.old_key).try_into() {
        Ok(v) => v,
        Err(err) => {
            return responses::ACMEResponse::new_error(types::error::Error {
                error_type: types::error::Type::BadPublicKey,
                status: 400,
                title: "Invalid public key".to_string(),
                detail: err.to_string(),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            });
        }
    };

    if inner_acct.payload.account != acct_key.inner.kid() {
        return responses::ACMEResponse::new_error(types::error::Error {
            error_type: types::error::Type::Malformed,
            status: 400,
            title: "Invalid change request".to_string(),
            detail: "Key change object is for a different account".to_string(),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        });
    }
    if !acct_key.key.public_eq(&old_key) {
        return responses::ACMEResponse::new_error(types::error::Error {
            error_type: types::error::Type::Malformed,
            status: 400,
            title: "Invalid change request".to_string(),
            detail: "Key change object key does not match account key".to_string(),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        });
    }

    let new_acct_key_bytes = match new_acct_key.public_key_to_der() {
        Ok(v) => v,
        Err(_) => {
            return responses::ACMEResponse::new_error(internal_server_error!());
        }
    };

    let existing_account: Option<models::Account> = try_result!(try_db_result!(schema::accounts::dsl::accounts.filter(
        schema::accounts::dsl::public_key.eq(&new_acct_key_bytes)
    ).first::<models::Account>(&db.0).optional(), "Unable to search for existing account: {}"));

    if let Some(acct) = existing_account {
        return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
            (KeyChangeResponse::Headers(responses::Headers {
                responder: rocket_contrib::json::Json(types::error::Error {
                    error_type: types::error::Type::Malformed,
                    status: 409,
                    title: "Conflict".to_string(),
                    detail: "Account already exists with the new key".to_string(),
                    sub_problems: vec![],
                    instance: None,
                    identifier: None,
                }),
                headers: vec![("Location".to_string(), format!("{}{}", conf.external_uri, acct.kid()))],
            }), rocket::http::Status::Conflict)
        ), vec![]);
    }

    try_result!(try_db_result!(diesel::update(&acct_key.inner)
            .set(schema::accounts::dsl::public_key.eq(new_acct_key_bytes))
            .execute(&db.0), "Unable to update account: {}"));

    return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
        (KeyChangeResponse::None(""), rocket::http::Status::Ok)
    ), vec![]);
}

#[get("/acme/new_order")]
pub fn new_order() -> rocket::http::Status {
    rocket::http::Status::MethodNotAllowed
}

#[post("/acme/new_order", data = "<order>")]
pub fn new_order_post(
    ua: ACMEResult<ClientData>,
    order: ACMEResult<jws::JWSRequest<types::order::OrderCreate>>,
    db: DBConn,
    conf: rocket::State<Config>,
    client: rocket::State<processing::BlockingOrderClient>,
) -> responses::ACMEResponse<'static, responses::Headers<rocket_contrib::json::Json<types::order::Order>>> {
    try_result!(ua);
    let acct = try_result!(order);
    let acct_key = ensure_request_key_kid!(acct.key);
    let payload = ensure_not_post_as_get!(acct.payload);

    let (db_order, ca_order) = try_result!(processing::create_order(&client, &db, &payload, &acct_key));

    let order_obj = try_result!(db_order.to_json(&db, ca_order, &conf));
    return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
        (responses::Headers {
            responder: rocket_contrib::json::Json(order_obj),
            headers: vec![("Location".to_string(), format!("{}{}", conf.external_uri, db_order.url()))],
        }, rocket::http::Status::Created)
    ), vec![]);
}

fn get_order(oid: &str, db: &DBConn, account: &Account) -> ACMEResult<models::Order> {
    let oid_uuid = decode_id!(oid)?;

    let existing_order: models::Order = match try_db_result!(schema::orders::dsl::orders.filter(
        schema::orders::dsl::id.eq(&oid_uuid)
    ).first::<models::Order>(&db.0).optional(), "Unable to search for order: {}")? {
        Some(o) => o,
        None => return Err(types::error::Error {
            error_type: types::error::Type::Malformed,
            status: 404,
            title: "Not found".to_string(),
            detail: format!("Order ID {} does not exist", oid),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        })
    };

    if existing_order.account != account.inner.id {
        return Err(types::error::Error {
            error_type: types::error::Type::Unauthorized,
            status: 400,
            title: "Unauthorized".to_string(),
            detail: format!("Order ID {} does not belong to the account", oid),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        });
    }

    Ok(existing_order)
}

fn get_authz(aid: &str, db: &DBConn, account: &Account) -> ACMEResult<models::Authorization> {
    let aid_uuid = decode_id!(aid)?;

    let existing_authz: models::Authorization = match try_db_result!(schema::authorizations::dsl::authorizations.filter(
        schema::authorizations::dsl::id.eq(&aid_uuid)
    ).first::<models::Authorization>(&db.0).optional(), "Unable to search for authorization: {}")? {
        Some(o) => o,
        None => return Err(types::error::Error {
            error_type: types::error::Type::Malformed,
            status: 404,
            title: "Not found".to_string(),
            detail: format!("Authorization ID {} does not exist", aid),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        })
    };

    if existing_authz.account != account.inner.id {
        return Err(types::error::Error {
            error_type: types::error::Type::Unauthorized,
            status: 400,
            title: "Unauthorized".to_string(),
            detail: format!("Authorization ID {} does not belong to the account", aid),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        });
    }

    Ok(existing_authz)
}

#[get("/acme/order/<_oid>")]
pub fn order(_oid: String) -> rocket::http::Status {
    rocket::http::Status::MethodNotAllowed
}

#[post("/acme/order/<oid>", data = "<order>")]
pub fn order_post(
    ua: ACMEResult<ClientData>,
    order: ACMEResult<jws::JWSRequest<()>>,
    db: DBConn,
    conf: rocket::State<Config>,
    oid: String,
    client: rocket::State<processing::BlockingOrderClient>,
) -> responses::ACMEResponse<'static, rocket_contrib::json::Json<types::order::Order>> {
    try_result!(ua);
    let order = try_result!(order);
    let acct_key = ensure_request_key_kid!(order.key);
    ensure_post_as_get!(order.payload);

    let existing_order = try_result!(get_order(&oid, &db, &acct_key));
    let mut locked_client = client.lock();
    let order_result = try_result!(try_tonic_result(locked_client.get_order(crate::cert_order::IdRequest {
        id: existing_order.ca_id.clone(),
    })));
    std::mem::drop(locked_client);

    let order_obj = try_result!(existing_order.to_json(&db, order_result.into_inner(), &conf));
    return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
        (rocket_contrib::json::Json(order_obj), rocket::http::Status::Ok)
    ), vec![]);
}

#[get("/acme/order/<_oid>/finalize")]
pub fn order_finalize(_oid: String) -> rocket::http::Status {
    rocket::http::Status::MethodNotAllowed
}

#[post("/acme/order/<oid>/finalize", data = "<order>")]
pub fn order_finalize_post(
    ua: ACMEResult<ClientData>,
    order: ACMEResult<jws::JWSRequest<types::order::OrderFinalize>>,
    db: DBConn,
    conf: rocket::State<Config>,
    oid: String,
    client: rocket::State<processing::BlockingOrderClient>,
) -> responses::ACMEResponse<'static, rocket_contrib::json::Json<types::order::Order>> {
    try_result!(ua);
    let order = try_result!(order);
    let acct_key = ensure_request_key_kid!(order.key);
    let order_finalize = ensure_not_post_as_get!(order.payload);

    let existing_order = try_result!(get_order(&oid, &db, &acct_key));

    let csr = match base64::decode_config(&order_finalize.csr, base64::URL_SAFE) {
        Ok(c) => c,
        Err(_) => {
            return responses::ACMEResponse::new_error(types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 400,
                title: "Bad CSR".to_string(),
                detail: "Invalid Base64 encoding for the CSR".to_string(),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            });
        }
    };

    let mut locked_client = client.lock();
    let order_result = try_result!(try_tonic_result(locked_client.finalize_order(crate::cert_order::FinalizeOrderRequest {
        id: existing_order.ca_id.clone(),
        csr,
    })));
    std::mem::drop(locked_client);

    let ca_order = try_result!(processing::unwrap_order_response(order_result.into_inner()));

    let order_obj = try_result!(existing_order.to_json(&db, ca_order, &conf));
    return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
        (rocket_contrib::json::Json(order_obj), rocket::http::Status::Ok)
    ), vec![]);
}

#[get("/acme/authorization/<_aid>")]
pub fn authorization(_aid: String) -> rocket::http::Status {
    rocket::http::Status::MethodNotAllowed
}

#[post("/acme/authorization/<aid>", data = "<authz>")]
pub fn authorization_post(
    ua: ACMEResult<ClientData>,
    authz: ACMEResult<jws::JWSRequest<types::authorization::AuthorizationUpdate>>,
    db: DBConn,
    conf: rocket::State<Config>,
    aid: String,
    client: rocket::State<processing::BlockingOrderClient>,
) -> responses::ACMEResponse<'static, rocket_contrib::json::Json<types::authorization::Authorization>> {
    try_result!(ua);
    let authz = try_result!(authz);
    let acct_key = ensure_request_key_kid!(authz.key);

    let existing_authz = try_result!(get_authz(&aid, &db, &acct_key));

    match authz.payload {
        None => {
            let mut locked_client = client.lock();
            let authz_result = try_result!(try_tonic_result(locked_client.get_authorization(crate::cert_order::IdRequest {
                id: existing_authz.ca_id.clone(),
            })));
            std::mem::drop(locked_client);

            let authz_obj = try_result!(existing_authz.to_json(authz_result.into_inner(), &conf));
            return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
                (rocket_contrib::json::Json(authz_obj), rocket::http::Status::Ok)
            ), vec![]);
        }
        Some(authz_update) => {
            if authz_update.status.is_some() {
                let status = authz_update.status.unwrap();

                if status != types::authorization::Status::Deactivated {
                    return responses::ACMEResponse::new_error(types::error::Error {
                        error_type: types::error::Type::Malformed,
                        status: 400,
                        title: "Update not allowed".to_string(),
                        detail: "'status' can only be set to 'deactivated'".to_string(),
                        sub_problems: vec![],
                        instance: None,
                        identifier: None,
                    });
                }
                let mut locked_client = client.lock();
                let authz_result = try_result!(try_tonic_result(locked_client.deactivate_authorization(crate::cert_order::IdRequest {
                    id: existing_authz.ca_id.clone(),
                })));
                std::mem::drop(locked_client);

                let ca_authz = try_result!(processing::unwrap_authz_response(authz_result.into_inner()));
                let authz_obj = try_result!(existing_authz.to_json(ca_authz, &conf));
                return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
                    (rocket_contrib::json::Json(authz_obj), rocket::http::Status::Ok)
                ), vec![]);
            }
            return responses::ACMEResponse::new_error(types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 400,
                title: "Update required".to_string(),
                detail: "No data to update was sent".to_string(),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            });
        }
    }
}

#[get("/acme/challenge/<_aid>/<_cid>")]
pub fn challenge(_aid: String, _cid: String) -> rocket::http::Status {
    rocket::http::Status::MethodNotAllowed
}

#[post("/acme/challenge/<aid>/<cid>", data = "<chall>")]
pub fn challenge_post(
    ua: ACMEResult<ClientData>,
    chall: ACMEResult<jws::JWSRequest<types::challenge::ChallengeRespond>>,
    db: DBConn,
    conf: rocket::State<Config>,
    aid: String,
    cid: String,
    client: rocket::State<processing::BlockingOrderClient>,
) -> responses::ACMEResponse<'static, rocket_contrib::json::Json<types::challenge::Challenge>> {
    try_result!(ua);
    let chall = try_result!(chall);
    let acct_key = ensure_request_key_kid!(chall.key);

    let cid = match base64::decode_config(cid, base64::URL_SAFE_NO_PAD) {
        Ok(n) => n,
        Err(_) => {
            return responses::ACMEResponse::new_error(types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 400,
                title: "Bad ID".to_string(),
                detail: "Invalid ID format".to_string(),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            });
        }
    };
    let existing_authz = try_result!(get_authz(&aid, &db, &acct_key));

    let chall_obj = match chall.payload {
        None => {
            let mut locked_client = client.lock();
            let chall_result = try_result!(try_tonic_result(locked_client.get_challenge(crate::cert_order::ChallengeIdRequest {
                id: cid,
                auth_id: existing_authz.ca_id.clone(),
            }))).into_inner();
            std::mem::drop(locked_client);

            try_result!(existing_authz.challenge_to_json(chall_result, &conf))
        }
        Some(_chall_response) => {
            let jwk: types::jose::JWK = (&acct_key.key).try_into().unwrap();
            let account_thumbprint = jws::make_jwk_thumbprint(&jwk);

            let mut locked_client = client.lock();
            let chall_result = try_result!(try_tonic_result(locked_client.complete_challenge(crate::cert_order::CompleteChallengeRequest {
                id: cid,
                auth_id: existing_authz.ca_id.clone(),
                account_thumbprint,
            }))).into_inner();
            std::mem::drop(locked_client);

            let ca_chall = try_result!(processing::unwrap_chall_response(chall_result));
            try_result!(existing_authz.challenge_to_json(ca_chall, &conf))
        }
    };

    return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
        (rocket_contrib::json::Json(chall_obj), rocket::http::Status::Ok)
    ), vec![links::LinkHeader {
        url: existing_authz.url(),
        relative: true,
        relation: "up".to_string(),
    }]);
}

enum CertFormat {
    PEMChain,
    PEM,
    DERPkix,
    DERPks7,
}

#[get("/acme/certificate/<cid>?<idx>&<cidx>")]
pub fn certificate(
    ua: ACMEResult<ClientData>,
    db: DBConn,
    cid: String,
    client: rocket::State<processing::BlockingOrderClient>,
    idx: Option<usize>,
    cidx: Option<usize>,
) -> responses::ACMEResponse<'static, rocket::response::Response<'static>> {
    let ua = try_result!(ua);

    let cid_uuid = try_result!(decode_id!(&cid));

    let existing_cert: models::Certificate = match try_result!(try_db_result!(schema::certificates::dsl::certificates.filter(
        schema::certificates::dsl::id.eq(&cid_uuid)
    ).first::<models::Certificate>(&db.0).optional(), "Unable to search for certificate: {}")) {
        Some(o) => o,
        None => return responses::ACMEResponse::new_error(types::error::Error {
            error_type: types::error::Type::Malformed,
            status: 404,
            title: "Not found".to_string(),
            detail: format!("Certificate ID {} does not exist", cid),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        })
    };

    let mut locked_client = client.lock();
    let mut ca_cert = try_result!(try_tonic_result(locked_client.get_certificate(crate::cert_order::IdRequest {
        id: existing_cert.ca_id.clone(),
    }))).into_inner();
    std::mem::drop(locked_client);

    let (mut chain, alternatives) = match cidx {
        Some(0) | None => match ca_cert.primary_chain {
            Some(c) => {
                (c, (0..ca_cert.alternative_chains.len()).map(|i| {
                    rocket::uri!(certificate: cid = &cid, idx = _, cidx = i).to_string()
                }).collect::<Vec<_>>())
            }
            None => return responses::ACMEResponse::new_error(crate::internal_server_error!())
        }
        Some(i) => if i < ca_cert.alternative_chains.len() {
            let mut alts = (0..ca_cert.alternative_chains.len())
                .filter(|ci| i != *ci)
                .map(|i| {
                    rocket::uri!(certificate: cid = &cid, idx = _, cidx = i).to_string()
                }).collect::<Vec<_>>();
            alts.push(rocket::uri!(certificate: cid = &cid, idx = _, cidx = _).to_string());
            (ca_cert.alternative_chains.remove(i), alts)
        } else {
            return responses::ACMEResponse::new_error(types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 404,
                title: "Not found".to_string(),
                detail: format!("Certificate chain number {} does not exist", i),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            });
        }
    };

    let mut alternatives = alternatives.into_iter().map(|a| links::LinkHeader {
        url: a,
        relative: true,
        relation: "alternate".to_string(),
    }).collect::<Vec<_>>();

    let up_idx = match idx {
        Some(i) => i,
        None => 0
    };
    let up_link = if up_idx + 1 < chain.certificates.len() {
        Some(links::LinkHeader {
            url: match cidx {
                Some(ci) => rocket::uri!(certificate: cid = &cid, idx = up_idx+1, cidx = ci).to_string(),
                None => rocket::uri!(certificate: cid = &cid, idx = up_idx+1, cidx = _).to_string(),
            },
            relative: true,
            relation: "up".to_string(),
        })
    } else {
        None
    };

    let pem_chain = rocket::http::MediaType::new("application", "pem-certificate-chain");
    let pkix_cert = rocket::http::MediaType::new("application", "pkix-cert");
    let pkcs7_mime = rocket::http::MediaType::new("application", "pkcs7-mime");
    let cert_format = match ua.accept {
        Some(a) => {
            let mut a: Vec<_> = a.iter().collect();
            a.sort_by(|a, b|
                a.weight_or(0.9).partial_cmp(&b.weight_or(0.9)).unwrap_or(std::cmp::Ordering::Equal)
            );
            match a.into_iter().find_map(|qm| {
                let mt = qm.media_type();
                if *mt == pem_chain {
                    if idx.is_some() {
                        Some(CertFormat::PEM)
                    } else {
                        Some(CertFormat::PEMChain)
                    }
                } else if *mt == pkix_cert {
                    Some(CertFormat::DERPkix)
                } else if *mt == pkcs7_mime {
                    Some(CertFormat::DERPks7)
                } else if mt.is_any() {
                    Some(CertFormat::PEMChain)
                } else {
                    None
                }
            }) {
                Some(f) => f,
                None => return responses::ACMEResponse::new_error(types::error::Error {
                    error_type: types::error::Type::Malformed,
                    status: 406,
                    title: "Not acceptable".to_string(),
                    detail: "No common certificate formats available".to_string(),
                    sub_problems: vec![],
                    instance: None,
                    identifier: None,
                })
            }
        }
        None => CertFormat::PEMChain
    };

    let make_pem = |c: Vec<u8>| {
        let cert_b64 = base64::encode(c)
            .as_bytes().chunks(76)
            .map(|buf| unsafe { std::str::from_utf8_unchecked(buf) })
            .collect::<Vec<&str>>().join("\n");

        format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----", cert_b64)
    };

    match cert_format {
        CertFormat::PEMChain => {
            let cert = chain.certificates.into_iter().map(make_pem).collect::<Vec<_>>().join("\n");

            let body = std::io::Cursor::new(cert.as_bytes().to_vec());
            let resp = rocket::response::Response::build()
                .header(rocket::http::ContentType(pem_chain))
                .raw_header("Cache-Control", "public, immutable")
                .raw_header("Vary", "Accept")
                .sized_body(body)
                .finalize();

            responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
                (resp, rocket::http::Status::Ok)
            ), alternatives)
        }
        CertFormat::PEM => {
            if up_idx >= chain.certificates.len() {
                return responses::ACMEResponse::new_error(types::error::Error {
                    error_type: types::error::Type::Malformed,
                    status: 404,
                    title: "Not found".to_string(),
                    detail: format!("Certificate number {} does not exist", up_idx),
                    sub_problems: vec![],
                    instance: None,
                    identifier: None,
                });
            }
            let cert = make_pem(chain.certificates.remove(up_idx));

            let body = std::io::Cursor::new(cert.as_bytes().to_vec());
            let resp = rocket::response::Response::build()
                .header(rocket::http::ContentType(pem_chain))
                .raw_header("Cache-Control", "public, immutable")
                .raw_header("Vary", "Accept")
                .sized_body(body)
                .finalize();

            if let Some(up_link) = up_link {
                alternatives.push(up_link);
            }

            responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
                (resp, rocket::http::Status::Ok)
            ), alternatives)
        }
        CertFormat::DERPkix | CertFormat::DERPks7 => {
            if up_idx >= chain.certificates.len() {
                return responses::ACMEResponse::new_error(types::error::Error {
                    error_type: types::error::Type::Malformed,
                    status: 404,
                    title: "Not found".to_string(),
                    detail: format!("Certificate number {} does not exist", up_idx),
                    sub_problems: vec![],
                    instance: None,
                    identifier: None,
                });
            }
            let cert = chain.certificates.remove(up_idx);

            let resp = rocket::response::Response::build()
                .header(rocket::http::ContentType(match cert_format {
                    CertFormat::DERPkix => pkix_cert,
                    CertFormat::DERPks7 => pkcs7_mime,
                    _ => unreachable!()
                }))
                .raw_header("Cache-Control", "public, immutable")
                .raw_header("Vary", "Accept")
                .sized_body(std::io::Cursor::new(cert))
                .finalize();

            if let Some(up_link) = up_link {
                alternatives.push(up_link);
            }

            responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
                (resp, rocket::http::Status::Ok)
            ), alternatives)
        }
    }
}

#[post("/acme/certificate/<cid>?<idx>&<cidx>", data = "<cert>")]
pub fn certificate_post(
    ua: ACMEResult<ClientData>,
    cert: ACMEResult<jws::JWSRequest<()>>,
    db: DBConn,
    cid: String,
    client: rocket::State<processing::BlockingOrderClient>,
    idx: Option<usize>,
    cidx: Option<usize>,
) -> responses::ACMEResponse<'static, rocket::response::Response<'static>> {
    let cert = try_result!(cert);
    ensure_request_key_kid!(cert.key);
    ensure_post_as_get!(cert.payload);

    certificate(ua, db, cid, client, idx, cidx)
}

#[catch(400)]
pub fn acme_400<'r>(_req: &rocket::Request) -> responses::ACMEResponse<'r, ()> {
    responses::ACMEResponse::new_error(types::error::Error {
        error_type: types::error::Type::Malformed,
        status: 400,
        title: "Bad request".to_string(),
        detail: "You tried to do something you shouldn't have.".to_string(),
        sub_problems: vec![],
        instance: None,
        identifier: None,
    })
}

#[catch(401)]
pub fn acme_401<'r>(_req: &rocket::Request) -> responses::ACMEResponse<'r, ()> {
    responses::ACMEResponse::new_error(types::error::Error {
        error_type: types::error::Type::Unauthorized,
        status: 401,
        title: "Unauthorized".to_string(),
        detail: "You're not allowed to see what's here, shoo!".to_string(),
        sub_problems: vec![],
        instance: None,
        identifier: None,
    })
}

#[catch(404)]
pub fn acme_404<'r>(req: &rocket::Request) -> responses::ACMEResponse<'r, ()> {
    responses::ACMEResponse::new_error(types::error::Error {
        error_type: types::error::Type::Malformed,
        status: 404,
        title: "Not found".to_string(),
        detail: format!("'{}' is not path we know of", req.uri()),
        sub_problems: vec![],
        instance: None,
        identifier: None,
    })
}

#[catch(405)]
pub fn acme_405<'r>(req: &rocket::Request) -> responses::ACMEResponse<'r, ()> {
    responses::ACMEResponse::new_error(types::error::Error {
        error_type: types::error::Type::Malformed,
        status: 405,
        title: "Method not allowed".to_string(),
        detail: format!("{} is not allowed on '{}'", req.method(), req.uri()),
        sub_problems: vec![],
        instance: None,
        identifier: None,
    })
}

#[catch(415)]
pub fn acme_415<'r>(req: &rocket::Request) -> responses::ACMEResponse<'r, ()> {
    responses::ACMEResponse::new_error(types::error::Error {
        error_type: types::error::Type::Malformed,
        status: 415,
        title: "Unsupported media type".to_string(),
        detail: match req.content_type() {
            Some(c) => format!("{} is not a supported media type", c),
            None => "No media type was given in the request".to_string(),
        },
        sub_problems: vec![],
        instance: None,
        identifier: None,
    })
}

#[catch(422)]
pub fn acme_422<'r>(_req: &rocket::Request) -> responses::ACMEResponse<'r, ()> {
    responses::ACMEResponse::new_error(types::error::Error {
        error_type: types::error::Type::Malformed,
        status: 422,
        title: "Unprocessable entity".to_string(),
        detail: "Ew! Untasty data, I can't parse that!".to_string(),
        sub_problems: vec![],
        instance: None,
        identifier: None,
    })
}

#[catch(500)]
pub fn acme_500<'r>() -> responses::ACMEResponse<'r, ()> {
    responses::ACMEResponse::new_error(internal_server_error!())
}