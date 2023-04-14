use diesel::prelude::*;
use chrono::prelude::*;
use base64::prelude::*;
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
    ($src:expr, $db:expr, $conf:expr) => {
        (match ($src) {
            Ok(inner) => inner,
            Err(err) => {
                return responses::ACMEResponse::new_error(err, &$db, &$conf).await;
            }
        })
    }
}

macro_rules! ensure_request_key_kid {
    ($src:expr, $db:expr, $conf:expr) => {
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
                }, &$db, &$conf).await;
            }
        }
    }
}

macro_rules! ensure_request_key_jwk {
    ($src:expr, $db:expr, $conf:expr) => {
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
                }, &$db, &$conf).await;
            }
            jws::JWSRequestKey::JWK { kid: _, key } => key
        }
    }
}

macro_rules! ensure_tos_agreed {
    ($src:expr, $conf:expr, $db:expr) => {
        if let Some(tos_date) = $conf.tos_agreed_to_after {
            if $src.inner.tos_agreed_at < tos_date {
                let tos_agreemet_token = models::ToSAgreementToken {
                    id: uuid::Uuid::new_v4(),
                    account: $src.inner.id,
                    expires_at: Utc::now() + chrono::Duration::days(1)
                };

                let tos_agreemet_token: models::ToSAgreementToken = try_result!(try_db_result!($db.run(move |c|
                    diesel::insert_into(schema::tos_agreement_tokens::dsl::tos_agreement_tokens)
                        .values(&tos_agreemet_token).get_result(c)).await,
                    "Unable to save ToS agreement token to database: {}"
                ), $db, $conf);

                return responses::ACMEResponse::new(responses::InnerACMEResponse::Error(
                    rocket::serde::json::Json(types::error::Error {
                        error_type: types::error::Type::UserActionRequired,
                        status: 403,
                        title: "User action required".to_string(),
                        detail: "Terms of Service have been updated".to_string(),
                        sub_problems: vec![],
                        instance: Some(format!(
                            "{}{}",
                            $conf.external_uri,
                            rocket::uri!(crate::acme::tos_agree(
                                tid = crate::util::uuid_as_b64(&tos_agreemet_token.id)
                            )).to_string()
                        )),
                        identifier: None,
                    })
                ), vec![links::LinkHeader {
                    url: $conf.tos_uri.as_deref().unwrap_or_default().to_string(),
                    relative: false,
                    relation: "terms-of-service".to_string()
                }], &$db, &$conf).await;
            }
        }
    }
}

macro_rules! ensure_not_post_as_get {
    ($src:expr, $db:expr, $conf:expr) => {
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
                }, &$db, &$conf).await;
            }
        }
    }
}

macro_rules! ensure_post_as_get {
    ($src:expr, $db:expr, $conf:expr) => {
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
                }, &$db, &$conf).await;
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
const NEW_AUTHZ_URI: &'static str = "/acme/new_authz";
const NEW_ORDER_URI: &'static str = "/acme/new_order";
const REVOKE_CERT_URI: &'static str = "/acme/revoke";

#[derive(Debug)]
pub struct Account {
    inner: models::Account,
    key: openssl::pkey::PKey<openssl::pkey::Public>,
}

async fn lookup_account(kid: &str, db: &DBConn) -> ACMEResult<Option<Account>> {
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

    let existing_account: Option<models::Account> = try_db_result!(db.run(move |c| {
        schema::accounts::dsl::accounts.filter(
            schema::accounts::dsl::id.eq(&kid_uuid)
        ).first::<models::Account>(c).optional()
    }).await, "Unable to search for existing contact: {}")?;

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
    tos_agreed_to_after: Option<DateTime<Utc>>,
    website_uri: Option<String>,
    issuers: Vec<ACMEIssuer>,
}

#[derive(Deserialize)]
struct ACMEIssuerConfig {
    issuer_cert_file: String,
    cert_id: String,
}

pub struct ACMEIssuer {
    pub(crate) issuer_cert: openssl::x509::X509,
    pub(crate) cert_id: String,
}

#[rocket::async_trait]
impl rocket::fairing::Fairing for ConfigFairing {
    fn info(&self) -> rocket::fairing::Info {
        rocket::fairing::Info {
            name: "Bj\u{f6}rn config loader",
            kind: rocket::fairing::Kind::Ignite,
        }
    }

    async fn on_ignite(&self, rocket: rocket::Rocket<rocket::Build>) -> rocket::fairing::Result {
        let external_uri = match rocket.figment().extract_inner::<String>("external_uri") {
            Ok(v) => v,
            Err(e) => {
                error!("Unable to load external URI from config: {}", e);
                return Err(rocket);
            }
        };
        let external_account_required = match rocket.figment().extract_inner::<bool>("external_account_required") {
            Ok(v) => v,
            Err(e) => {
                if let figment::error::Kind::MissingField(_) = e.kind {
                    false
                } else {
                    error!("Unable to load external account required from config: {}", e);
                    return Err(rocket);
                }
            }
        };
        let caa_identities = match rocket.figment().extract_inner::<Vec<String>>("caa_identities") {
            Ok(v) => v,
            Err(e) => {
                if let figment::error::Kind::MissingField(_) = e.kind {
                    vec![]
                } else {
                    error!("Unable to load CAA identities from config: {}", e);
                    return Err(rocket);
                }
            }
        };
        let tos_uri = match rocket.figment().extract_inner::<String>("tos_uri") {
            Ok(v) => Some(v),
            Err(e) => {
                if let figment::error::Kind::MissingField(_) = e.kind {
                    None
                } else {
                    error!("Unable to load ToS URI from config: {}", e);
                    return Err(rocket);
                }
            }
        };
        let tos_agreed_to_after = match rocket.figment().extract_inner::<String>("tos_agreed_to_after") {
            Ok(v) => match v.parse::<DateTime<Utc>>() {
                Ok(v) => Some(v),
                Err(e) => {
                    error!("Unable to parse ToS agreed to after date: {}", e);
                    return Err(rocket);
                }
            }
            Err(e) => {
                if let figment::error::Kind::MissingField(_) = e.kind {
                    None
                } else {
                    error!("Unable to load ToS agreed to after date from config: {}", e);
                    return Err(rocket);
                }
            }
        };
        let website_uri = match rocket.figment().extract_inner::<String>("website_uri") {
            Ok(v) => Some(v),
            Err(e) => {
                if let figment::error::Kind::MissingField(_) = e.kind {
                    None
                } else {
                    error!("Unable to load website URI from config: {}", e);
                    return Err(rocket);
                }
            }
        };

        let issuers_conf: Vec<ACMEIssuerConfig> = rocket.figment().extract_inner("acme_issuers")
            .expect("'acme_issuers' not configured");

        let issuers = issuers_conf.into_iter()
            .map(|issuer| {
                let issuer_cert = openssl::x509::X509::from_pem(
                    &std::fs::read(issuer.issuer_cert_file).expect("Unable to read issuer certificate")
                ).expect("Unable to parse issuer certificate");

                ACMEIssuer {
                    cert_id: issuer.cert_id,
                    issuer_cert,
                }
            })
            .collect::<Vec<_>>();

        Ok(
            rocket.manage(Config {
                external_uri,
                caa_identities,
                external_account_required,
                tos_uri,
                tos_agreed_to_after,
                website_uri,
                issuers,
            })
        )
    }
}

embed_migrations!("./migrations/acme");

pub struct DBMigrationFairing();

#[rocket::async_trait]
impl rocket::fairing::Fairing for DBMigrationFairing {
    fn info(&self) -> rocket::fairing::Info {
        rocket::fairing::Info {
            name: "DB Migration runner",
            kind: rocket::fairing::Kind::Ignite,
        }
    }

    async fn on_ignite(&self, rocket: rocket::Rocket<rocket::Build>) -> rocket::fairing::Result {
        let db_con = match DBConn::get_one(&rocket).await {
            Some(v) => v.0,
            None => {
                error!("Unable to get DB connection handle");
                return Err(rocket);
            }
        };


        if let Err(e) = db_con.run(|c| {
            embedded_migrations::run_with_output(c, &mut std::io::stdout())
        }).await {
            error!("Unable to run migrations: {}", e);
            return Err(rocket);
        }

        Ok(rocket)
    }
}

#[allow(dead_code)]
pub struct ClientData {
    user_agent: String,
    accept_languages: Vec<String>,
    accept: Option<rocket::http::Accept>,
}

#[rocket::async_trait]
impl<'a> rocket::request::FromRequest<'a> for ClientData {
    type Error = types::error::Error;

    async fn from_request(request: &'a rocket::request::Request<'_>) -> rocket::request::Outcome<Self, Self::Error> {
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
pub fn index() ->  rocket_dyn_templates::Template {
    rocket_dyn_templates::Template::render("index", std::collections::HashMap::<(), ()>::new())
}

#[derive(Serialize)]
struct ToSAgreeTemplateData {
    tos_uri: String,
    tos_agreed_at: DateTime<Utc>,
}

async fn get_tos_agreement_token(tid: &str, db: &DBConn) -> Result<(models::ToSAgreementToken, models::Account), types::error::Error> {
    let tid_uuid = match decode_id!(&tid) {
        Ok(v) => v,
        Err(e) => return Err(e)
    };
    let tos_agreement_token: models::ToSAgreementToken = match match try_db_result!(db.run(move |c| {
        schema::tos_agreement_tokens::dsl::tos_agreement_tokens.filter(
            schema::tos_agreement_tokens::dsl::id.eq(&tid_uuid)
        ).first::<models::ToSAgreementToken>(c).optional()
    }).await, "Unable to search for ToS agreement token: {}") {
        Ok(v) => v,
        Err(e) => return Err(e)
    } {
        Some(t) => t,
        None => return Err(types::error::Error {
            error_type: types::error::Type::Malformed,
            status: 404,
            title: "Not found".to_string(),
            detail: format!("ToS token {} does not exist", tid),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        })
    };

    if tos_agreement_token.expires_at < Utc::now() {
        return Err(types::error::Error {
            error_type: types::error::Type::Malformed,
            status: 404,
            title: "Not found".to_string(),
            detail: format!("ToS token {} does not exist", tid),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        });
    }

    let acct_id = tos_agreement_token.account;
    let account: models::Account = match try_db_result!(db.run(move |c| {schema::accounts::dsl::accounts.filter(
            schema::accounts::dsl::id.eq(&acct_id)
        ).first::<models::Account>(c)
    }).await,  "Unable to search for account: {}") {
        Ok(v) => v,
        Err(e) => return Err(e)
    };

    Ok((tos_agreement_token, account))
}

#[get("/tos_agreement/<tid>")]
pub async fn tos_agree(tid: String, conf: &rocket::State<Config>, db: DBConn) -> responses::InnerACMEResponse<'static, 'static, rocket_dyn_templates::Template> {
    let (_, account) = match get_tos_agreement_token(&tid, &db).await {
        Ok(v) => v,
        Err(e) => return responses::InnerACMEResponse::Error(rocket::serde::json::Json(e))
    };

    responses::InnerACMEResponse::Ok(
        ( rocket_dyn_templates::Template::render("tos_agree", ToSAgreeTemplateData {
            tos_uri: conf.tos_uri.as_deref().unwrap_or_default().to_string(),
            tos_agreed_at: account.tos_agreed_at,
        }), rocket::http::Status::Ok)
    )
}

#[derive(FromForm)]
pub struct ToSAgree {
    agree: bool,
}

#[post("/tos_agreement/<tid>", data = "<tos_agree>")]
pub async fn tos_agree_post(
    tid: String, conf: &rocket::State<Config>, db: DBConn,
    tos_agree: rocket::form::Form<ToSAgree>,
) -> responses::InnerACMEResponse<'static, 'static, rocket_dyn_templates::Template> {
    let (tos_agreement_token, account) = match get_tos_agreement_token(&tid, &db).await {
        Ok(v) => v,
        Err(e) => return responses::InnerACMEResponse::Error(rocket::serde::json::Json(e))
    };

    if !tos_agree.agree {
        responses::InnerACMEResponse::Ok(
            ( rocket_dyn_templates::Template::render("tos_agree", ToSAgreeTemplateData {
                tos_uri: conf.tos_uri.as_deref().unwrap_or_default().to_string(),
                tos_agreed_at: account.tos_agreed_at,
            }), rocket::http::Status::Ok)
        )
    } else {
        match try_db_result!(db.run(move |c| {
            diesel::update(schema::accounts::dsl::accounts.filter(schema::accounts::dsl::id.eq(&account.id)))
                .set(schema::accounts::dsl::tos_agreed_at.eq(Utc::now()))
                .execute(c)
        }).await, "Unable to update account: {}") {
            Ok(_) => {}
            Err(e) => return responses::InnerACMEResponse::Error(rocket::serde::json::Json(e))
        };
        match try_db_result!(db.run(move |c| {
            diesel::delete(schema::tos_agreement_tokens::dsl::tos_agreement_tokens.filter(
                schema::tos_agreement_tokens::dsl::id.eq(&tos_agreement_token.id)
            )).execute(c)
        }).await, "Unable to delete ToS agreement token: {}") {
            Ok(_) => {}
            Err(e) => return responses::InnerACMEResponse::Error(rocket::serde::json::Json(e))
        }

        responses::InnerACMEResponse::Ok(
            (
                rocket_dyn_templates::Template::render("tos_agreed", std::collections::HashMap::<(), ()>::new()),
                rocket::http::Status::Ok
            )
        )
    }
}

#[get("/directory")]
pub fn directory(ua: ACMEResult<ClientData>, conf: &rocket::State<Config>)
                 -> responses::InnerACMEResponse<'static, 'static, rocket::serde::json::Json<types::directory::Directory>> {
    if let Err(err) = ua {
        return responses::InnerACMEResponse::Error(rocket::serde::json::Json(err));
    }

    responses::InnerACMEResponse::Ok((rocket::serde::json::Json(types::directory::Directory {
        new_nonce: format!("{}{}", conf.external_uri, NEW_NONCE_URI),
        new_account: Some(format!("{}{}", conf.external_uri, NEW_ACCOUNT_URI)),
        new_order: Some(format!("{}{}", conf.external_uri, NEW_ORDER_URI)),
        new_authz: Some(format!("{}{}", conf.external_uri, NEW_AUTHZ_URI)),
        revoke_cert: Some(format!("{}{}", conf.external_uri, REVOKE_CERT_URI)),
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

pub struct NonceResponse {}

impl<'r> rocket::response::Responder<'r, 'static> for NonceResponse {
    fn respond_to(self, _req: &'r rocket::Request<'_>) -> rocket::response::Result<'static> {
        Ok(rocket::response::Response::build()
            .status(rocket::http::Status::Ok)
            .raw_header("Cache-Control", "no-store")
            .finalize())
    }
}

#[get("/acme/nonce")]
pub async fn get_nonce(db: DBConn, conf: &rocket::State<Config>) -> responses::ACMEResponse<'static, 'static, NonceResponse> {
    responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
        (NonceResponse {}, rocket::http::Status::Ok)
    ), vec![], &db, &conf).await
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
pub async fn new_account_post(
    ua: ACMEResult<ClientData>,
    acct: ACMEResult<jws::JWSRequest<types::account::AccountCreate>>,
    db: DBConn,
    conf: &rocket::State<Config>,
    client: &rocket::State<processing::OrderClient>,
) -> responses::ACMEResponse<'static, 'static, responses::Headers<rocket::serde::json::Json<types::account::Account>>> {
    try_result!(ua, db, conf);
    let acct = try_result!(acct, db, conf);
    let acct_key = ensure_request_key_jwk!(acct.key, db, conf);
    let payload = ensure_not_post_as_get!(acct.payload, db, conf);

    let acct_key_bytes = match acct_key.public_key_to_der() {
        Ok(v) => v,
        Err(_) => {
            return responses::ACMEResponse::new_error(internal_server_error!(), &db, &conf).await;
        }
    };

    let akb = acct_key_bytes.clone();
    let existing_account: Option<models::Account> = try_result!(try_db_result!(db.run(move |c| schema::accounts::dsl::accounts.filter(
        schema::accounts::dsl::public_key.eq(&akb)
    ).first::<models::Account>(c).optional()).await, "Unable to search for existing account: {}"), db, conf);

    if let Some(acct) = existing_account {
        let acct_obj = try_result!(acct.to_json(&db, &conf).await, db, conf);
        return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
            (responses::Headers {
                responder: rocket::serde::json::Json(acct_obj),
                headers: vec![("Location".to_string(), format!("{}{}", conf.external_uri, acct.kid()))],
            }, rocket::http::Status::Ok)
        ), vec![], &db, &conf).await;
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
        }, &db, &conf).await;
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
        }, &db, &conf).await;
    }

    let account_id = uuid::Uuid::new_v4();
    let contacts = try_result!(models::parse_contacts(
        &payload.contact.iter().map(|c| c.as_ref()).collect::<Vec<_>>(), &account_id
    ), db, conf);

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

    let mut client = client.inner().clone();
    if let Some(eab) = payload.external_account_binding {
        let eab_id = try_result!(processing::verify_eab(&mut client, &eab, &acct.url, &acct_key).await, db, conf);

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
        }, &db, &conf).await;
    }

    let account: models::Account = try_result!(try_db_result!(db.run(move |c| {
        c.transaction::<_, diesel::result::Error, _>(|| {
            let a = diesel::insert_into(schema::accounts::dsl::accounts)
                .values(&account)
                .get_result(c)?;

            for contact in contacts {
                diesel::insert_into(schema::account_contacts::dsl::account_contacts)
                    .values(contact)
                    .execute(c)?;
            }

            Ok(a)
        })
    }).await, "Unable to save account to database: {}"), db, conf);

    let acct_obj = try_result!(account.to_json(&db, &conf).await, db, conf);
    return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
        (responses::Headers {
            responder: rocket::serde::json::Json(acct_obj),
            headers: vec![("Location".to_string(), format!("{}{}", conf.external_uri, account.kid()))],
        }, rocket::http::Status::Created)
    ), vec![], &db, &conf).await;
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
pub async fn account_post(
    ua: ACMEResult<ClientData>,
    acct: ACMEResult<jws::JWSRequest<types::account::AccountUpdate>>,
    db: DBConn,
    conf: &rocket::State<Config>,
    aid: String,
) -> responses::ACMEResponse<'static, 'static, rocket::serde::json::Json<types::account::Account>> {
    try_result!(ua, db, conf);
    let acct = try_result!(acct, db, conf);
    let acct_key = ensure_request_key_kid!(acct.key, db, conf);
    ensure_tos_agreed!(acct_key, conf, db);
    try_result!(check_account(&aid, &acct_key), db, conf);

    let payload = match acct.payload {
        Some(v) => v,
        None => {
            let acct_obj = try_result!(acct_key.inner.to_json(&db, &conf).await, db, conf);
            return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
                (rocket::serde::json::Json(acct_obj), rocket::http::Status::Created)
            ), vec![], &db, &conf).await;
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
            }, &db, &conf).await;
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
            }, &db, &conf).await;
        }

        let new_acct: models::Account = try_result!(try_db_result!(db.run(move |c| {
            diesel::update(&acct_key.inner)
                .set(schema::accounts::dsl::status.eq(models::AccountStatus::Deactivated))
                .get_result(c)
        }).await, "Unable to deactivate account: {}"), db, conf);

        let acct_obj = try_result!(new_acct.to_json(&db, &conf).await, db, conf);
        return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
            (rocket::serde::json::Json(acct_obj), rocket::http::Status::Created)
        ), vec![], &db, &conf).await;
    }

    if let Some(new_contacts) = payload.contact {
        let contacts = try_result!(models::parse_contacts(
            &new_contacts.iter().map(|c| c.as_ref()).collect::<Vec<_>>(), &acct_key.inner.id
        ), db, conf);

        let acct_key_id = acct_key.inner.id;
        try_result!(try_db_result!(db.run(move |c| {
            c.transaction::<_, diesel::result::Error, _>(|| {
                diesel::delete(schema::account_contacts::dsl::account_contacts)
                    .filter(schema::account_contacts::dsl::account.eq(&acct_key_id))
                    .execute(c)?;

                for contact in contacts {
                    diesel::insert_into(schema::account_contacts::dsl::account_contacts)
                        .values(contact)
                        .execute(c)?;
                }

                Ok(())
            })
        }).await, "Unable to save account to database: {}"), db, conf);
    }

    let acct_obj = try_result!(acct_key.inner.to_json(&db, &conf).await, db, conf);
    return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
        (rocket::serde::json::Json(acct_obj), rocket::http::Status::Ok)
    ), vec![], &db, &conf).await;
}

#[get("/acme/account/<_aid>/orders")]
pub fn account_orders(_aid: String) -> rocket::http::Status {
    rocket::http::Status::MethodNotAllowed
}

#[post("/acme/account/<aid>/orders", data = "<acct>")]
pub async fn account_orders_post(
    ua: ACMEResult<ClientData>,
    acct: ACMEResult<jws::JWSRequest<()>>,
    db: DBConn,
    conf: &rocket::State<Config>,
    aid: String,
) -> responses::ACMEResponse<'static, 'static, rocket::serde::json::Json<types::order::List>> {
    try_result!(ua, db, conf);
    let acct = try_result!(acct, db, conf);
    let acct_key = ensure_request_key_kid!(acct.key, db, conf);
    ensure_tos_agreed!(acct_key, conf, db);
    ensure_post_as_get!(acct.payload, db, conf);
    try_result!(check_account(&aid, &acct_key), db, conf);

    let account_orders: Vec<models::Order> = try_result!(try_db_result!(db.run(move |c| {
        schema::orders::dsl::orders.filter(
            schema::orders::dsl::account.eq(&acct_key.inner.id)
        ).load(c)
    }).await, "Failed to get account orders: {}"), db, conf);

    let list_obj = types::order::List {
        orders: account_orders.into_iter()
            .map(|o| format!("{}{}", conf.external_uri, o.url())).collect()
    };

    return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
        (rocket::serde::json::Json(list_obj), rocket::http::Status::Ok)
    ), vec![], &db, &conf).await;
}

#[get("/acme/key_change")]
pub fn key_change() -> rocket::http::Status {
    rocket::http::Status::MethodNotAllowed
}

#[derive(Responder)]
pub enum KeyChangeResponse {
    Headers(responses::Headers<rocket::serde::json::Json<types::error::Error>>),
    None(&'static str),
}

#[post("/acme/key_change", data = "<acct>")]
pub async fn key_change_post(
    uri: &rocket::http::uri::Origin<'_>,
    ua: ACMEResult<ClientData>,
    acct: ACMEResult<jws::JWSRequest<types::jose::FlattenedJWS>>,
    db: DBConn,
    conf: &rocket::State<Config>,
) -> responses::ACMEResponse<'static, 'static, KeyChangeResponse> {
    try_result!(ua, db, conf);
    let acct = try_result!(acct, db, conf);
    let acct_key = ensure_request_key_kid!(acct.key, db, conf);
    ensure_tos_agreed!(acct_key, conf, db);
    let payload = ensure_not_post_as_get!(acct.payload, db, conf);

    let path = uri.path();
    let inner_acct: jws::JWSRequestInner<types::account::KeyChange> = try_result!(
        jws::JWSRequestInner::from_jws(path, payload, &conf, &db).await, db, conf);
    let new_acct_key = ensure_request_key_jwk!(inner_acct.key, db, conf);

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
            }, &db, &conf).await;
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
        }, &db, &conf).await;
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
        }, &db, &conf).await;
    }

    let new_acct_key_bytes = match new_acct_key.public_key_to_der() {
        Ok(v) => v,
        Err(_) => {
            return responses::ACMEResponse::new_error(internal_server_error!(), &db, &conf).await;
        }
    };

    let nakb = new_acct_key_bytes.clone();
    let existing_account: Option<models::Account> = try_result!(try_db_result!(db.run(move |c| {
        schema::accounts::dsl::accounts.filter(
            schema::accounts::dsl::public_key.eq(&nakb)
        ).first::<models::Account>(c).optional()
    }).await, "Unable to search for existing account: {}"), db, conf);

    if let Some(acct) = existing_account {
        return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
            (KeyChangeResponse::Headers(responses::Headers {
                responder: rocket::serde::json::Json(types::error::Error {
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
        ), vec![], &db, &conf).await;
    }

    try_result!(try_db_result!(db.run(move |c| diesel::update(&acct_key.inner)
            .set(schema::accounts::dsl::public_key.eq(new_acct_key_bytes))
            .execute(c)).await, "Unable to update account: {}"), db, conf);

    return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
        (KeyChangeResponse::None(""), rocket::http::Status::Ok)
    ), vec![], &db, &conf).await;
}

#[get("/acme/new_order")]
pub fn new_order() -> rocket::http::Status {
    rocket::http::Status::MethodNotAllowed
}

#[post("/acme/new_order", data = "<order>")]
pub async fn new_order_post(
    ua: ACMEResult<ClientData>,
    order: ACMEResult<jws::JWSRequest<types::order::OrderCreate>>,
    db: DBConn,
    conf: &rocket::State<Config>,
    client: &rocket::State<processing::OrderClient>,
) -> responses::ACMEResponse<'static, 'static, responses::Headers<rocket::serde::json::Json<types::order::Order>>> {
    try_result!(ua, db, conf);
    let acct = try_result!(order, db, conf);
    let acct_key = ensure_request_key_kid!(acct.key, db, conf);
    ensure_tos_agreed!(acct_key, conf, db);
    let payload = ensure_not_post_as_get!(acct.payload, db, conf);

    let mut client = client.inner().clone();
    let (db_order, ca_order) = try_result!(
        processing::create_order(&mut client, &db, &payload, &acct_key).await, db, conf);

    let order_obj = try_result!(db_order.to_json(&db, ca_order, &conf).await, db, conf);
    return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
        (responses::Headers {
            responder: rocket::serde::json::Json(order_obj),
            headers: vec![("Location".to_string(), format!("{}{}", conf.external_uri, db_order.url()))],
        }, rocket::http::Status::Created)
    ), vec![], &db, &conf).await;
}

#[get("/acme/new_authz")]
pub fn new_authz() -> rocket::http::Status {
    rocket::http::Status::MethodNotAllowed
}

#[post("/acme/new_authz", data = "<order>")]
pub async fn new_authz_post(
    ua: ACMEResult<ClientData>,
    order: ACMEResult<jws::JWSRequest<types::authorization::AuthorizationCreate>>,
    db: DBConn,
    conf: &rocket::State<Config>,
    client: &rocket::State<processing::OrderClient>,
) -> responses::ACMEResponse<'static, 'static, responses::Headers<rocket::serde::json::Json<types::authorization::Authorization>>> {
    try_result!(ua, db, conf);
    let acct = try_result!(order, db, conf);
    let acct_key = ensure_request_key_kid!(acct.key, db, conf);
    ensure_tos_agreed!(acct_key, conf, db);
    let payload = ensure_not_post_as_get!(acct.payload, db, conf);

    let mut client = client.inner().clone();
    let (db_authz, ca_authz) = try_result!(
        processing::create_authz(&mut client, &db, &payload, &acct_key).await, db, conf);

    let authz_obj = try_result!(db_authz.to_json(ca_authz, &conf), db, conf);
    return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
        (responses::Headers {
            responder: rocket::serde::json::Json(authz_obj),
            headers: vec![("Location".to_string(), format!("{}{}", conf.external_uri, db_authz.url()))],
        }, rocket::http::Status::Created)
    ), vec![], &db, &conf).await;
}

async fn get_order(oid: &str, db: &DBConn, account: &Account) -> ACMEResult<models::Order> {
    let oid_uuid = decode_id!(oid)?;

    let existing_order: models::Order = match try_db_result!(db.run(move |c| {
        schema::orders::dsl::orders.filter(
            schema::orders::dsl::id.eq(&oid_uuid)
        ).first::<models::Order>(c).optional()
    }).await, "Unable to search for order: {}")? {
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

async fn get_authz(aid: &str, db: &DBConn, account: &Account) -> ACMEResult<models::Authorization> {
    let aid_uuid = decode_id!(aid)?;

    let existing_authz: models::Authorization = match try_db_result!(db.run(move |c| {
        schema::authorizations::dsl::authorizations.filter(
            schema::authorizations::dsl::id.eq(&aid_uuid)
        ).first::<models::Authorization>(c).optional()
    }).await, "Unable to search for authorization: {}")? {
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
pub async fn order_post(
    ua: ACMEResult<ClientData>,
    order: ACMEResult<jws::JWSRequest<()>>,
    db: DBConn,
    conf: &rocket::State<Config>,
    oid: String,
    client: &rocket::State<processing::OrderClient>,
) -> responses::ACMEResponse<'static, 'static, rocket::serde::json::Json<types::order::Order>> {
    try_result!(ua, db, conf);
    let order = try_result!(order, db, conf);
    let acct_key = ensure_request_key_kid!(order.key, db, conf);
    ensure_tos_agreed!(acct_key, conf, db);
    ensure_post_as_get!(order.payload, db, conf);

    let existing_order = try_result!(get_order(&oid, &db, &acct_key).await, db, conf);
    let mut client = client.inner().clone();
    let order_result = try_result!(try_tonic_result(client.get_order(crate::cert_order::IdRequest {
        id: existing_order.ca_id.clone(),
    }).await), db, conf);

    let order_obj = try_result!(existing_order.to_json(&db, order_result.into_inner(), &conf).await, db, conf);
    return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
        (rocket::serde::json::Json(order_obj), rocket::http::Status::Ok)
    ), vec![], &db, &conf).await;
}

#[get("/acme/order/<_oid>/finalize")]
pub fn order_finalize(_oid: String) -> rocket::http::Status {
    rocket::http::Status::MethodNotAllowed
}

#[post("/acme/order/<oid>/finalize", data = "<order>")]
pub async fn order_finalize_post(
    ua: ACMEResult<ClientData>,
    order: ACMEResult<jws::JWSRequest<types::order::OrderFinalize>>,
    db: DBConn,
    conf: &rocket::State<Config>,
    oid: String,
    client: &rocket::State<processing::OrderClient>,
) -> responses::ACMEResponse<'static, 'static, rocket::serde::json::Json<types::order::Order>> {
    try_result!(ua, db, conf);
    let order = try_result!(order, db, conf);
    let acct_key = ensure_request_key_kid!(order.key, db, conf);
    ensure_tos_agreed!(acct_key, conf, db);
    let order_finalize = ensure_not_post_as_get!(order.payload, db, conf);

    let existing_order = try_result!(get_order(&oid, &db, &acct_key).await, db, conf);

    let csr = match BASE64_URL_SAFE_NO_PAD.decode(&order_finalize.csr) {
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
            }, &db, &conf).await;
        }
    };

    let mut client = client.inner().clone();
    let order_result = try_result!(try_tonic_result(client.finalize_order(crate::cert_order::FinalizeOrderRequest {
        id: existing_order.ca_id.clone(),
        csr,
    }).await), db, conf);

    let ca_order = try_result!(processing::unwrap_order_response(order_result.into_inner()), db, conf);

    let order_obj = try_result!(existing_order.to_json(&db, ca_order, &conf).await, db, conf);
    return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
        (rocket::serde::json::Json(order_obj), rocket::http::Status::Ok)
    ), vec![], &db, &conf).await;
}

#[get("/acme/authorization/<_aid>")]
pub fn authorization(_aid: String) -> rocket::http::Status {
    rocket::http::Status::MethodNotAllowed
}

#[post("/acme/authorization/<aid>", data = "<authz>")]
pub async fn authorization_post(
    ua: ACMEResult<ClientData>,
    authz: ACMEResult<jws::JWSRequest<types::authorization::AuthorizationUpdate>>,
    db: DBConn,
    conf: &rocket::State<Config>,
    aid: String,
    client: &rocket::State<processing::OrderClient>,
) -> responses::ACMEResponse<'static, 'static, rocket::serde::json::Json<types::authorization::Authorization>> {
    try_result!(ua, db, conf);
    let authz = try_result!(authz, db, conf);
    let acct_key = ensure_request_key_kid!(authz.key, db, conf);
    ensure_tos_agreed!(acct_key, conf, db);

    let mut client = client.inner().clone();
    let existing_authz = try_result!(get_authz(&aid, &db, &acct_key).await, db, conf);

    match authz.payload {
        None => {
            let authz_result = try_result!(try_tonic_result(client.get_authorization(crate::cert_order::IdRequest {
                id: existing_authz.ca_id.clone(),
            }).await), db, conf);

            let authz_obj = try_result!(existing_authz.to_json(authz_result.into_inner(), &conf), db, conf);
            return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
                (rocket::serde::json::Json(authz_obj), rocket::http::Status::Ok)
            ), vec![], &db, &conf).await;
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
                    }, &db, &conf).await;
                }
                let authz_result = try_result!(try_tonic_result(client.deactivate_authorization(crate::cert_order::IdRequest {
                    id: existing_authz.ca_id.clone(),
                }).await), db, conf);

                let ca_authz = try_result!(processing::unwrap_authz_response(authz_result.into_inner()), db, conf);
                let authz_obj = try_result!(existing_authz.to_json(ca_authz, &conf), db, conf);
                return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
                    (rocket::serde::json::Json(authz_obj), rocket::http::Status::Ok)
                ), vec![], &db, &conf).await;
            }
            return responses::ACMEResponse::new_error(types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 400,
                title: "Update required".to_string(),
                detail: "No data to update was sent".to_string(),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            }, &db, &conf).await;
        }
    }
}

#[get("/acme/challenge/<_aid>/<_cid>")]
pub fn challenge(_aid: String, _cid: String) -> rocket::http::Status {
    rocket::http::Status::MethodNotAllowed
}

#[post("/acme/challenge/<aid>/<cid>", data = "<chall>")]
pub async fn challenge_post(
    ua: ACMEResult<ClientData>,
    chall: ACMEResult<jws::JWSRequest<types::challenge::ChallengeRespond>>,
    db: DBConn,
    conf: &rocket::State<Config>,
    aid: String,
    cid: String,
    client: &rocket::State<processing::OrderClient>,
) -> responses::ACMEResponse<'static, 'static, rocket::serde::json::Json<types::challenge::Challenge>> {
    try_result!(ua, db, conf);
    let chall = try_result!(chall, db, conf);
    let acct_key = ensure_request_key_kid!(chall.key, db, conf);
    ensure_tos_agreed!(acct_key, conf, db);

    let cid = match BASE64_URL_SAFE_NO_PAD.decode(cid) {
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
            }, &db, &conf).await;
        }
    };
    let existing_authz = try_result!(get_authz(&aid, &db, &acct_key).await, db, conf);

    let mut client = client.inner().clone();
    let chall_obj = match chall.payload {
        None => {
            let chall_result = try_result!(try_tonic_result(client.get_challenge(crate::cert_order::ChallengeIdRequest {
                id: cid,
                auth_id: existing_authz.ca_id.clone(),
            }).await), db, conf).into_inner();

            try_result!(existing_authz.challenge_to_json(chall_result, &conf), db, conf)
        }
        Some(_chall_response) => {
            let jwk: types::jose::JWK = (&acct_key.key).try_into().unwrap();
            let account_thumbprint = jws::make_jwk_thumbprint(&jwk);

            let chall_result = try_result!(try_tonic_result(client.complete_challenge(crate::cert_order::CompleteChallengeRequest {
                id: cid,
                auth_id: existing_authz.ca_id.clone(),
                account_thumbprint,
                account_uri: format!("{}{}", conf.external_uri, acct_key.inner.kid()),
            }).await), db, conf).into_inner();

            let ca_chall = try_result!(processing::unwrap_chall_response(chall_result), db, conf);
            try_result!(existing_authz.challenge_to_json(ca_chall, &conf), db, conf)
        }
    };

    return responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
        (rocket::serde::json::Json(chall_obj), rocket::http::Status::Ok)
    ), vec![links::LinkHeader {
        url: existing_authz.url(),
        relative: true,
        relation: "up".to_string(),
    }], &db, &conf).await;
}


#[get("/acme/revoke")]
pub fn revoke() -> rocket::http::Status {
    rocket::http::Status::MethodNotAllowed
}

#[post("/acme/revoke", data = "<authz>")]
pub async fn revoke_post(
    ua: ACMEResult<ClientData>,
    db: DBConn,
    authz: ACMEResult<jws::JWSRequest<types::revoke::RevokeCert>>,
    conf: &rocket::State<Config>,
    client: &rocket::State<processing::OrderClient>,
) -> responses::ACMEResponse<'static, 'static, ()> {
    try_result!(ua, db, conf);
    let authz = try_result!(authz, db, conf);
    let revoke_cert = ensure_not_post_as_get!(authz.payload, db, conf);

    let cert_bytes = match BASE64_URL_SAFE.decode(&revoke_cert.certificate) {
        Ok(c) => c,
        Err(_) => {
            return responses::ACMEResponse::new_error(types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 400,
                title: "Bad certificate".to_string(),
                detail: "Invalid Base64 encoding for the certificate".to_string(),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            }, &db, &conf).await;
        }
    };
    let cert = match openssl::x509::X509::from_der(&cert_bytes) {
        Ok(c) => c,
        Err(_) => {
            return responses::ACMEResponse::new_error(types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 400,
                title: "Bad certificate".to_string(),
                detail: "Un-parsable certificate".to_string(),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            }, &db, &conf).await;
        }
    };

    let issued_by = match conf.issuers
        .iter()
        .filter(|i| i.issuer_cert.issued(&cert) == openssl::x509::X509VerifyResult::OK)
        .next() {
        Some(i) => i,
        None => {
            return responses::ACMEResponse::new_error(types::error::Error {
                error_type: types::error::Type::Unauthorized,
                status: 403,
                title: "Unauthorized".to_string(),
                detail: "This server did not issue the certificate requested to be revoked".to_string(),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            }, &db, &conf).await;
        }
    };
    let serial_number = cert.serial_number().to_bn().unwrap().to_vec();
    let cert_public_key = cert.public_key().unwrap();

    let revoke_req = match authz.key {
        jws::JWSRequestKey::KID(acct) => {
            ensure_tos_agreed!(acct, conf, db);
            crate::cert_order::RevokeCertRequest {
                account_id: acct.inner.id.to_string(),
                authz_checked: false,
                issuer_id: issued_by.cert_id.clone(),
                serial_number,
                revocation_reason: revoke_cert.reason,
            }
        }
        jws::JWSRequestKey::JWK { key, .. } => {
            if cert_public_key.public_eq(&key) {
                crate::cert_order::RevokeCertRequest {
                    account_id: String::new(),
                    authz_checked: true,
                    issuer_id: issued_by.cert_id.clone(),
                    serial_number,
                    revocation_reason: revoke_cert.reason,
                }
            } else {
                return responses::ACMEResponse::new_error(types::error::Error {
                    error_type: types::error::Type::Unauthorized,
                    status: 403,
                    title: "Unauthorized".to_string(),
                    detail: "The public key used to sign the request does not match the certificate".to_string(),
                    sub_problems: vec![],
                    instance: None,
                    identifier: None,
                }, &db, &conf).await;
            }
        }
    };

    let mut client = client.inner().clone();
    let revoke_result = try_result!(
        try_tonic_result(client.revoke_certificate(revoke_req).await), db, conf).into_inner();

    if let Some(error) = revoke_result.error {
        return responses::ACMEResponse::new_error(crate::util::error_list_to_result(
            error.errors.into_iter().map(processing::rpc_error_to_problem).collect(),
            "Multiple errors make this request invalid".to_string(),
        ).err().unwrap(), &db, &conf).await;
    }

    responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
        ((), rocket::http::Status::Ok)
    ), vec![], &db, &conf).await
}

enum CertFormat {
    PEMChain,
    PEM,
    DERPkix,
    DERPks7,
}

pub struct CertificateResponse {
    format: rocket::http::ContentType,
    body: Vec<u8>
}

impl<'r> rocket::response::Responder<'r, 'static> for CertificateResponse {
    fn respond_to(self, _req: &'r rocket::Request<'_>) -> rocket::response::Result<'static> {
        Ok(rocket::response::Response::build()
            .header(self.format)
            .raw_header("Cache-Control", "public, immutable")
            .raw_header("Vary", "Accept")
            .sized_body(self.body.len(), std::io::Cursor::new(self.body))
            .finalize())
    }
}

#[get("/acme/certificate/<cid>?<idx>&<cidx>")]
pub async fn certificate(
    ua: ACMEResult<ClientData>,
    db: DBConn,
    conf: &rocket::State<Config>,
    cid: String,
    client: &rocket::State<processing::OrderClient>,
    idx: Option<usize>,
    cidx: Option<usize>,
) -> responses::ACMEResponse<'static, 'static, CertificateResponse> {
    let ua = try_result!(ua, db, conf);

    let cid_uuid = try_result!(decode_id!(&cid), db, conf);

    let existing_cert: models::Certificate = match try_result!(try_db_result!(db.run(move |c| schema::certificates::dsl::certificates.filter(
        schema::certificates::dsl::id.eq(&cid_uuid)
    ).first::<models::Certificate>(c).optional()).await, "Unable to search for certificate: {}"), db, conf) {
        Some(o) => o,
        None => return responses::ACMEResponse::new_error(types::error::Error {
            error_type: types::error::Type::Malformed,
            status: 404,
            title: "Not found".to_string(),
            detail: format!("Certificate ID {} does not exist", cid),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        }, &db, &conf).await
    };

    let mut client = client.inner().clone();
    let mut ca_cert = try_result!(try_tonic_result(client.get_certificate(crate::cert_order::IdRequest {
        id: existing_cert.ca_id.clone(),
    }).await), db, conf).into_inner();

    let (mut chain, alternatives) = match cidx {
        Some(0) | None => match ca_cert.primary_chain {
            Some(c) => {
                (c, (0..ca_cert.alternative_chains.len()).map(|i| {
                    rocket::uri!(certificate(cid = &cid, idx = _, cidx = Some(i))).to_string()
                }).collect::<Vec<_>>())
            }
            None => return responses::ACMEResponse::new_error(crate::internal_server_error!(), &db, &conf).await
        }
        Some(i) => if i < ca_cert.alternative_chains.len() {
            let mut alts = (0..ca_cert.alternative_chains.len())
                .filter(|ci| i != *ci)
                .map(|i| {
                    rocket::uri!(certificate(cid = &cid, idx = _, cidx = Some(i))).to_string()
                }).collect::<Vec<_>>();
            alts.push(rocket::uri!(certificate(cid = &cid, idx = _, cidx = _)).to_string());
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
            }, &db, &conf).await;
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
                Some(ci) => rocket::uri!(certificate(cid = &cid, idx = Some(up_idx+1), cidx = Some(ci))).to_string(),
                None => rocket::uri!(certificate(cid = &cid, idx = Some(up_idx+1), cidx = _)).to_string(),
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
                }, &db, &conf).await
            }
        }
        None => CertFormat::PEMChain
    };

    let make_pem = |c: Vec<u8>| {
        let cert_b64 = BASE64_STANDARD.encode(c)
            .as_bytes().chunks(76)
            .map(|buf| unsafe { std::str::from_utf8_unchecked(buf) })
            .collect::<Vec<&str>>().join("\n");

        format!("-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----", cert_b64)
    };

    match cert_format {
        CertFormat::PEMChain => {
            let cert = chain.certificates.into_iter().map(make_pem).collect::<Vec<_>>().join("\n");

            responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
                (CertificateResponse {
                    format: rocket::http::ContentType(pem_chain),
                    body: cert.as_bytes().to_vec()
                }, rocket::http::Status::Ok)
            ), alternatives, &db, &conf).await
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
                }, &db, &conf).await;
            }
            let cert = make_pem(chain.certificates.remove(up_idx));

            if let Some(up_link) = up_link {
                alternatives.push(up_link);
            }

            responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
                (CertificateResponse {
                    format: rocket::http::ContentType(pem_chain),
                    body: cert.as_bytes().to_vec()
                }, rocket::http::Status::Ok)
            ), alternatives, &db, &conf).await
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
                }, &db, &conf).await;
            }
            let cert = chain.certificates.remove(up_idx);

            if let Some(up_link) = up_link {
                alternatives.push(up_link);
            }

            responses::ACMEResponse::new(responses::InnerACMEResponse::Ok(
                (CertificateResponse {
                    format: rocket::http::ContentType(match cert_format {
                        CertFormat::DERPkix => pkix_cert,
                        CertFormat::DERPks7 => pkcs7_mime,
                        _ => unreachable!()
                    }),
                    body: cert,
                }, rocket::http::Status::Ok)
            ), alternatives, &db, &conf).await
        }
    }
}

#[post("/acme/certificate/<cid>?<idx>&<cidx>", data = "<cert>")]
pub async fn certificate_post(
    ua: ACMEResult<ClientData>,
    cert: ACMEResult<jws::JWSRequest<()>>,
    conf: &rocket::State<Config>,
    db: DBConn,
    cid: String,
    client: &rocket::State<processing::OrderClient>,
    idx: Option<usize>,
    cidx: Option<usize>,
) -> responses::ACMEResponse<'static, 'static, CertificateResponse> {
    let cert = try_result!(cert, db, conf);
    let acct_key = ensure_request_key_kid!(cert.key, db, conf);
    ensure_tos_agreed!(acct_key, conf, db);
    ensure_post_as_get!(cert.payload, db, conf);

    certificate(ua, db, conf, cid, client, idx, cidx).await
}

macro_rules! catcher_get_state {
    ($req:expr) => {
        {
            let db = match $req.guard::<DBConn>().await {
                rocket::request::Outcome::Success(v) => v,
                rocket::request::Outcome::Failure(_) => {
                    return responses::ACMEResponse::Raw(responses::InnerACMEResponse::Error(rocket::serde::json::Json(internal_server_error!())))
                }
                rocket::request::Outcome::Forward(_) => unreachable!()
            };
            let conf = match $req.guard::<&rocket::State<Config>>().await {
                rocket::request::Outcome::Success(v) => v,
                rocket::request::Outcome::Failure(_) => {
                    return responses::ACMEResponse::Raw(responses::InnerACMEResponse::Error(rocket::serde::json::Json(internal_server_error!())))
                }
                rocket::request::Outcome::Forward(_) => unreachable!()
            };
            (db, conf)
        }
    }
}

#[catch(400)]
pub async fn acme_400<'r>(req: &rocket::Request<'_>) -> responses::ACMEResponse<'r, 'static, ()> {
    let (db, conf) = catcher_get_state!(req);

    responses::ACMEResponse::new_error(types::error::Error {
        error_type: types::error::Type::Malformed,
        status: 400,
        title: "Bad request".to_string(),
        detail: "You tried to do something you shouldn't have.".to_string(),
        sub_problems: vec![],
        instance: None,
        identifier: None,
    }, &db, &conf).await
}

#[catch(401)]
pub async fn acme_401<'r>(req: &rocket::Request<'_>) -> responses::ACMEResponse<'r, 'static, ()> {
    let (db, conf) = catcher_get_state!(req);

    responses::ACMEResponse::new_error(types::error::Error {
        error_type: types::error::Type::Unauthorized,
        status: 401,
        title: "Unauthorized".to_string(),
        detail: "You're not allowed to see what's here, shoo!".to_string(),
        sub_problems: vec![],
        instance: None,
        identifier: None,
    }, &db, &conf).await
}

#[catch(404)]
pub async fn acme_404<'r>(req: &rocket::Request<'_>) -> responses::ACMEResponse<'r, 'static, ()> {
    let (db, conf) = catcher_get_state!(req);

    responses::ACMEResponse::new_error(types::error::Error {
        error_type: types::error::Type::Malformed,
        status: 404,
        title: "Not found".to_string(),
        detail: format!("'{}' is not path we know of", req.uri()),
        sub_problems: vec![],
        instance: None,
        identifier: None,
    }, &db, &conf).await
}

#[catch(405)]
pub async fn acme_405<'r>(req: &rocket::Request<'_>) -> responses::ACMEResponse<'r, 'static, ()> {
    let (db, conf) = catcher_get_state!(req);

    responses::ACMEResponse::new_error(types::error::Error {
        error_type: types::error::Type::Malformed,
        status: 405,
        title: "Method not allowed".to_string(),
        detail: format!("{} is not allowed on '{}'", req.method(), req.uri()),
        sub_problems: vec![],
        instance: None,
        identifier: None,
    }, &db, &conf).await
}

#[catch(415)]
pub async fn acme_415<'r>(req: &rocket::Request<'_>) -> responses::ACMEResponse<'r, 'static, ()> {
    let (db, conf) = catcher_get_state!(req);

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
    }, &db, &conf).await
}

#[catch(422)]
pub async fn acme_422<'r>(req: &rocket::Request<'_>) -> responses::ACMEResponse<'r, 'static, ()> {
    let (db, conf) = catcher_get_state!(req);

    responses::ACMEResponse::new_error(types::error::Error {
        error_type: types::error::Type::Malformed,
        status: 422,
        title: "Unprocessable entity".to_string(),
        detail: "Ew! Untasty data, I can't parse that!".to_string(),
        sub_problems: vec![],
        instance: None,
        identifier: None,
    }, &db, &conf).await
}

#[catch(500)]
pub async fn acme_500<'r>(req: &rocket::Request<'_>) -> responses::ACMEResponse<'r, 'static, ()> {
    let (db, conf) = catcher_get_state!(req);

    responses::ACMEResponse::new_error(internal_server_error!(), &db, &conf).await
}