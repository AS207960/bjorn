use crate::types;
use std::convert::TryInto;
use crate::types::jose::{JWSProtectedHeader, FlattenedJWS};
use base64::prelude::*;

#[derive(Debug)]
pub enum JWSRequestKey {
    JWK {
        kid: Option<String>,
        key: openssl::pkey::PKey<openssl::pkey::Public>,
    },
    KID(super::Account),
}

#[derive(Debug)]
pub struct JWSRequest<R> where R: serde::de::DeserializeOwned + std::fmt::Debug {
    pub payload: Option<R>,
    pub key: JWSRequestKey,
    pub url: String,
}

#[derive(Debug)]
pub(crate) struct JWSRequestInner<R> where R: serde::de::DeserializeOwned + std::fmt::Debug {
    pub payload: R,
    pub key: JWSRequestKey,
}

async fn get_flattened_jws(
    request: &rocket::request::Request<'_>, data: rocket::data::Data<'_>,
) -> Result<FlattenedJWS, (rocket::http::Status, types::error::Error)> {
    let ct = request.headers().get_one("Content-Type").unwrap_or_default();
    if ct != "application/jose+json" {
        return Err((rocket::http::Status::UnsupportedMediaType, types::error::Error {
            error_type: types::error::Type::Malformed,
            status: 415,
            title: "Invalid content type".to_string(),
            detail: format!("'{}' is not an expected body content type", ct),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        }));
    }
    let body = match data.open(4 *  rocket::data::ByteUnit::MiB).into_string().await {
        Ok(v) => v,
        Err(err) => {
            return Err((rocket::http::Status::BadRequest, types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 400,
                title: "Invalid UTF8".to_string(),
                detail: format!("Invalid UTF8 received in body: '{}'", err),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            }));
        }
    };
    let jws = match serde_json::from_str::<FlattenedJWS>(&body) {
        Ok(j) => j,
        Err(err) => {
            return Err((rocket::http::Status::BadRequest, types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 400,
                title: "Invalid JWS".to_string(),
                detail: format!("Invalid JWS received in body: '{}'", err),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            }));
        }
    };

    Ok(jws)
}

pub fn start_decode_jws(
    jws: &FlattenedJWS,
) -> Result<(JWSProtectedHeader, Vec<u8>, Vec<u8>), (rocket::http::Status, types::error::Error)> {
    let header_bytes = match BASE64_URL_SAFE_NO_PAD.decode(&jws.protected) {
        Ok(h) => h,
        Err(err) => {
            return Err((rocket::http::Status::BadRequest, types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 400,
                title: "Invalid JWS".to_string(),
                detail: format!("Invalid JWS header: '{}'", err),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            }));
        }
    };
    let signature_bytes = match BASE64_URL_SAFE_NO_PAD.decode(&jws.signature) {
        Ok(h) => h,
        Err(err) => {
            return Err((rocket::http::Status::BadRequest, types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 400,
                title: "Invalid JWS".to_string(),
                detail: format!("Invalid JWS signature: '{}'", err),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            }));
        }
    };
    let payload_bytes = match BASE64_URL_SAFE_NO_PAD.decode(&jws.payload) {
        Ok(h) => h,
        Err(err) => {
            return Err((rocket::http::Status::BadRequest, types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 400,
                title: "Invalid JWS".to_string(),
                detail: format!("Invalid JWS payload: '{}'", err),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            }));
        }
    };

    let header = match serde_json::from_slice::<types::jose::JWSProtectedHeader>(&header_bytes) {
        Ok(h) => h,
        Err(err) => {
            return Err((rocket::http::Status::BadRequest, types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 400,
                title: "Invalid JWS".to_string(),
                detail: format!("Invalid JWS header: '{}'", err),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            }));
        }
    };

    let crit_vals = header.crit.as_deref().unwrap_or_default();
    if !crit_vals.is_empty() {
        return Err((rocket::http::Status::BadRequest, types::error::Error {
            error_type: types::error::Type::Malformed,
            status: 400,
            title: "Invalid JWS".to_string(),
            detail: format!("Unsupported critical constraints: {:?}", crit_vals),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        }));
    }

    let is_b64 = header.b64.unwrap_or(true);
    if !is_b64 {
        return Err((rocket::http::Status::BadRequest, types::error::Error {
            error_type: types::error::Type::Malformed,
            status: 400,
            title: "Invalid JWS".to_string(),
            detail: "Unencoded payload not supported".to_string(),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        }));
    }

    Ok((header, payload_bytes, signature_bytes))
}

async fn verify_jws_sig(
    jws: &FlattenedJWS, header: &JWSProtectedHeader, signature_bytes: &[u8], db: &crate::DBConn,
) -> Result<JWSRequestKey, (rocket::http::Status, types::error::Error)> {
    let key: JWSRequestKey = match &header.key {
        types::jose::JWKKey::JWK(jwk) => {
            let kid = jwk.kid.clone();
            match jwk.try_into() {
                Ok(v) => JWSRequestKey::JWK {
                    key: v,
                    kid,
                },
                Err(err) => {
                    return Err((rocket::http::Status::BadRequest, types::error::Error {
                        error_type: types::error::Type::BadPublicKey,
                        status: 400,
                        title: "Invalid public key".to_string(),
                        detail: err.to_string(),
                        sub_problems: vec![],
                        instance: None,
                        identifier: None,
                    }));
                }
            }
        }
        types::jose::JWKKey::KID(kid) => {
            match match super::lookup_account(&kid, &db).await {
                Ok(v) => v,
                Err(e) => {
                    return Err((rocket::http::Status::BadRequest, e));
                }
            } {
                Some(a) => JWSRequestKey::KID(a),
                None => {
                    return Err((rocket::http::Status::BadRequest, types::error::Error {
                        error_type: types::error::Type::AccountDoesNotExist,
                        status: 400,
                        title: "Account does not exist".to_string(),
                        detail: format!("No account can be found with the ID {}", kid),
                        sub_problems: vec![],
                        instance: None,
                        identifier: None,
                    }));
                }
            }
        }
    };
    let key_openssl = match &key {
        JWSRequestKey::JWK { key, kid: _ } => key.clone(),
        JWSRequestKey::KID(a) => a.key.clone()
    };

    match header.alg.as_str() {
        "RS256" | "RS384" | "RS512" | "ES256" | "ES384" | "ES512" => {
            let msg_digest = match header.alg.as_str() {
                "RS256" | "ES256" => openssl::hash::MessageDigest::sha256(),
                "RS384" | "ES384" => openssl::hash::MessageDigest::sha384(),
                "RS512" | "ES512" => openssl::hash::MessageDigest::sha512(),
                _ => unreachable!()
            };
            let mut verifier = match match match header.alg.as_str() {
                "RS256" | "RS384" | "RS512" => {
                    if let Err(_) = key_openssl.rsa() {
                        None
                    } else {
                        Some(openssl::sign::Verifier::new(msg_digest, &key_openssl))
                    }
                }
                "ES256" | "ES384" | "ES512" => {
                    if let Err(_) = key_openssl.ec_key() {
                        None
                    } else {
                        Some(openssl::sign::Verifier::new(msg_digest, &key_openssl))
                    }
                }
                _ => unreachable!()
            } {
                Some(v) => v,
                None => {
                    return Err((rocket::http::Status::BadRequest, types::error::Error {
                        error_type: types::error::Type::BadSignatureAlgorithm,
                        status: 400,
                        title: "Invalid JWS".to_string(),
                        detail: format!("'{}' is not an appropriate algorithm for the given key", header.alg),
                        sub_problems: vec![],
                        instance: None,
                        identifier: None,
                    }));
                }
            } {
                Ok(v) => v,
                Err(err) => {
                    return Err((rocket::http::Status::BadRequest, types::error::Error {
                        error_type: types::error::Type::BadPublicKey,
                        status: 400,
                        title: "Invalid JWS".to_string(),
                        detail: err.to_string(),
                        sub_problems: vec![],
                        instance: None,
                        identifier: None,
                    }));
                }
            };
            let to_verify = format!("{}.{}", jws.protected, jws.payload);
            let verified = match verifier.verify_oneshot(&signature_bytes, to_verify.as_bytes()) {
                Ok(v) => v,
                Err(_) => {
                    return Err((rocket::http::Status::InternalServerError, crate::internal_server_error!()));
                }
            };
            if !verified {
                return Err((rocket::http::Status::BadRequest, types::error::Error {
                    error_type: types::error::Type::Malformed,
                    status: 400,
                    title: "Invalid JWS signature".to_string(),
                    detail: String::new(),
                    sub_problems: vec![],
                    instance: None,
                    identifier: None,
                }));
            }
        }
        a => {
            return Err((rocket::http::Status::BadRequest, types::error::Error {
                error_type: types::error::Type::BadSignatureAlgorithm,
                status: 400,
                title: "Invalid JWS".to_string(),
                detail: format!("'{}' is not a supported algorithm", a),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            }));
        }
    }

    Ok(key)
}

fn decode_jws_payload<R: serde::de::DeserializeOwned>(
    payload_bytes: &[u8],
) -> Result<R, (rocket::http::Status, types::error::Error)> {
    let payload: R = match serde_json::from_slice(&payload_bytes) {
        Ok(v) => v,
        Err(err) => {
            return Err((rocket::http::Status::BadRequest, types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 400,
                title: "Invalid JWS".to_string(),
                detail: format!("Error decoding payload: '{}'", err),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            }));
        }
    };

    Ok(payload)
}

impl<R: serde::de::DeserializeOwned + std::fmt::Debug> JWSRequestInner<R> {
    pub async fn from_jws(
        uri: rocket::http::uri::Path<'_>, jws: FlattenedJWS, external_uri: &crate::acme::ExternalURL,db: &crate::DBConn,
    ) -> crate::acme::ACMEResult<Self> {
        let (header, payload_bytes, signature_bytes) =
            start_decode_jws(&jws).map_err(|e| e.1)?;

        let req_url = external_uri.0.join(uri.as_str()).unwrap().to_string();
        if req_url != header.url {
            return Err(types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 400,
                title: "Invalid URI".to_string(),
                detail: format!("JWS is for '{}' but request made to '{}'", header.url, req_url),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            });
        }

        let key = verify_jws_sig(&jws, &header, &signature_bytes, &db).await.map_err(|e| e.1)?;

        let payload = decode_jws_payload(&payload_bytes).map_err(|e| e.1)?;

        Ok(JWSRequestInner {
            payload,
            key,
        })
    }
}

#[rocket::async_trait]
impl<'r, R: serde::de::DeserializeOwned + std::fmt::Debug> rocket::data::FromData<'r> for JWSRequest<R> {
    type Error = types::error::Error;

    async fn from_data(request: &'r rocket::request::Request<'_>, data: rocket::data::Data<'r>) -> rocket::data::Outcome<'r, Self> {
        let external_uri = match request.guard::<super::ExternalURL>().await {
            rocket::request::Outcome::Success(v) => v,
            rocket::request::Outcome::Failure(_) => {
                return rocket::data::Outcome::Failure((rocket::http::Status::InternalServerError, crate::internal_server_error!()));
            }
            rocket::request::Outcome::Forward(_) => unreachable!()
        };
        let db = match request.guard::<crate::DBConn>().await {
            rocket::request::Outcome::Success(v) => v,
            rocket::request::Outcome::Failure(_) => {
                return rocket::data::Outcome::Failure((rocket::http::Status::InternalServerError, crate::internal_server_error!()));
            }
            rocket::request::Outcome::Forward(_) => unreachable!()
        };

        let jws = match get_flattened_jws(request, data).await {
            Ok(v) => v,
            Err(e) => return rocket::data::Outcome::Failure(e)
        };

        let (header, payload_bytes, signature_bytes) = match start_decode_jws(&jws) {
            Ok(v) => v,
            Err(e) => return rocket::data::Outcome::Failure(e)
        };

        let nonce = match &header.nonce {
            Some(v) => v,
            None => {
                return rocket::data::Outcome::Failure((rocket::http::Status::BadRequest, types::error::Error {
                    error_type: types::error::Type::Malformed,
                    status: 400,
                    title: "No nonce".to_string(),
                    detail: "A nonce must be provided".to_string(),
                    sub_problems: vec![],
                    instance: None,
                    identifier: None,
                }));
            }
        };
        if let Err(err) = super::replay::verify_nonce(&nonce, &db).await {
            return rocket::data::Outcome::Failure((rocket::http::Status::BadRequest, err));
        }

        let req_url = external_uri.0.join(&request.uri().to_string()).unwrap().to_string();
        if req_url != header.url {
            return rocket::data::Outcome::Failure((rocket::http::Status::BadRequest, types::error::Error {
                error_type: types::error::Type::Malformed,
                status: 400,
                title: "Invalid URI".to_string(),
                detail: format!("JWS is for '{}' but request made to '{}'", header.url, req_url),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            }));
        }

        let key = match verify_jws_sig(&jws, &header,  &signature_bytes, &db).await {
            Ok(v) => v,
            Err(e) => return rocket::data::Outcome::Failure(e)
        };

        let payload = if payload_bytes.len() != 0 {
            match decode_jws_payload(&payload_bytes) {
                Ok(v) => Some(v),
                Err(e) => return rocket::data::Outcome::Failure(e)
            }
        } else {
            None
        };

        rocket::data::Outcome::Success(JWSRequest {
            payload,
            key,
            url: header.url,
        })
    }
}

pub fn make_jwk_thumbprint(jwk: &super::types::jose::JWK) -> String {
    let jwk = serde_json::to_string(jwk).unwrap();
    let jwk: std::collections::BTreeMap<String, serde_json::Value> = serde_json::from_str(&jwk).unwrap();
    let jwk = serde_json::to_string(&jwk).unwrap();
    let thumbprint_bytes = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), jwk.as_bytes()).unwrap().to_vec();
    let thumbprint = BASE64_URL_SAFE_NO_PAD.encode(&thumbprint_bytes);
    thumbprint
}