use diesel::prelude::*;
use std::convert::TryInto;

pub type OrderClient = crate::cert_order::ca_client::CaClient<tonic::transport::Channel>;

pub(crate) async fn verify_eab(
    client: &mut OrderClient, eab: &crate::types::jose::FlattenedJWS, req_url: &str,
    acct_key: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> super::ACMEResult<String> {
    let (eab_header, eab_payload_bytes, eab_signature_bytes) = match super::jws::start_decode_jws(&eab) {
        Ok(v) => v,
        Err(e) => return Err(e.1)
    };

    if eab_header.nonce.is_some() {
        return Err(crate::types::error::Error {
            error_type: crate::types::error::Type::Malformed,
            status: 400,
            title: "Bad request".to_string(),
            detail: "EAB must not contain a nonce".to_string(),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        });
    }

    if eab_header.url != req_url {
        return Err(crate::types::error::Error {
            error_type: crate::types::error::Type::Malformed,
            status: 400,
            title: "Bad request".to_string(),
            detail: "EAB URL must match outer URL".to_string(),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        });
    }

    let eab_id = match eab_header.key {
        crate::types::jose::JWKKey::KID(i) => i,
        _ => return Err(crate::types::error::Error {
            error_type: crate::types::error::Type::Malformed,
            status: 400,
            title: "Bad request".to_string(),
            detail: "EAB must contain KID".to_string(),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        })
    };

    let eab_jwk: openssl::pkey::PKey<openssl::pkey::Public> = (
        &serde_json::from_slice::<crate::types::jose::JWK>(&eab_payload_bytes)
            .map_err(|err| crate::types::error::Error {
                error_type: crate::types::error::Type::Malformed,
                status: 400,
                title: "Invalid JWK".to_string(),
                detail: format!("Invalid JWK header: '{}'", err),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            })?
    ).try_into().map_err(|err| crate::types::error::Error {
        error_type: crate::types::error::Type::BadPublicKey,
        status: 400,
        title: "Invalid public key".to_string(),
        detail: err,
        sub_problems: vec![],
        instance: None,
        identifier: None,
    })?;

    if !acct_key.public_eq(&eab_jwk) {
        return Err(crate::types::error::Error {
            error_type: crate::types::error::Type::Malformed,
            status: 400,
            title: "Bad request".to_string(),
            detail: "EAB key must match outer key".to_string(),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        });
    }

    let signature_method: i32 = match eab_header.alg.as_str() {
        "HS256" => crate::cert_order::EabSignatureMethod::Hs256.into(),
        "HS384" => crate::cert_order::EabSignatureMethod::Hs384.into(),
        "HS512" => crate::cert_order::EabSignatureMethod::Hs512.into(),
        "HS1" => crate::cert_order::EabSignatureMethod::Hs1.into(),
        _ => return Err(crate::types::error::Error {
            error_type: crate::types::error::Type::BadSignatureAlgorithm,
            status: 400,
            title: "Bad request".to_string(),
            detail: "Invalid EAB signature algorithm".to_string(),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        })
    };

    let eab_result = crate::try_db_result!(client.validate_eab(crate::cert_order::ValidateEabRequest {
            kid: eab_id.clone(),
            signature_method,
            signed_data: format!("{}.{}", eab.protected, eab.payload).into_bytes(),
            signature: eab_signature_bytes,
        }).await, "Failed to check EAB: {}")?;

    if !eab_result.get_ref().valid {
        return Err(crate::types::error::Error {
            error_type: crate::types::error::Type::Malformed,
            status: 403,
            title: "Forbidden".to_string(),
            detail: "EAB signature did not verify".to_string(),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        });
    }

    Ok(eab_id)
}

pub(crate) fn map_rpc_identifier(i: crate::cert_order::Identifier) -> crate::types::identifier::Identifier {
    crate::types::identifier::Identifier {
        id_type: match crate::cert_order::IdentifierType::from_i32(i.id_type) {
            None => "".to_string(),
            Some(crate::cert_order::IdentifierType::UnknownIdentifier) => "".to_string(),
            Some(crate::cert_order::IdentifierType::DnsIdentifier) => crate::types::identifier::Type::DNS.to_string(),
            Some(crate::cert_order::IdentifierType::IpIdentifier) => crate::types::identifier::Type::IP.to_string(),
            Some(crate::cert_order::IdentifierType::EmailIdentifier) => crate::types::identifier::Type::Email.to_string(),
        },
        value: i.identifier,
    }
}

pub(crate) fn rpc_error_to_problem(err: crate::cert_order::Error) -> crate::types::error::Error {
    crate::types::error::Error {
        error_type: match crate::cert_order::ErrorType::from_i32(err.error_type) {
            None => crate::types::error::Type::ServerInternal,
            Some(crate::cert_order::ErrorType::ServerInternalError) => crate::types::error::Type::ServerInternal,
            Some(crate::cert_order::ErrorType::AccountDoesNotExistError) => crate::types::error::Type::AccountDoesNotExist,
            Some(crate::cert_order::ErrorType::AlreadyRevokedError) => crate::types::error::Type::AlreadyRevoked,
            Some(crate::cert_order::ErrorType::BadCsrError) => crate::types::error::Type::BadCSR,
            Some(crate::cert_order::ErrorType::BadNonceError) => crate::types::error::Type::BadNonce,
            Some(crate::cert_order::ErrorType::BadPublicKeyError) => crate::types::error::Type::BadPublicKey,
            Some(crate::cert_order::ErrorType::BadRevocationReasonError) => crate::types::error::Type::BadRevocationReason,
            Some(crate::cert_order::ErrorType::BadSignatureAlgorithmError) => crate::types::error::Type::BadSignatureAlgorithm,
            Some(crate::cert_order::ErrorType::CaaError) => crate::types::error::Type::CAA,
            Some(crate::cert_order::ErrorType::CompoundError) => crate::types::error::Type::Compound,
            Some(crate::cert_order::ErrorType::ConnectionError) => crate::types::error::Type::Connection,
            Some(crate::cert_order::ErrorType::DnsError) => crate::types::error::Type::DNS,
            Some(crate::cert_order::ErrorType::ExternalAccountRequiredError) => crate::types::error::Type::ExternalAccountRequired,
            Some(crate::cert_order::ErrorType::IncorrectResponseError) => crate::types::error::Type::IncorrectResponse,
            Some(crate::cert_order::ErrorType::InvalidContactError) => crate::types::error::Type::InvalidContact,
            Some(crate::cert_order::ErrorType::MalformedError) => crate::types::error::Type::Malformed,
            Some(crate::cert_order::ErrorType::OrderNotReadyError) => crate::types::error::Type::OrderNotReady,
            Some(crate::cert_order::ErrorType::RateLimitedError) => crate::types::error::Type::RateLimited,
            Some(crate::cert_order::ErrorType::RejectedIdentifierError) => crate::types::error::Type::RejectedIdentifier,
            Some(crate::cert_order::ErrorType::TlsError) => crate::types::error::Type::TLS,
            Some(crate::cert_order::ErrorType::UnauthorizedError) => crate::types::error::Type::Unauthorized,
            Some(crate::cert_order::ErrorType::UnsupportedContactError) => crate::types::error::Type::UnsupportedContact,
            Some(crate::cert_order::ErrorType::UnsupportedIdentifierError) => crate::types::error::Type::UnsupportedIdentifier,
            Some(crate::cert_order::ErrorType::UserActionRequiredError) => crate::types::error::Type::UserActionRequired,
            Some(crate::cert_order::ErrorType::AutoRenewalCanceledError) => crate::types::error::Type::AutoRenewalCanceled,
            Some(crate::cert_order::ErrorType::AutoRenewalExpiredError) => crate::types::error::Type::AutoRenewalExpired,
            Some(crate::cert_order::ErrorType::AutoRenewalCancellationInvalidError) => crate::types::error::Type::AutoRenewalCancellationInvalid,
            Some(crate::cert_order::ErrorType::AutoRenewalRevocationNotSupportedError) => crate::types::error::Type::AutoRenewalRevocationNotSupported,
        },
        title: err.title,
        status: err.status as u16,
        detail: err.detail,
        instance: err.instance,
        sub_problems: err.sub_problems.into_iter().map(rpc_error_to_problem).collect(),
        identifier: err.identifier.map(map_rpc_identifier),
    }
}

pub(crate) fn unwrap_order_response(resp: crate::cert_order::OrderResponse) -> crate::acme::ACMEResult<crate::cert_order::Order> {
    match resp.result {
        Some(crate::cert_order::order_response::Result::Order(o)) => Ok(o),
        Some(crate::cert_order::order_response::Result::Error(e)) => Err(
            crate::util::error_list_to_result(
                e.errors.into_iter().map(rpc_error_to_problem).collect(),
                "Multiple errors make this order invalid".to_string(),
            ).err().unwrap()
        ),
        None => Err(crate::internal_server_error!())
    }
}

pub(crate) fn unwrap_authz_response(resp: crate::cert_order::AuthorizationResponse) -> crate::acme::ACMEResult<crate::cert_order::Authorization> {
    match resp.result {
        Some(crate::cert_order::authorization_response::Result::Authorization(a)) => Ok(a),
        Some(crate::cert_order::authorization_response::Result::Error(e)) => Err(
            crate::util::error_list_to_result(
                e.errors.into_iter().map(rpc_error_to_problem).collect(),
                "Multiple errors make this authorization invalid".to_string(),
            ).err().unwrap()
        ),
        None => Err(crate::internal_server_error!())
    }
}

pub(crate) fn unwrap_chall_response(resp: crate::cert_order::ChallengeResponse) -> crate::acme::ACMEResult<crate::cert_order::Challenge> {
    match resp.result {
        Some(crate::cert_order::challenge_response::Result::Challenge(a)) => Ok(a),
        Some(crate::cert_order::challenge_response::Result::Error(e)) => Err(
            crate::util::error_list_to_result(
                e.errors.into_iter().map(rpc_error_to_problem).collect(),
                "Multiple errors make this challenge invalid".to_string(),
            ).err().unwrap()
        ),
        None => Err(crate::internal_server_error!())
    }
}

pub(crate) async fn create_order(
    client: &mut OrderClient, db: &crate::DBConn,
    order: &crate::types::order::OrderCreate, account: &crate::acme::Account,
) -> crate::acme::ACMEResult<(super::models::Order, crate::cert_order::Order)> {
    let mut errors = vec![];

    let mut identifiers = vec![];

    for id in &order.identifiers {
        let id_type = crate::types::identifier::Type::from_str(&id.id_type);
        let grpc_id_type = match id_type {
            Some(crate::types::identifier::Type::DNS) => crate::cert_order::IdentifierType::DnsIdentifier,
            Some(crate::types::identifier::Type::IP) => crate::cert_order::IdentifierType::IpIdentifier,
            Some(crate::types::identifier::Type::Email) => crate::cert_order::IdentifierType::EmailIdentifier,
            None => {
                errors.push(crate::types::error::Error {
                    error_type: crate::types::error::Type::UnsupportedIdentifier,
                    status: 400,
                    title: "Unsupported identifier".to_string(),
                    detail: format!("'{}' is not an identifier we support", id.id_type),
                    sub_problems: vec![],
                    instance: None,
                    identifier: Some(id.to_owned()),
                });
                continue;
            }
        };
        identifiers.push(crate::cert_order::Identifier {
            id_type: grpc_id_type.into(),
            identifier: id.value.clone(),
        });
    }

    crate::util::error_list_to_result(errors, "Multiple errors make this order invalid".to_string())?;

    let order_result = crate::try_db_result!(client.create_order(crate::cert_order::CreateOrderRequest {
        identifiers,
        not_before: crate::util::chrono_to_proto(order.not_before),
        not_after: crate::util::chrono_to_proto(order.not_after),
        account_id: account.inner.id.to_string(),
        eab_id: account.inner.eab_id.clone(),
    }).await, "Failed to create order: {}")?;

    let ca_order = unwrap_order_response(order_result.into_inner())?;

    let db_order = super::models::Order {
        id: uuid::Uuid::new_v4(),
        account: account.inner.id,
        ca_id: ca_order.id.clone(),
    };

    let db_order = crate::try_db_result!(db.run(move |c|
        diesel::insert_into(super::schema::orders::dsl::orders)
            .values(&db_order).get_result(c)
    ).await,
        "Unable to save order to database: {}"
    )?;

    Ok((db_order, ca_order))
}

pub(crate) async fn create_authz(
    client: &mut OrderClient, db: &crate::DBConn,
    authz: &crate::types::authorization::AuthorizationCreate, account: &crate::acme::Account,
) -> crate::acme::ACMEResult<(super::models::Authorization, crate::cert_order::Authorization)> {
    let grpc_id_type = match crate::types::identifier::Type::from_str(&authz.identifier.id_type) {
        Some(crate::types::identifier::Type::DNS) => crate::cert_order::IdentifierType::DnsIdentifier,
        Some(crate::types::identifier::Type::IP) => crate::cert_order::IdentifierType::IpIdentifier,
        Some(crate::types::identifier::Type::Email) => crate::cert_order::IdentifierType::EmailIdentifier,
        None => {
            return Err(crate::types::error::Error {
                error_type: crate::types::error::Type::UnsupportedIdentifier,
                status: 400,
                title: "Unsupported identifier".to_string(),
                detail: format!("'{}' is not an identifier we support", authz.identifier.id_type),
                sub_problems: vec![],
                instance: None,
                identifier: Some(authz.identifier.to_owned()),
            });
        }
    };
    let identifier = crate::cert_order::Identifier {
        id_type: grpc_id_type.into(),
        identifier: authz.identifier.value.clone(),
    };

    let authz_result = crate::try_db_result!(client.create_authorization(crate::cert_order::CreateAuthorizationRequest {
        identifier: Some(identifier),
        account_id: account.inner.id.to_string(),
        eab_id: account.inner.eab_id.clone(),
    }).await, "Failed to create authorization: {}")?;

    let ca_authz = unwrap_authz_response(authz_result.into_inner())?;

    let db_authz = super::models::Authorization {
        id: uuid::Uuid::new_v4(),
        account: account.inner.id,
        ca_id: ca_authz.id.clone(),
    };

    let db_authz = crate::try_db_result!(db.run(move |c|
        diesel::insert_into(super::schema::authorizations::dsl::authorizations)
            .values(&db_authz).get_result(c)
    ).await,
        "Unable to save authorization to database: {}"
    )?;

    Ok((db_authz, ca_authz))
}