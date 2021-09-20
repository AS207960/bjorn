use crate::types;
use diesel::prelude::*;

lazy_static! {
    static ref NONCES: std::sync::Mutex<std::collections::HashSet<uuid::Uuid>> = std::sync::Mutex::new(std::collections::HashSet::new());
}

#[derive(Debug)]
pub struct ReplayNonce<R>(pub R);

impl<'r, R: rocket::response::Responder<'r>> rocket::response::Responder<'r> for ReplayNonce<R> {
    fn respond_to(self, request: &rocket::request::Request<'_>) -> rocket::response::Result<'r> {
        let mut result = self.0.respond_to(request)?;

        let db = match request.guard::<crate::DBConn>() {
            rocket::request::Outcome::Success(v) => v,
            rocket::request::Outcome::Failure(e) => return Err(e.0),
            rocket::request::Outcome::Forward(_) => unreachable!()
        };

        let new_nonce = super::models::Nonce {
            nonce: uuid::Uuid::new_v4(),
            issued_at: chrono::Utc::now(),
        };
        let nonce = match diesel::insert_into(super::schema::nonces::table)
            .values(&new_nonce)
            .get_result::<super::models::Nonce>(&db.0) {
            Err(err) => {
                error!("Error inserting new nonce: {}", err);
                return Err(rocket::http::Status::InternalServerError);
            }
            Ok(v) => v,
        };

        let nonce = crate::util::uuid_as_b64(&nonce.nonce);
        result.set_raw_header("Replay-Nonce", nonce);
        Ok(result)
    }
}

pub(crate) fn verify_nonce(nonce: &str, db: &crate::DBConn) -> crate::acme::ACMEResult<()> {
    let nonce_uuid = match crate::util::b64_to_uuid(&nonce) {
        Some(v) => v,
        None => {
            return Err(types::error::Error {
                error_type: types::error::Type::BadNonce,
                status: 400,
                title: "Bad nonce".to_string(),
                detail: "Invalid nonce format".to_string(),
                sub_problems: vec![],
                instance: None,
                identifier: None,
            });
        }
    };

    let affected = match diesel::delete(super::schema::nonces::dsl::nonces.filter(
        super::schema::nonces::dsl::nonce.eq(&nonce_uuid))
    ).execute(&db.0) {
        Ok(v) => v,
        Err(err) => {
            error!("Error checking nonce validitiy: {}", err);
            return Err(crate::internal_server_error!());
        }
    };

    if affected < 1 {
        return Err(types::error::Error {
            error_type: types::error::Type::BadNonce,
            status: 400,
            title: "Bad nonce".to_string(),
            detail: "The nonce may have expired or it is being reused.".to_string(),
            sub_problems: vec![],
            instance: None,
            identifier: None,
        });
    }
    Ok(())
}