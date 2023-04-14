use base64::prelude::*;

pub fn uuid_as_b64(uuid: &uuid::Uuid) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(uuid.as_bytes())
}

pub fn b64_to_uuid(b64: &str) -> Option<uuid::Uuid> {
    let uuid_bytes = match BASE64_URL_SAFE_NO_PAD.decode(b64) {
        Ok(n) => n,
        Err(_) => {
            return None;
        }
    };
    let uuid_obj = match uuid::Uuid::from_slice(&uuid_bytes) {
        Ok(u) => u,
        Err(_) => {
            return None
        }
    };
    Some(uuid_obj)
}

/// Helper function to convert chrono times to protobuf well-known type times
pub fn chrono_to_proto<T: chrono::TimeZone>(
    time: Option<chrono::DateTime<T>>,
) -> Option<prost_types::Timestamp> {
    time.map(|t| prost_types::Timestamp {
        seconds: t.timestamp(),
        nanos: t.timestamp_subsec_nanos() as i32,
    })
}

pub fn proto_to_chrono(
    time: Option<prost_types::Timestamp>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::offset::TimeZone;
    match time {
        Some(t) => chrono::Utc
            .timestamp_opt(t.seconds, t.nanos as u32)
            .single(),
        None => None,
    }
}

pub fn error_list_to_result<D: Into<Option<String>>>(
    mut errors: Vec<crate::types::error::Error>, compound_detail: D
) -> Result<(), crate::types::error::Error> {
    match errors.len() {
        0 => Ok(()),
        1 => Err(errors.pop().unwrap()),
        _ => Err(crate::types::error::Error {
            error_type: crate::types::error::Type::Compound,
            status: 400,
            title: "Compound errors".to_string(),
            detail: match compound_detail.into() {
                Some(d) => d,
                None => "Multiple errors make this request invalid".to_string(),
            },
            sub_problems: errors,
            instance: None,
            identifier: None,
        })
    }
}

pub fn cvt(r: libc::c_int) -> Result<libc::c_int, openssl::error::ErrorStack> {
    if r <= 0 {
        Err(openssl::error::ErrorStack::get())
    } else {
        Ok(r)
    }
}

pub fn cvt_p<T>(r: *mut T) -> Result<*mut T, openssl::error::ErrorStack> {
    if r.is_null() {
        Err(openssl::error::ErrorStack::get())
    } else {
        Ok(r)
    }
}

// pub fn cvt_cp<T>(r: *const T) -> Result<*const T, openssl::error::ErrorStack> {
//     if r.is_null() {
//         Err(openssl::error::ErrorStack::get())
//     } else {
//         Ok(r)
//     }
// }