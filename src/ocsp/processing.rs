use chrono::prelude::*;

#[derive(Debug)]
pub(crate) struct InnerBlockingOCSPClient {
    client: crate::cert_order::ocsp_client::OcspClient<tonic::transport::Channel>,
    rt: tokio::runtime::Runtime,
}

impl InnerBlockingOCSPClient {
    pub(crate) fn check_cert(&mut self, request: impl tonic::IntoRequest<crate::cert_order::CheckCertRequest>)
                             -> Result<tonic::Response<crate::cert_order::CheckCertResponse>, tonic::Status> {
        self.rt.block_on(self.client.check_cert(request))
    }
}

#[derive(Debug)]
pub struct BlockingOCSPClient(std::sync::Arc<std::sync::Mutex<InnerBlockingOCSPClient>>);

impl BlockingOCSPClient {
    pub fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: std::convert::TryInto<tonic::transport::Endpoint>,
            D::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>
    {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        let client = rt.block_on(crate::cert_order::ocsp_client::OcspClient::connect(dst))?;

        Ok(Self(std::sync::Arc::new(std::sync::Mutex::new(InnerBlockingOCSPClient {
            client,
            rt,
        }))))
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, InnerBlockingOCSPClient> {
        self.0.lock().unwrap()
    }
}


pub fn handle_ocsp<'a>(req: &'a [u8], ocsp_issuers: &'a super::issuers::OCSPIssuers) -> super::types::OCSPResponse<'a> {
    let req = match super::types::parse_ocsp_req(&req) {
        Ok(r) => r,
        Err(e) => return e
    };

    if req.request.requests.len() < 1 {
        return super::types::OCSPResponse {
            status: super::types::OCSPResponseStatus::MalformedRequest,
            response: None,
        };
    }

    if let Some(nonce) = req.request.nonce {
        if nonce.len() == 0 || nonce.len() > 32 {
            return super::types::OCSPResponse {
                status: super::types::OCSPResponseStatus::MalformedRequest,
                response: None,
            };
        }
    }

    if let Some(acceptable_responses) = req.request.acceptable_responses {
        if !acceptable_responses.contains(&super::types::OCSPResponseTypeTag::BasicResponse) {
            return super::types::OCSPResponse {
                status: super::types::OCSPResponseStatus::MalformedRequest,
                response: None,
            };
        }
    }

    let first_request = req.request.requests.get(0).unwrap();
    let first_issuer = match ocsp_issuers.find_issuer(&first_request.cert_id) {
        Some(i) => i,
        None => return super::types::OCSPResponse {
            status: super::types::OCSPResponseStatus::Unauthorized,
            response: None,
        }
    };

    for cert_req in &req.request.requests[1..] {
        let ocsp_issuer = ocsp_issuers.find_issuer(&cert_req.cert_id);
        match ocsp_issuer {
            Some(i) => {
                if i.cert_id != first_issuer.cert_id {
                    return super::types::OCSPResponse {
                        status: super::types::OCSPResponseStatus::MalformedRequest,
                        response: None,
                    };
                }
            }
            None => return super::types::OCSPResponse {
                status: super::types::OCSPResponseStatus::Unauthorized,
                response: None,
            }
        }
    }

    let mut single_responses = vec![];

    for cert_req in req.request.requests {
        let mut locked_client = first_issuer.grpc_client.lock();
        let check_cert_resp = match locked_client.check_cert(crate::cert_order::CheckCertRequest {
            issuer_id: first_issuer.cert_id.clone(),
            serial_number: cert_req.cert_id.serial_number.to_vec(),
        }) {
            Ok(r) => r.into_inner(),
            Err(e) => {
                warn!("Unable to check certificate status: {:?}", e);
                return super::types::OCSPResponse {
                    status: super::types::OCSPResponseStatus::InternalError,
                    response: None,
                };
            }
        };
        std::mem::drop(locked_client);
        single_responses.push(super::types::SingleOCSPResponse {
            cert_id: cert_req.cert_id.clone(),
            cert_status: match crate::cert_order::CertStatus::from_i32(check_cert_resp.status) {
                Some(crate::cert_order::CertStatus::CertGood) => super::types::CertStatus::Good,
                Some(crate::cert_order::CertStatus::CertUnknown) => super::types::CertStatus::Unknown,
                Some(crate::cert_order::CertStatus::CertRevoked) => super::types::CertStatus::Revoked(super::types::RevokedInfo {
                    revocation_time: match crate::util::proto_to_chrono(check_cert_resp.revocation_timestamp) {
                        Some(t) => t,
                        None => return super::types::OCSPResponse {
                            status: super::types::OCSPResponseStatus::InternalError,
                            response: None,
                        }
                    },
                    revocation_reason: match crate::cert_order::RevocationReason::from_i32(check_cert_resp.revocation_reason) {
                        None => None,
                        Some(crate::cert_order::RevocationReason::RevocationUnknown) => None,
                        Some(crate::cert_order::RevocationReason::RevocationUnspecified) => Some(super::types::RevocationReason::Unspecified),
                        Some(crate::cert_order::RevocationReason::RevocationKeyCompromise) => Some(super::types::RevocationReason::KeyCompromise),
                        Some(crate::cert_order::RevocationReason::RevocationCaCompromise) => Some(super::types::RevocationReason::CACompromise),
                        Some(crate::cert_order::RevocationReason::RevocationAffiliationChanged) => Some(super::types::RevocationReason::AffiliationChanged),
                        Some(crate::cert_order::RevocationReason::RevocationSuperseded) => Some(super::types::RevocationReason::Superseded),
                        Some(crate::cert_order::RevocationReason::RevocationCessationOfOperation) => Some(super::types::RevocationReason::CessationOfOperation),
                        Some(crate::cert_order::RevocationReason::RevocationCertificateHold) => Some(super::types::RevocationReason::CertificateHold),
                        Some(crate::cert_order::RevocationReason::RevocationRemoveFromCrl) => Some(super::types::RevocationReason::RemoveFromCRL),
                        Some(crate::cert_order::RevocationReason::RevocationPrivilegeWithdrawn) => Some(super::types::RevocationReason::PrivilegeWithdrawn),
                        Some(crate::cert_order::RevocationReason::RevocationAaCompromise) => Some(super::types::RevocationReason::AACompromise),
                    },
                }),
                Some(crate::cert_order::CertStatus::CertUnissued) => super::types::CertStatus::Revoked(super::types::RevokedInfo {
                    revocation_time: Utc.timestamp(0, 0),
                    revocation_reason: Some(super::types::RevocationReason::CertificateHold),
                }),
                None => super::types::CertStatus::Unknown,
            },
            this_update: crate::util::proto_to_chrono(check_cert_resp.this_update).unwrap_or_else(Utc::now),
            next_update: crate::util::proto_to_chrono(check_cert_resp.next_update),
            archive_cutoff: crate::util::proto_to_chrono(check_cert_resp.archive_cutoff),
            invalidity_date: crate::util::proto_to_chrono(check_cert_resp.invalidity_date),
        });
        println!("{:?}", single_responses);
    }

    super::types::OCSPResponse {
        status: super::types::OCSPResponseStatus::Successful,
        response: Some(super::types::OCSPResponseType::BasicResponse(super::types::BasicOCSPResponse {
            produced_at: Utc::now(),
            issuer: &first_issuer,
            responses: single_responses,
            nonce: req.request.nonce,
        })),
    }
}