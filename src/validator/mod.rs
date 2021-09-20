pub mod caa;

#[derive(Debug)]
pub struct Validator {
    dns_resolver: trust_dns_resolver::TokioAsyncResolver,
    reqwest_client: reqwest::Client,
    caa_identities: Vec<String>,
}

impl Validator {
    pub fn new(caa_identities: Vec<String>) -> Validator {
        let resolver = trust_dns_resolver::AsyncResolver::tokio_from_system_conf()
            .expect("Unable to read DNS config");
        let client = reqwest::Client::builder()
            .user_agent(concat!(env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION")))
            .gzip(true)
            .brotli(true)
            .deflate(true)
            .redirect(reqwest::redirect::Policy::limited(10))
            .referer(true)
            .no_proxy()
            .build()
            .expect("Unable to build HTTP client");

        Validator {
            dns_resolver: resolver,
            reqwest_client: client,
            caa_identities,
        }
    }
}

async fn check_caa(validator: &Validator, identifier: &str) -> Option<crate::cert_order::ValidationResult> {
    let caa_res = match caa::verify_caa_record(validator, identifier).await {
        Ok(r) => r,
        Err(err) => match err {
            caa::CAAError::ServFail => return Some(crate::cert_order::ValidationResult {
                valid: false,
                error: Some(crate::cert_order::ErrorResponse {
                    errors: vec![crate::cert_order::Error {
                        error_type: crate::cert_order::ErrorType::DnsError.into(),
                        title: "CAA error".to_string(),
                        detail: "SERVFAIL when checking CAA record".to_string(),
                        status: 400,
                        identifier: None,
                        instance: None,
                        sub_problems: vec![],
                    }]
                }),
            }),
            caa::CAAError::UnsupportedCritical => return Some(crate::cert_order::ValidationResult {
                valid: false,
                error: Some(crate::cert_order::ErrorResponse {
                    errors: vec![crate::cert_order::Error {
                        error_type: crate::cert_order::ErrorType::CaaError.into(),
                        title: "CAA error".to_string(),
                        detail: "Unsupported critical CAA record".to_string(),
                        status: 400,
                        identifier: None,
                        instance: None,
                        sub_problems: vec![],
                    }]
                }),
            })
        }
    };

    if !caa_res {
        return Some(crate::cert_order::ValidationResult {
            valid: false,
            error: Some(crate::cert_order::ErrorResponse {
                errors: vec![crate::cert_order::Error {
                    error_type: crate::cert_order::ErrorType::CaaError.into(),
                    title: "CAA error".to_string(),
                    detail: "CAA policy prohibits issuance".to_string(),
                    status: 400,
                    identifier: None,
                    instance: None,
                    sub_problems: vec![],
                }]
            }),
        });
    }

    None
}

#[tonic::async_trait]
impl crate::cert_order::validator_server::Validator for Validator {
    async fn validate_http01(
        &self, request: tonic::Request<crate::cert_order::KeyValidationRequest>,
    ) -> Result<tonic::Response<crate::cert_order::ValidationResult>, tonic::Status> {
        let req = request.into_inner();

        if let Some(caa_err) = check_caa(self, &req.identifier).await {
            return Ok(tonic::Response::new(caa_err));
        }

        let test_uri = format!("http://{}/.well-known/acme-challenge/{}", req.identifier, req.token);
        let key_auth = format!("{}.{}", req.token, req.account_thumbprint);

        let test_uri = match reqwest::Url::parse(&test_uri) {
            Ok(u) => u,
            Err(_) => return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                valid: false,
                error: Some(crate::cert_order::ErrorResponse {
                    errors: vec![crate::cert_order::Error {
                        error_type: crate::cert_order::ErrorType::MalformedError.into(),
                        title: "Validation failed".to_string(),
                        detail: "Invalid URI".to_string(),
                        status: 400,
                        identifier: None,
                        instance: None,
                        sub_problems: vec![],
                    }]
                }),
            }))
        };
        let resp = match self.reqwest_client.get(test_uri).send().await {
            Ok(u) => u,
            Err(err) => {
                if err.is_timeout() {
                    return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                        valid: false,
                        error: Some(crate::cert_order::ErrorResponse {
                            errors: vec![crate::cert_order::Error {
                                error_type: crate::cert_order::ErrorType::ConnectionError.into(),
                                title: "Validation failed".to_string(),
                                detail: "Connection timed out".to_string(),
                                status: 400,
                                identifier: None,
                                instance: None,
                                sub_problems: vec![],
                            }]
                        }),
                    }));
                } else if err.is_connect() {
                    return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                        valid: false,
                        error: Some(crate::cert_order::ErrorResponse {
                            errors: vec![crate::cert_order::Error {
                                error_type: crate::cert_order::ErrorType::ConnectionError.into(),
                                title: "Validation failed".to_string(),
                                detail: "Connection refused".to_string(),
                                status: 400,
                                identifier: None,
                                instance: None,
                                sub_problems: vec![],
                            }]
                        }),
                    }));
                } else if err.is_redirect() {
                    return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                        valid: false,
                        error: Some(crate::cert_order::ErrorResponse {
                            errors: vec![crate::cert_order::Error {
                                error_type: crate::cert_order::ErrorType::ConnectionError.into(),
                                title: "Validation failed".to_string(),
                                detail: "Too many redirects".to_string(),
                                status: 400,
                                identifier: None,
                                instance: None,
                                sub_problems: vec![],
                            }]
                        }),
                    }));
                } else {
                    return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                        valid: false,
                        error: Some(crate::cert_order::ErrorResponse {
                            errors: vec![crate::cert_order::Error {
                                error_type: crate::cert_order::ErrorType::ConnectionError.into(),
                                title: "Validation failed".to_string(),
                                detail: "Unknown request error".to_string(),
                                status: 400,
                                identifier: None,
                                instance: None,
                                sub_problems: vec![],
                            }]
                        }),
                    }));
                }
            }
        };
        if !resp.status().is_success() {
            return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                valid: false,
                error: Some(crate::cert_order::ErrorResponse {
                    errors: vec![crate::cert_order::Error {
                        error_type: crate::cert_order::ErrorType::IncorrectResponseError.into(),
                        title: "Validation failed".to_string(),
                        detail: format!("HTTP {} received", resp.status().as_str()),
                        status: 400,
                        identifier: None,
                        instance: None,
                        sub_problems: vec![],
                    }]
                }),
            }));
        }
        let resp_txt = match resp.text().await {
            Ok(u) => u.trim().to_string(),
            Err(_) => return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                valid: false,
                error: Some(crate::cert_order::ErrorResponse {
                    errors: vec![crate::cert_order::Error {
                        error_type: crate::cert_order::ErrorType::IncorrectResponseError.into(),
                        title: "Validation failed".to_string(),
                        detail: "Text charset error".to_string(),
                        status: 400,
                        identifier: None,
                        instance: None,
                        sub_problems: vec![],
                    }]
                }),
            }))
        };

        if resp_txt == key_auth {
            Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                valid: true,
                error: None,
            }))
        } else {
            return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                valid: false,
                error: Some(crate::cert_order::ErrorResponse {
                    errors: vec![crate::cert_order::Error {
                        error_type: crate::cert_order::ErrorType::IncorrectResponseError.into(),
                        title: "Validation failed".to_string(),
                        detail: format!("Expected '{}', received '{}'", key_auth, resp_txt),
                        status: 400,
                        identifier: None,
                        instance: None,
                        sub_problems: vec![],
                    }]
                }),
            }));
        }
    }

    async fn validate_dns01(
        &self, request: tonic::Request<crate::cert_order::KeyValidationRequest>,
    ) -> Result<tonic::Response<crate::cert_order::ValidationResult>, tonic::Status> {
        let req = request.into_inner();

        if let Some(caa_err) = check_caa(self, &req.identifier).await {
            return Ok(tonic::Response::new(caa_err));
        }

        let key_auth = format!("{}.{}", req.token, req.account_thumbprint);
        let key_auth_hash_bytes = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), key_auth.as_bytes()).unwrap().to_vec();
        let key_auth_hash = base64::encode_config(&key_auth_hash_bytes, base64::URL_SAFE_NO_PAD);
        let key_auth_hash_utf8 = key_auth_hash.as_bytes();

        let search_domain = format!("_acme-challenge.{}.", req.identifier.trim_end_matches('.'));
        match self.dns_resolver.lookup(
            search_domain.clone(), trust_dns_proto::rr::record_type::RecordType::TXT,
            trust_dns_proto::xfer::dns_request::DnsRequestOptions {
                expects_multiple_responses: false,
                use_edns: true,
            },
        ).await {
            Ok(r) => {
                for record in r.iter()
                    .filter_map(|r| match r {
                        trust_dns_proto::rr::record_data::RData::TXT(d) => Some(d),
                        _ => None
                    }) {
                    if let Some(txt_data) = record.txt_data().iter().next() {
                        if txt_data.as_ref() == key_auth_hash_utf8 {
                            return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                                    valid: true,
                                    error: None,
                            }));
                        }
                    }
                }

                Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                    valid: false,
                    error: Some(crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::IncorrectResponseError.into(),
                            title: "Validation failed".to_string(),
                            detail: format!("No TXT records found for {} with the value '{}'", search_domain, key_auth_hash),
                            status: 400,
                            identifier: None,
                            instance: None,
                            sub_problems: vec![],
                        }]
                    }),
                }))
            }
            Err(err) => match err.kind() {
                trust_dns_resolver::error::ResolveErrorKind::NoRecordsFound { .. } => Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                    valid: false,
                    error: Some(crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::DnsError.into(),
                            title: "Validation failed".to_string(),
                            detail: format!("No TXT records found for {}", search_domain),
                            status: 400,
                            identifier: None,
                            instance: None,
                            sub_problems: vec![],
                        }]
                    }),
                })),
                _ => Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                    valid: false,
                    error: Some(crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::DnsError.into(),
                            title: "Validation failed".to_string(),
                            detail: format!("SERVFAIL whilst getting records for {}", search_domain),
                            status: 400,
                            identifier: None,
                            instance: None,
                            sub_problems: vec![],
                        }]
                    }),
                }))
            }
        }
    }
}