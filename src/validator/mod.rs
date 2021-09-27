use foreign_types::ForeignType;

pub mod caa;

#[derive(Debug)]
pub enum Identifier {
    Domain(String, bool),
    IPAddr(std::net::IpAddr),
    Email(String),
}

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

async fn check_caa(
    validator: &Validator, identifier: &Identifier, validation_method: &str, account_uri: Option<&str>
) -> Option<crate::cert_order::ValidationResult> {
    let caa_res = match caa::verify_caa_record(validator, identifier, validation_method, account_uri).await {
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

fn map_identifier(identifier: Option<crate::cert_order::Identifier>) -> Result<Identifier, tonic::Status> {
    if let Some(identifier) = identifier {
        Ok(match crate::cert_order::IdentifierType::from_i32(identifier.id_type) {
            _ => return Err(tonic::Status::invalid_argument("Invalid identifier type specified")),
            Some(crate::cert_order::IdentifierType::DnsIdentifier) => {
                let is_wild = identifier.identifier.starts_with("*.");
                if is_wild {
                    Identifier::Domain(identifier.identifier[2..].to_string(), true)
                } else {
                    Identifier::Domain(identifier.identifier, false)
                }
            }
            Some(crate::cert_order::IdentifierType::IpIdentifier) => {
                let ip_addr: std::net::IpAddr = match std::str::FromStr::from_str(&identifier.identifier) {
                    Ok(a) => a,
                    Err(_) => return Err(tonic::Status::invalid_argument("Invalid IP address")),
                };
                Identifier::IPAddr(ip_addr)
            }
            Some(crate::cert_order::IdentifierType::EmailIdentifier) => {
                Identifier::Email(identifier.identifier)
            }
        })
    } else {
        Err(tonic::Status::invalid_argument("Identifier must be specified"))
    }
}

#[tonic::async_trait]
impl crate::cert_order::validator_server::Validator for Validator {
    async fn validate_http01(
        &self, request: tonic::Request<crate::cert_order::KeyValidationRequest>,
    ) -> Result<tonic::Response<crate::cert_order::ValidationResult>, tonic::Status> {
        let req = request.into_inner();
        let identifier = map_identifier(req.identifier.clone())?;

        if let Some(caa_err) = check_caa(self, &identifier, "http-01", req.account_uri.as_deref()).await {
            return Ok(tonic::Response::new(caa_err));
        }

        let test_uri = match identifier {
            Identifier::Domain(domain, _) => format!("http://{}:80/.well-known/acme-challenge/{}", domain, req.token),
            Identifier::IPAddr(ip) => match ip {
                std::net::IpAddr::V4(ipv4) => format!("http://{}:80/.well-known/acme-challenge/{}", ipv4, req.token),
                std::net::IpAddr::V6(ipv6) => format!("http://[{}]:80/.well-known/acme-challenge/{}", ipv6, req.token),
            },
            Identifier::Email(_) => return Err(tonic::Status::invalid_argument("http-01 makes no sense for email"))
        };
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
                        identifier: req.identifier,
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
                                identifier: req.identifier,
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
                                identifier: req.identifier,
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
                                identifier: req.identifier,
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
                                identifier: req.identifier,
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
                        identifier: req.identifier,
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
                        identifier: req.identifier,
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
                        identifier: req.identifier,
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
        let identifier = map_identifier(req.identifier.clone())?;

        if let Some(caa_err) = check_caa(self, &identifier, "dns-01", req.account_uri.as_deref()).await {
            return Ok(tonic::Response::new(caa_err));
        }

        let key_auth = format!("{}.{}", req.token, req.account_thumbprint);
        let key_auth_hash_bytes = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), key_auth.as_bytes()).unwrap().to_vec();
        let key_auth_hash = base64::encode_config(&key_auth_hash_bytes, base64::URL_SAFE_NO_PAD);
        let key_auth_hash_utf8 = key_auth_hash.as_bytes();

        let search_domain = match identifier {
            Identifier::Domain(domain, _) => format!("_acme-challenge.{}.", domain.trim_end_matches('.')),
            Identifier::IPAddr(_) => return Err(tonic::Status::invalid_argument("dns-01 must not be used for IP addresses")),
            Identifier::Email(_) => return Err(tonic::Status::invalid_argument("dns-01 makes no sense for email")),
        };
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
                            identifier: req.identifier,
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
                            identifier: req.identifier,
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
                            identifier: req.identifier,
                            instance: None,
                            sub_problems: vec![],
                        }]
                    }),
                }))
            }
        }
    }

    async fn validate_tlsalpn01(
        &self, request: tonic::Request<crate::cert_order::KeyValidationRequest>,
    ) -> Result<tonic::Response<crate::cert_order::ValidationResult>, tonic::Status> {
        let req = request.into_inner();
        let identifier = map_identifier(req.identifier.clone())?;

        if let Some(caa_err) = check_caa(self, &identifier, "tls-alpn-01", req.account_uri.as_deref()).await {
            return Ok(tonic::Response::new(caa_err));
        }

        let (connection_string, sni_string, ip_bytes) = match identifier {
            Identifier::Domain(domain, _) => (format!("{}:443", domain), domain.to_ascii_lowercase(), vec![]),
            Identifier::IPAddr(ip) => match ip {
                std::net::IpAddr::V4(ipv4) =>
                    (format!("{}:443", ipv4), trust_dns_resolver::Name::from(ipv4).to_ascii(), ipv4.octets().to_vec()),
                std::net::IpAddr::V6(ipv6) =>
                    (format!("[{}]:443", ipv6), trust_dns_resolver::Name::from(ipv6).to_ascii(), ipv6.octets().to_vec()),
            },
            Identifier::Email(_) => return Err(tonic::Status::invalid_argument("tls-alpn-01 makes no sense for email"))
        };
        let key_auth = format!("{}.{}", req.token, req.account_thumbprint);
        let key_auth_hash_bytes = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), key_auth.as_bytes()).unwrap().to_vec();

        let mut ssl_ctx_builder = match openssl::ssl::SslContext::builder(openssl::ssl::SslMethod::tls_client()) {
            Ok(b) => b,
            Err(err) => {
                error!("Failed to create SSL context builder: {}", err);
                return Err(tonic::Status::internal("failed to create SSL context"));
            }
        };
        ssl_ctx_builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
        ssl_ctx_builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2));
        ssl_ctx_builder.set_alpn_protos(b"\x0aacme-tls/1");
        let ssl_ctx = ssl_ctx_builder.build();

        let tcp_stream = match tokio::net::TcpStream::connect(connection_string).await {
            Ok(s) => s,
            Err(_) => return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                valid: false,
                error: Some(crate::cert_order::ErrorResponse {
                    errors: vec![crate::cert_order::Error {
                        error_type: crate::cert_order::ErrorType::ConnectionError.into(),
                        title: "Connection failed".to_string(),
                        detail: format!("Failed to open TCP connection to {}", connection_string),
                        status: 400,
                        identifier: req.identifier,
                        instance: None,
                        sub_problems: vec![],
                    }]
                }),
            }))
        };

        let mut ssl_session = match openssl::ssl::Ssl::new(&ssl_ctx) {
            Ok(b) => b,
            Err(err) => {
                error!("Failed to create SSL session: {}", err);
                return Err(tonic::Status::internal("failed to create SSL session"));
            }
        };
        ssl_session.set_hostname(&sni_string);
        let mut ssl_stream = match tokio_openssl::SslStream::new(ssl_session, tcp_stream) {
            Ok(b) => b,
            Err(err) => {
                error!("Failed to create SSL stream: {}", err);
                return Err(tonic::Status::internal("failed to create SSL stream"));
            }
        };

        match std::pin::Pin::new(&mut ssl_stream).connect().await {
            Ok(_) => {}
            Err(_) => return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                valid: false,
                error: Some(crate::cert_order::ErrorResponse {
                    errors: vec![crate::cert_order::Error {
                        error_type: crate::cert_order::ErrorType::ConnectionError.into(),
                        title: "Connection failed".to_string(),
                        detail: format!("Failed to negotiate TLS connection with {}", connection_string),
                        status: 400,
                        identifier: req.identifier,
                        instance: None,
                        sub_problems: vec![],
                    }]
                }),
            }))
        }

        let ssl_session_ref = ssl_stream.ssl();
        let acme_identifier_oid = openssl::asn1::Asn1Object::from_str("1.3.6.1.5.5.7.1.31").unwrap();
        let selected_alpn_protocol = ssl_session_ref.selected_alpn_protocol();
        let peer_certificate = match ssl_session_ref.peer_certificate() {
            Some(c) => c,
            None => return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                valid: false,
                error: Some(crate::cert_order::ErrorResponse {
                    errors: vec![crate::cert_order::Error {
                        error_type: crate::cert_order::ErrorType::IncorrectResponseError.into(),
                        title: "No certificate".to_string(),
                        detail: "Server did not return a self signed certificate".to_string(),
                        status: 400,
                        identifier: req.identifier,
                        instance: None,
                        sub_problems: vec![],
                    }]
                }),
            }))
        };

        if selected_alpn_protocol != Some(b"acme-tls/1") {
            return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                valid: false,
                error: Some(crate::cert_order::ErrorResponse {
                    errors: vec![crate::cert_order::Error {
                        error_type: crate::cert_order::ErrorType::IncorrectResponseError.into(),
                        title: "ALPN failed".to_string(),
                        detail: "Server did not negotiate \"acme-tls/1\" protocol".to_string(),
                        status: 400,
                        identifier: req.identifier,
                        instance: None,
                        sub_problems: vec![],
                    }]
                }),
            }));
        }

        let mut subject_alt_names = match peer_certificate.subject_alt_names() {
            Some(n) => n,
            None => return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                valid: false,
                error: Some(crate::cert_order::ErrorResponse {
                    errors: vec![crate::cert_order::Error {
                        error_type: crate::cert_order::ErrorType::IncorrectResponseError.into(),
                        title: "No SANs".to_string(),
                        detail: "Server did not return a SAN in its self signed certificate".to_string(),
                        status: 400,
                        identifier: req.identifier,
                        instance: None,
                        sub_problems: vec![],
                    }]
                }),
            }))
        };

        if subject_alt_names.len() != 1 {
            return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                valid: false,
                error: Some(crate::cert_order::ErrorResponse {
                    errors: vec![crate::cert_order::Error {
                        error_type: crate::cert_order::ErrorType::IncorrectResponseError.into(),
                        title: "Invalid SANs".to_string(),
                        detail: "Server did not return only one SAN in its self signed certificate".to_string(),
                        status: 400,
                        identifier: req.identifier,
                        instance: None,
                        sub_problems: vec![],
                    }]
                }),
            }));
        }
        let subject_alt_name = subject_alt_names.pop().unwrap();
        if ip_bytes.is_empty() {
            if let Some(domain_alt_name) = subject_alt_name.dnsname() {
                if domain_alt_name.to_ascii_lowercase() != sni_string {
                    return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                        valid: false,
                        error: Some(crate::cert_order::ErrorResponse {
                            errors: vec![crate::cert_order::Error {
                                error_type: crate::cert_order::ErrorType::IncorrectResponseError.into(),
                                title: "Invalid SANs".to_string(),
                                detail: format!("Server returned a SAN for '{}' its self signed certificate, expected '{}'", domain_alt_name, sni_string),
                                status: 400,
                                identifier: req.identifier,
                                instance: None,
                                sub_problems: vec![],
                            }]
                        }),
                    }));
                }
            } else {
                return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                    valid: false,
                    error: Some(crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::IncorrectResponseError.into(),
                            title: "Invalid SANs".to_string(),
                            detail: "Server did not return a domain SAN in its self signed certificate".to_string(),
                            status: 400,
                            identifier: req.identifier,
                            instance: None,
                            sub_problems: vec![],
                        }]
                    }),
                }));
            }
        } else {
            if let Some(ip_alt_name) = subject_alt_name.ipaddress() {
                if ip_alt_name != ip_bytes {
                    return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                        valid: false,
                        error: Some(crate::cert_order::ErrorResponse {
                            errors: vec![crate::cert_order::Error {
                                error_type: crate::cert_order::ErrorType::IncorrectResponseError.into(),
                                title: "Invalid SANs".to_string(),
                                detail: format!("Server returned a SAN for '{:X?}' its self signed certificate, expected '{:X?}'", ip_alt_name, ip_bytes),
                                status: 400,
                                identifier: req.identifier,
                                instance: None,
                                sub_problems: vec![],
                            }]
                        }),
                    }));
                }
            } else {
                return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                    valid: false,
                    error: Some(crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::IncorrectResponseError.into(),
                            title: "Invalid SANs".to_string(),
                            detail: "Server did not return an IP SAN in its self signed certificate".to_string(),
                            status: 400,
                            identifier: req.identifier,
                            instance: None,
                            sub_problems: vec![],
                        }]
                    }),
                }));
            }
        }

        let acme_id_data_bytes = unsafe {
            let extensions = openssl_sys::X509_get0_extensions(peer_certificate.as_ptr());
            let acme_id_idx = X509v3_get_ext_by_OBJ(extensions, acme_identifier_oid.as_ptr(), -1);
            if acme_id_idx < 0 {
                return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                    valid: false,
                    error: Some(crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::IncorrectResponseError.into(),
                            title: "No acmeIdentifier extensions".to_string(),
                            detail: "Server did not return a acmeIdentifier with the key authorization in its self signed certificate".to_string(),
                            status: 400,
                            identifier: req.identifier,
                            instance: None,
                            sub_problems: vec![],
                        }]
                    }),
                }));
            }

            let acme_id_ext = openssl_sys::X509v3_get_ext(extensions, acme_id_idx);

            if openssl_sys::X509_EXTENSION_get_critical(acme_id_ext) != 1 {
                return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                    valid: false,
                    error: Some(crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::IncorrectResponseError.into(),
                            title: "Invalid acmeIdentifier extension".to_string(),
                            detail: "Server returned a non critical acmeIdentifier extension in its self signed certificate".to_string(),
                            status: 400,
                            identifier: req.identifier,
                            instance: None,
                            sub_problems: vec![],
                        }]
                    }),
                }));
            }

            let acme_id_ext_data = openssl_sys::X509_EXTENSION_get_data(acme_id_ext);
            let acme_id_data = match crate::util::cvt_p(d2i_ASN1_OCTET_STRING(
                std::ptr::null_mut(),
                &mut openssl_sys::ASN1_STRING_get0_data(acme_id_ext_data as *const openssl_sys::ASN1_STRING),
                openssl_sys::ASN1_STRING_length(acme_id_ext_data as *const openssl_sys::ASN1_STRING) as libc::c_long,
            )) {
                Ok(d) => d,
                Err(_) => {
                    return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                        valid: false,
                        error: Some(crate::cert_order::ErrorResponse {
                            errors: vec![crate::cert_order::Error {
                                error_type: crate::cert_order::ErrorType::IncorrectResponseError.into(),
                                title: "Invalid acmeIdentifier extension".to_string(),
                                detail: "Server returned an un-parsable acmeIdentifier extension in its self signed certificate".to_string(),
                                status: 400,
                                identifier: req.identifier,
                                instance: None,
                                sub_problems: vec![],
                            }]
                        }),
                    }));
                }
            };
            std::slice::from_raw_parts(
                openssl_sys::ASN1_STRING_get0_data(acme_id_ext_data as *const openssl_sys::ASN1_STRING),
                openssl_sys::ASN1_STRING_length(acme_id_ext_data as *const openssl_sys::ASN1_STRING) as usize,
            )
        };

        Ok(tonic::Response::new(if acme_id_data_bytes == key_auth_hash_bytes {
            crate::cert_order::ValidationResult {
                valid: true,
                error: None,
            }
        } else {
            crate::cert_order::ValidationResult {
                valid: false,
                error: Some(crate::cert_order::ErrorResponse {
                    errors: vec![crate::cert_order::Error {
                        error_type: crate::cert_order::ErrorType::IncorrectResponseError.into(),
                        title: "Invalid acmeIdentifier extension".to_string(),
                        detail: format!("Server returned '{:X?}', expected '{:X?}'", acme_id_data_bytes, key_auth_hash_bytes),
                        status: 400,
                        identifier: req.identifier,
                        instance: None,
                        sub_problems: vec![],
                    }]
                }),
            }
        }))
    }
}

extern "C" {
    fn X509v3_get_ext_by_OBJ(
        x: *const openssl_sys::stack_st_X509_EXTENSION,
        obj: *const openssl_sys::ASN1_OBJECT,
        lastpos: libc::c_int,
    ) -> libc::c_int;

    fn d2i_ASN1_OCTET_STRING(
        a: *mut *mut openssl_sys::ASN1_OCTET_STRING,
        pp: *mut *const libc::c_uchar,
        length: libc::c_long,
    ) -> *mut openssl_sys::ASN1_OCTET_STRING;
}