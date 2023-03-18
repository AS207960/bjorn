use foreign_types::ForeignType;
use std::convert::TryFrom;
use base64::prelude::*;

pub mod caa;

#[derive(Debug)]
pub enum Identifier {
    Domain(String, bool),
    IPAddr(std::net::IpAddr),
    Email(String),
}

#[derive(Debug)]
pub struct Validator<S: torrosion::storage::Storage> {
    dns_resolver: trust_dns_resolver::TokioAsyncResolver,
    reqwest_client: reqwest::Client,
    tor_client: Option<torrosion::Client<S>>,
    caa_identities: Vec<String>,
}

impl<S: torrosion::storage::Storage + Send + Sync + 'static> Validator<S> {
    pub async fn new(caa_identities: Vec<String>, storage: Option<S>) -> Self {
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

        let tor_client = if let Some(storage) = storage {
            let mut c = torrosion::Client::new(storage);
            c.run().await;

            Some(c)
        } else {
            None
        };

        Validator {
            dns_resolver: resolver,
            reqwest_client: client,
            tor_client,
            caa_identities,
        }
    }
}

async fn check_caa<S: torrosion::storage::Storage + Send + Sync + 'static>(
    validator: &Validator<S>, identifier: &Identifier, validation_method: &str,
    account_uri: Option<&str>, hs_priv_key: Option<&[u8; 32]>
) -> Option<crate::cert_order::ValidationResult> {
    let caa_res = match caa::verify_caa_record(
        validator, identifier, validation_method, account_uri, hs_priv_key
    ).await {
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
            },
            _ => return Err(tonic::Status::invalid_argument("Invalid identifier type specified")),
        })
    } else {
        Err(tonic::Status::invalid_argument("Identifier must be specified"))
    }
}

trait RW: tokio::io::AsyncRead + tokio::io::AsyncWrite {}
impl<T> RW for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite {}

#[tonic::async_trait]
impl<S: torrosion::storage::Storage + Send + Sync + 'static> crate::cert_order::validator_server::Validator for Validator<S> {
    async fn validate_http01(
        &self, request: tonic::Request<crate::cert_order::KeyValidationRequest>,
    ) -> Result<tonic::Response<crate::cert_order::ValidationResult>, tonic::Status> {
        let req = request.into_inner();
        let identifier = map_identifier(req.identifier.clone())?;

        let hs_priv_key = if req.hs_private_key.len() == 0 {
            None
        } else if req.hs_private_key.len() == 32 {
            Some(std::convert::TryInto::<[u8; 32]>::try_into(req.hs_private_key.as_slice()).unwrap())
        } else {
            return Err(tonic::Status::invalid_argument("hs_priv_key must be 32 bytes long"));
        };

        if let Some(caa_err) = check_caa(
            self, &identifier, "http-01",
            req.account_uri.as_deref(), hs_priv_key.as_ref(),
        ).await {
            return Ok(tonic::Response::new(caa_err));
        }

        let (test_uri, is_tor) = match identifier {
            Identifier::Domain(domain, _) => (
                format!("http://{}:80/.well-known/acme-challenge/{}", domain, req.token),
                domain.ends_with(".onion")
            ),
            Identifier::IPAddr(ip) => (match ip {
                std::net::IpAddr::V4(ipv4) => format!("http://{}:80/.well-known/acme-challenge/{}", ipv4, req.token),
                std::net::IpAddr::V6(ipv6) => format!("http://[{}]:80/.well-known/acme-challenge/{}", ipv6, req.token),
            }, false),
            Identifier::Email(_) => return Err(tonic::Status::invalid_argument("http-01 makes no sense for email"))
        };
        let key_auth = format!("{}.{}", req.token, req.account_thumbprint);

        let uri_error = crate::cert_order::ErrorResponse {
            errors: vec![crate::cert_order::Error {
                error_type: crate::cert_order::ErrorType::ConnectionError.into(),
                title: "Validation failed".to_string(),
                detail: "Connection refused".to_string(),
                status: 400,
                identifier: req.identifier.clone(),
                instance: None,
                sub_problems: vec![],
            }]
        };
        let timeout_error = crate::cert_order::ErrorResponse {
            errors: vec![crate::cert_order::Error {
                error_type: crate::cert_order::ErrorType::ConnectionError.into(),
                title: "Validation failed".to_string(),
                detail: "Connection timed out".to_string(),
                status: 400,
                identifier: req.identifier.clone(),
                instance: None,
                sub_problems: vec![],
            }]
        };
        let connect_error = crate::cert_order::ErrorResponse {
            errors: vec![crate::cert_order::Error {
                error_type: crate::cert_order::ErrorType::ConnectionError.into(),
                title: "Validation failed".to_string(),
                detail: "Connection refused".to_string(),
                status: 400,
                identifier: req.identifier.clone(),
                instance: None,
                sub_problems: vec![],
            }]
        };
        let other_error = crate::cert_order::ErrorResponse {
            errors: vec![crate::cert_order::Error {
                error_type: crate::cert_order::ErrorType::ConnectionError.into(),
                title: "Validation failed".to_string(),
                detail: "Unknown request error".to_string(),
                status: 400,
                identifier: req.identifier.clone(),
                instance: None,
                sub_problems: vec![],
            }]
        };
        let charset_error = crate::cert_order::ErrorResponse {
            errors: vec![crate::cert_order::Error {
                error_type: crate::cert_order::ErrorType::IncorrectResponseError.into(),
                title: "Validation failed".to_string(),
                detail: "Text charset error".to_string(),
                status: 400,
                identifier: req.identifier.clone(),
                instance: None,
                sub_problems: vec![],
            }]
        };

        let (status, resp_txt) = if is_tor {
            let client = match self.tor_client {
                Some(ref c) => c.clone(),
                None => return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                    valid: false,
                    error: Some(crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::UnsupportedIdentifierError.into(),
                            title: "Validation failed".to_string(),
                            detail: "Hidden services are not supported".to_string(),
                            status: 400,
                            identifier: req.identifier,
                            instance: None,
                            sub_problems: vec![],
                        }]
                    }),
                }))
            };

            let test_uri = match hyper::Uri::try_from(&test_uri) {
                Ok(u) => u,
                Err(_) => return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                    valid: false,
                    error: Some(uri_error),
                }))
            };

            let hs_client = torrosion::hs::http::new_hs_client(client, hs_priv_key);

            let resp = match hs_client.get(test_uri).await {
                Ok(u) => u,
                Err(err) => {
                    if err.is_timeout() {
                        return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                            valid: false,
                            error: Some(timeout_error),
                        }));
                    } else if err.is_connect() {
                        return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                            valid: false,
                            error: Some(connect_error),
                        }));
                    } else {
                        return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                            valid: false,
                            error: Some(other_error),
                        }));
                    }
                }
            };

            (resp.status(), match hyper::body::to_bytes(resp.into_body()).await {
                Ok(b) => match String::from_utf8(b.to_vec()) {
                    Ok(s) => s,
                    Err(_) => return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                        valid: false,
                        error: Some(charset_error),
                    }))
                },
                Err(_) => return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                    valid: false,
                    error: Some(other_error),
                }))
            })
        } else {
            let test_uri = match reqwest::Url::parse(&test_uri) {
                Ok(u) => u,
                Err(_) => return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                    valid: false,
                    error: Some(uri_error),
                }))
            };
            let resp = match self.reqwest_client.get(test_uri).send().await {
                Ok(u) => u,
                Err(err) => {
                    if err.is_timeout() {
                        return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                            valid: false,
                            error: Some(timeout_error),
                        }));
                    } else if err.is_connect() {
                        return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                            valid: false,
                            error: Some(connect_error),
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
                            error: Some(other_error),
                        }));
                    }
                }
            };

            (resp.status(), match resp.text().await {
                Ok(t) => t,
                Err(_) => return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                    valid: false,
                    error: Some(charset_error),
                }))
            })
        };

        if !status.is_success() {
            return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                valid: false,
                error: Some(crate::cert_order::ErrorResponse {
                    errors: vec![crate::cert_order::Error {
                        error_type: crate::cert_order::ErrorType::IncorrectResponseError.into(),
                        title: "Validation failed".to_string(),
                        detail: format!("HTTP {} received", status.as_str()),
                        status: 400,
                        identifier: req.identifier,
                        instance: None,
                        sub_problems: vec![],
                    }]
                }),
            }));
        }

        if resp_txt.trim() == key_auth {
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

        if let Some(caa_err) = check_caa(
            self, &identifier, "dns-01",
            req.account_uri.as_deref(), None
        ).await {
            return Ok(tonic::Response::new(caa_err));
        }

        let key_auth = format!("{}.{}", req.token, req.account_thumbprint);
        let key_auth_hash_bytes = openssl::hash::hash(openssl::hash::MessageDigest::sha256(), key_auth.as_bytes()).unwrap().to_vec();
        let key_auth_hash = BASE64_URL_SAFE_NO_PAD.encode(&key_auth_hash_bytes);
        let key_auth_hash_utf8 = key_auth_hash.as_bytes();

        let search_domain = match identifier {
            Identifier::Domain(domain, _) => {
                if domain.ends_with(".onion") {
                    return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                        valid: false,
                        error: Some(crate::cert_order::ErrorResponse {
                            errors: vec![crate::cert_order::Error {
                                error_type: crate::cert_order::ErrorType::UnsupportedIdentifierError.into(),
                                title: "Validation failed".to_string(),
                                detail: "dns-01 is not supported for .onion domains".to_string(),
                                status: 400,
                                identifier: req.identifier,
                                instance: None,
                                sub_problems: vec![],
                            }]
                        }),
                    }))
                }
                format!("_acme-challenge.{}.", domain.trim_end_matches('.'))
            },
            Identifier::IPAddr(_) => return Err(tonic::Status::invalid_argument("dns-01 must not be used for IP addresses")),
            Identifier::Email(_) => return Err(tonic::Status::invalid_argument("dns-01 makes no sense for email")),
        };
        match self.dns_resolver.txt_lookup(search_domain.clone()).await {
            Ok(r) => {
                for record in r.iter(){
                    if let Some(data) = record.txt_data().iter().next().as_deref() {
                        if data.as_ref() == key_auth_hash_utf8 {
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

        let hs_priv_key = if req.hs_private_key.len() == 0 {
            None
        } else if req.hs_private_key.len() == 32 {
            Some(std::convert::TryInto::<[u8; 32]>::try_into(req.hs_private_key.as_slice()).unwrap())
        } else {
            return Err(tonic::Status::invalid_argument("hs_priv_key must be 32 bytes long"));
        };

        if let Some(caa_err) = check_caa(
            self, &identifier, "tls-alpn-01",
            req.account_uri.as_deref(), hs_priv_key.as_ref()
        ).await {
            return Ok(tonic::Response::new(caa_err));
        }

        let (connection_string, sni_string, ip_bytes, is_tor) = match identifier {
            Identifier::Domain(domain, _) => (
                format!("{}:443", domain), domain.to_ascii_lowercase(), vec![], domain.ends_with(".onion")
            ),
            Identifier::IPAddr(ip) => match ip {
                std::net::IpAddr::V4(ipv4) =>
                    (format!("{}:443", ipv4), trust_dns_resolver::Name::from(ipv4).to_ascii(), ipv4.octets().to_vec(), false),
                std::net::IpAddr::V6(ipv6) =>
                    (format!("[{}]:443", ipv6), trust_dns_resolver::Name::from(ipv6).to_ascii(), ipv6.octets().to_vec(), false),
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
        ssl_ctx_builder.set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2)).unwrap();
        ssl_ctx_builder.set_alpn_protos(b"\x0aacme-tls/1").unwrap();
        let ssl_ctx = ssl_ctx_builder.build();

        let tcp_stream: std::pin::Pin<Box<dyn RW + Send>> = if is_tor {
            let client = match self.tor_client {
                Some(ref c) => c,
                None => return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                    valid: false,
                    error: Some(crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::UnsupportedIdentifierError.into(),
                            title: "Validation failed".to_string(),
                            detail: "Hidden services are not supported".to_string(),
                            status: 400,
                            identifier: req.identifier,
                            instance: None,
                            sub_problems: vec![],
                        }]
                    }),
                }))
            };

            let hs_address = match torrosion::hs::HSAddress::from_str(&sni_string) {
                Ok(hs) => hs,
                Err(_) => return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                    valid: false,
                    error: Some(crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::ConnectionError.into(),
                            title: "Connection failed".to_string(),
                            detail: "Malformed HS address".to_string(),
                            status: 400,
                            identifier: req.identifier,
                            instance: None,
                            sub_problems: vec![],
                        }]
                    }),
                }))
            };

            let (ds, subcred) = match hs_address.fetch_ds(&client, hs_priv_key).await {
                Ok(v) => v,
                Err(_) => return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                    valid: false,
                    error: Some(crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::ConnectionError.into(),
                            title: "Connection failed".to_string(),
                            detail: "Failed to get HS descriptor".to_string(),
                            status: 400,
                            identifier: req.identifier,
                            instance: None,
                            sub_problems: vec![],
                        }]
                    }),
                }))
            };
            let hs_circ = match torrosion::hs::con::connect(&client, &ds, &subcred).await {
                Ok(v) => v,
                Err(_) => return Ok(tonic::Response::new(crate::cert_order::ValidationResult {
                    valid: false,
                    error: Some(crate::cert_order::ErrorResponse {
                        errors: vec![crate::cert_order::Error {
                            error_type: crate::cert_order::ErrorType::ConnectionError.into(),
                            title: "Connection failed".to_string(),
                            detail: "Failed to connect to HS".to_string(),
                            status: 400,
                            identifier: req.identifier,
                            instance: None,
                            sub_problems: vec![],
                        }]
                    }),
                }))
            };

            Box::pin(hs_circ.relay_begin(&connection_string, None).await?)
        } else {
            match tokio::net::TcpStream::connect(connection_string.clone()).await {
                Ok(s) => Box::pin(s),
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
            }
        };

        let mut ssl_session = match openssl::ssl::Ssl::new(&ssl_ctx) {
            Ok(b) => b,
            Err(err) => {
                error!("Failed to create SSL session: {}", err);
                return Err(tonic::Status::internal("failed to create SSL session"));
            }
        };
        ssl_session.set_hostname(&sni_string).unwrap();
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
                        error_type: crate::cert_order::ErrorType::TlsError.into(),
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
                        error_type: crate::cert_order::ErrorType::TlsError.into(),
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
                        error_type: crate::cert_order::ErrorType::TlsError.into(),
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
                openssl_sys::ASN1_STRING_get0_data(acme_id_data as *const openssl_sys::ASN1_STRING),
                openssl_sys::ASN1_STRING_length(acme_id_data as *const openssl_sys::ASN1_STRING) as usize,
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