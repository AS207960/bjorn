#[derive(Debug)]
pub enum CAAError {
    ServFail,
    UnsupportedCritical,
}

pub type CAAResult<T> = Result<T, CAAError>;

pub async fn find_caa_record(validator: &super::Validator, identifier: &super::Identifier) -> CAAResult<Vec<trust_dns_proto::rr::rdata::CAA>> {
    match identifier {
        super::Identifier::Domain(domain, _) => {
            let mut domain = domain.trim_end_matches('.').split(".").collect::<Vec<_>>();
            while !domain.is_empty() {
                let search_domain = format!("{}.", domain.join("."));
                let result = match validator.dns_resolver.lookup(
                    search_domain, trust_dns_proto::rr::record_type::RecordType::CAA,
                    trust_dns_proto::xfer::dns_request::DnsRequestOptions {
                        expects_multiple_responses: false,
                        use_edns: true,
                    },
                ).await {
                    Ok(r) => Some(
                        r.iter()
                            .filter_map(|r| match r {
                                trust_dns_proto::rr::record_data::RData::CAA(d) => Some(d),
                                _ => None
                            })
                            .map(|r| r.to_owned())
                            .collect()
                    ),
                    Err(err) => match err.kind() {
                        trust_dns_resolver::error::ResolveErrorKind::NoRecordsFound { .. } => None,
                        _ => return Err(CAAError::ServFail)
                    }
                };

                if let Some(res) = result {
                    return Ok(res);
                } else {
                    domain.remove(0);
                }
            }
        }
        super::Identifier::IPAddr(ip_addr) => {
            let ip_addr_domain = trust_dns_resolver::Name::from(ip_addr.to_owned());
            return match validator.dns_resolver.lookup(
                ip_addr_domain, trust_dns_proto::rr::record_type::RecordType::CAA,
                trust_dns_proto::xfer::dns_request::DnsRequestOptions {
                    expects_multiple_responses: false,
                    use_edns: true,
                },
            ).await {
                Ok(r) => Ok(
                    r.iter()
                        .filter_map(|r| match r {
                            trust_dns_proto::rr::record_data::RData::CAA(d) => Some(d),
                            _ => None
                        })
                        .map(|r| r.to_owned())
                        .collect()
                ),
                Err(err) => match err.kind() {
                    trust_dns_resolver::error::ResolveErrorKind::NoRecordsFound { .. } => Ok(vec![]),
                    _ => Err(CAAError::ServFail)
                }
            };
        },
        _ => unimplemented!()
    }

    return Ok(vec![]);
}

struct CAAIssuer {
    identifier: String,
    account_uri: Option<String>,
    validation_methods: Option<Vec<String>>,
}

struct CAAIssuers(Vec<CAAIssuer>);

impl CAAIssuers {
    fn is_authorized(&self, issuer_id: &str, account_uri: Option<&str>, validation_method: &str) -> bool {
        if self.0.is_empty() {
            return true;
        }

        for issuer in &self.0 {
            if issuer.identifier == issuer_id {
                if let Some(caa_account_uri) = &issuer.account_uri {
                    if let Some(match_account_uri) = account_uri {
                        if caa_account_uri != match_account_uri {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }

                if let Some(caa_validation_methods) = &issuer.validation_methods {
                    if !caa_validation_methods.iter().any(|x| x == validation_method) {
                        continue;
                    }
                }

                return true;
            }
        }

        return false;
    }

    fn push(&mut self, elm: CAAIssuer) {
        self.0.push(elm)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

struct CAAPolicy {
    issuers: CAAIssuers,
    issuers_wild: CAAIssuers,
    iodef_email: Option<String>,
    iodef_url: Option<String>,
}

fn parse_caa_issuer(name: &trust_dns_proto::rr::domain::Name, params: &Vec<trust_dns_proto::rr::rdata::caa::KeyValue>) -> CAAResult<CAAIssuer> {
    let account_uris = params.iter().filter(|kv| kv.key() == "accounturi").collect::<Vec<_>>();
    let validation_methods = params.iter().filter(|kv| kv.key() == "validationmethods").collect::<Vec<_>>();

    if account_uris.len() > 1 {
        return Err(CAAError::ServFail);
    }
    if validation_methods.len() > 1 {
        return Err(CAAError::ServFail);
    }

    Ok(CAAIssuer {
        identifier: name.to_utf8(),
        account_uri: if account_uris.is_empty() {
            None
        } else {
            Some(account_uris[0].value().to_string())
        },
        validation_methods: if validation_methods.is_empty() {
            None
        } else {
            Some(validation_methods[0].value().split(",").map(|v| v.trim().to_string()).collect())
        },
    })
}

fn parse_caa_policy(rdata: &[trust_dns_proto::rr::rdata::CAA]) -> CAAResult<CAAPolicy> {
    let mut policy = CAAPolicy {
        issuers: CAAIssuers(vec![]),
        issuers_wild: CAAIssuers(vec![]),
        iodef_email: None,
        iodef_url: None,
    };

    for rr in rdata {
        match rr.tag() {
            trust_dns_proto::rr::rdata::caa::Property::Iodef => {
                match rr.value() {
                    trust_dns_proto::rr::rdata::caa::Value::Url(url) => {
                        match url.scheme() {
                            "mailto" => {
                                policy.iodef_email = Some(url.path().to_string())
                            }
                            "http" | "https" => {
                                policy.iodef_url = Some(url.as_str().to_string())
                            }
                            _ => {
                                if rr.issuer_critical() {
                                    return Err(CAAError::UnsupportedCritical);
                                }
                            }
                        }
                        if url.scheme() == "mailto" {}
                    }
                    _ => unreachable!()
                }
            }
            trust_dns_proto::rr::rdata::caa::Property::Issue => {
                match rr.value() {
                    trust_dns_proto::rr::rdata::caa::Value::Issuer(issuer, params) => {
                        if let Some(issuer_id) = issuer {
                            policy.issuers.push(parse_caa_issuer(issuer_id, params)?);
                        }
                    }
                    _ => unreachable!()
                }
            }
            trust_dns_proto::rr::rdata::caa::Property::IssueWild => {
                match rr.value() {
                    trust_dns_proto::rr::rdata::caa::Value::Issuer(issuer, params) => {
                        if let Some(issuer_id) = issuer {
                            policy.issuers.push(parse_caa_issuer(issuer_id, params)?);
                        }
                    }
                    _ => unreachable!()
                }
            }
            _ =>
                if rr.issuer_critical() {
                    return Err(CAAError::UnsupportedCritical);
                }
        }
    }

    Ok(policy)
}

pub async fn verify_caa_record(
    validator: &super::Validator, identifier: &super::Identifier, validation_method: &str,
    account_uri: Option<&str>
) -> CAAResult<bool> {
    let is_wild = match identifier {
        super::Identifier::Domain(_, is_wild) => *is_wild,
        _ => false
    };

    if let super::Identifier::Email(_) = identifier {
        return Ok(true);
    }

    let records = find_caa_record(validator, identifier).await?;
    let policy = parse_caa_policy(&records)?;

    if !is_wild {
        for caa_identity in &validator.caa_identities {
            if policy.issuers.is_authorized(caa_identity, account_uri, validation_method) {
                return Ok(true);
            }
        }
        Ok(false)
    } else {
        if !policy.issuers_wild.is_empty() {
            for caa_identity in &validator.caa_identities {
                if policy.issuers_wild.is_authorized(caa_identity, account_uri, validation_method) {
                    return Ok(true);
                }
            }
            Ok(false)
        } else {
            for caa_identity in &validator.caa_identities {
                if policy.issuers.is_authorized(caa_identity, account_uri, validation_method) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}