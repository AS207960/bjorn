#[derive(Debug)]
pub enum CAAError {
    ServFail,
    UnsupportedCritical,
}

pub type CAAResult<T> = Result<T, CAAError>;

pub async fn find_caa_record(validator: &super::Validator, domain: &str) -> CAAResult<Vec<trust_dns_proto::rr::rdata::CAA>> {
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

    return Ok(vec![]);
}

struct CAAPolicy {
    issuers: Vec<String>,
    issuers_wild: Vec<String>,
    iodef_email: Option<String>,
    iodef_url: Option<String>,
}

fn parse_caa_policy(rdata: &[trust_dns_proto::rr::rdata::CAA]) -> CAAResult<CAAPolicy> {
    let mut policy = CAAPolicy {
        issuers: vec![],
        issuers_wild: vec![],
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
                    trust_dns_proto::rr::rdata::caa::Value::Issuer(issuer, _) => {
                        if let Some(issuer_id) = issuer {
                            policy.issuers.push(issuer_id.to_utf8());
                        }
                    }
                    _ => unreachable!()
                }
            }
            trust_dns_proto::rr::rdata::caa::Property::IssueWild => {
                match rr.value() {
                    trust_dns_proto::rr::rdata::caa::Value::Issuer(issuer, _) => {
                        if let Some(issuer_id) = issuer {
                            policy.issuers_wild.push(issuer_id.to_utf8());
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

pub async fn verify_caa_record(validator: &super::Validator, domain: &str) -> CAAResult<bool> {
    let is_wild = domain.starts_with("*.");
    let search_domain = if is_wild {
        &domain[2..]
    } else {
        domain
    };
    let records = find_caa_record(validator, search_domain).await?;
    let policy = parse_caa_policy(&records)?;

    if !is_wild {
        if policy.issuers.is_empty() {
            return Ok(true);
        };

        for issuer in &policy.issuers {
            if validator.caa_identities.contains(issuer) {
                return Ok(true);
            }
        }
        Ok(false)
    } else {
        if !policy.issuers_wild.is_empty() {
            for issuer in &policy.issuers_wild {
                if validator.caa_identities.contains(issuer) {
                    return Ok(true);
                }
            }
            Ok(false)
        } else {
            if policy.issuers.is_empty() {
                return Ok(true);
            };

            for issuer in &policy.issuers {
                if validator.caa_identities.contains(issuer) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}