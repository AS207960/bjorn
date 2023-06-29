#[derive(Debug)]
pub enum CAAError {
    ServFail,
    UnsupportedCritical(String),
    Other(String)
}

pub type CAAResult<T> = Result<T, CAAError>;

pub async fn find_hs_caa_record<S: torrosion::storage::Storage + Send + Sync + 'static>(
    validator: &super::Validator<S>, domain: &str, hs_priv_key: Option<&[u8; 32]>
) -> CAAResult<Vec<trust_dns_proto::rr::rdata::CAA>> {
    let client = match validator.tor_client {
        Some(ref c) => c,
        None => return Err(CAAError::ServFail)
    };

    if !client.ready().await {
        return Err(CAAError::Other("Unable to connect to the Tor network".to_string()));
    }

    let hs_address = match torrosion::hs::HSAddress::from_str(domain) {
        Ok(hs) => hs,
        Err(e) => {
            return Err(CAAError::Other(format!("Invalid HS address: {}", e)));
        }
    };

    let (
        descriptor, first_layer, blinded_key, hs_subcred
    ) = match hs_address.fetch_ds_first_layer(&client).await {
        Ok(v) => v,
        Err(e) => {
            return Err(CAAError::Other(format!("Failed to fetch HS descriptor: {}", e)));
        }
    };

    let is_caa_critical = first_layer.caa_critical;

    let second_layer = match torrosion::hs::HSAddress::get_ds_second_layer(
        descriptor, first_layer, hs_priv_key.copied(), &blinded_key, &hs_subcred
    ).await {
        Ok(v) => v,
        Err(e) => {
            info!("Failed to fetch second layer for {}: {}", domain, e);
            if is_caa_critical {
                return Err(CAAError::UnsupportedCritical("CAA is critical but failed to read second layer".to_string()));
            } else {
                return Ok(Vec::new());
            }
        }
    };

    Ok(second_layer.caa.into_iter().map(|caa| {
        let tag = trust_dns_proto::rr::rdata::caa::Property::from(caa.tag);

        let value =  match &tag {
            trust_dns_proto::rr::rdata::caa::Property::Issue | trust_dns_proto::rr::rdata::caa::Property::IssueWild => {
                let value = trust_dns_proto::rr::rdata::caa::read_issuer(&caa.value)
                    .map_err(|e| CAAError::Other(format!("Unable to parse issuer tag: {}", e)))?;
                trust_dns_proto::rr::rdata::caa::Value::Issuer(value.0, value.1)
            }
            trust_dns_proto::rr::rdata::caa::Property::Iodef => {
                let url = trust_dns_proto::rr::rdata::caa::read_iodef(&caa.value)
                    .map_err(|e| CAAError::Other(format!("Unable to parse iodef tag: {}", e)))?;
                trust_dns_proto::rr::rdata::caa::Value::Url(url)
            }
            trust_dns_proto::rr::rdata::caa::Property::Unknown(_) => trust_dns_proto::rr::rdata::caa::Value::Unknown(
                caa.value
            ),
        };

        Ok(trust_dns_proto::rr::rdata::CAA {
            issuer_critical: caa.flags & 0b1000_0000 != 0,
            tag,
            value,
        })
    }).collect::<Result<Vec<_>, _>>()?)
}

pub async fn find_caa_record<S: torrosion::storage::Storage + Send + Sync + 'static>(
    validator: &super::Validator<S>, identifier: &super::Identifier, hs_priv_key: Option<&[u8; 32]>
) -> CAAResult<Vec<trust_dns_proto::rr::rdata::CAA>> {
    match identifier {
        super::Identifier::Domain(domain, _) => {
            if domain.ends_with(".onion") {
                return find_hs_caa_record(validator, domain, hs_priv_key).await;
            } else {
                let mut domain = domain.trim_end_matches('.').split(".").collect::<Vec<_>>();
                while !domain.is_empty() {
                    let search_domain = format!("{}.", domain.join("."));
                    let result = match validator.dns_resolver.lookup(
                        search_domain, trust_dns_proto::rr::record_type::RecordType::CAA,
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
        }
        super::Identifier::IPAddr(ip_addr) => {
            let ip_addr_domain = trust_dns_resolver::Name::from(ip_addr.to_owned());
            return match validator.dns_resolver.lookup(
                ip_addr_domain, trust_dns_proto::rr::record_type::RecordType::CAA,
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

#[derive(Debug)]
struct CAAIssuer {
    identifier: String,
    account_uri: Option<String>,
    validation_methods: Option<Vec<String>>,
}

#[derive(Debug)]
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

#[derive(Debug)]
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
                            o => {
                                if rr.issuer_critical() {
                                    return Err(CAAError::UnsupportedCritical(format!("unsupported iodef URI scheme: {}", o)));
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
            trust_dns_proto::rr::rdata::caa::Property::Unknown(o) => {
                if rr.issuer_critical() {
                    return Err(CAAError::UnsupportedCritical(format!("unsupported CAA tag: {}", o)));
                }
            }
        }
    }

    Ok(policy)
}

pub async fn verify_caa_record<S: torrosion::storage::Storage + Send + Sync + 'static>(
    validator: &super::Validator<S>, identifier: &super::Identifier, validation_method: &str,
    account_uri: Option<&str>, hs_priv_key: Option<&[u8; 32]>
) -> CAAResult<bool> {
    let is_wild = match identifier {
        super::Identifier::Domain(_, is_wild) => *is_wild,
        _ => false
    };

    if let super::Identifier::Email(_) = identifier {
        return Ok(true);
    }

    let records = find_caa_record(validator, identifier, hs_priv_key).await?;
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