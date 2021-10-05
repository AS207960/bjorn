# Björn - The AS207960 ACME server

<img src="https://as207960.net/assets/img/logo.svg" alt="" width="150">

Björn is not a full CA upon to itself, but contains many of the building 
blocks of a complete ACME CA.

## Components

Björn consists of three primary components, and includes an example CA
backend written in Django. This CA backend **MUST NOT** be used in a
production environment. It is purely for demonstration purposes.

Communication between internal components happens over gRPC.

The components are:
* Björn - The ACME front end and the largest component. It handles account
  registration, and acts as a proxy between the CA backend and ACME clients.
* Benny - The OCSP responder. It receives and responds to OCSP requests 
from TLS clients, routing to whichever backend handles the signing 
  certificate used in the end entity certificate.
* Frida - The ACME validator. It handles CAA checking, and verification of
ACME `http-01` and `dns-01` challenges.
  
A basic diagram of their inter-working is as follows;

```text
                          End user <-> CA boundary 
                                    |       *------------*
                                    |       | PostgreSQL | <--------------
                                    |       *------------*                \ 
                                    |                                      |
*-------------*                     |                                  *-------*
| ACME Client | ---ACME over HTTPS--|--                            --> | Björn | ------
*-------------*                     |  \    *-----------------*   /    *-------*       \   
                                    |   --> | TLS terminating | --                 gRPC |
                                    |   --> |  ingress proxy  | --                      |
*------------*                      |  /    *-----------------*   \    *-------*        |
| TLS Client | --OCSP over HTTP(S)--|--                            --> | Benny | ----   |
*------------*                      |                                  *-------*     \  |
                                    |                                            gRPC | |
                                    |                                                /  |
*-------------*    |  http-01  |    |      *-------*               *------------* <--   |
| User server | <--|   dns-01  |----|----- | Frida | <----gRPC---- | Backend CA |      /
*-------------*    |tls-alpn-01|    |      *-------*               *------------* <----
```

## Repositry layout

| Directory              | Contents                                        |
|------------------------|-------------------------------------------------|
| `migrations`           | SQL database migrations                         |
| `proto`                | gRPC definitions for inter-working              |
| `python-ca`            | Example CA backend **DO NOT USE IN PRODUCTION** |
| `src`                  | Common Rust source code                         |
| `src/bin/acme.rs`      | The Björn binary                                |
| `src/acme`             | Björn specific utilities                        |
| `src/bin/ocsp.rs`      | The Benny binary                                |
| `src/ocsp`             | Benny specific utilities                        |
| `src/bin/validator.rs` | The Frida binary                                |
| `src/validator`        | Frida specific utilities                        |
| `templates`            | Björn HTML templates                            |

## Implemented RFCs

* [RFC 6960](https://datatracker.ietf.org/doc/html/rfc6960) - Online Certificate Status Protocol - OCSP
* [RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638) - JSON Web Key (JWK) Thumbprint
* [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555) - Automatic Certificate Management Environment (ACME)
* [RFC 8657](https://datatracker.ietf.org/doc/html/rfc8657) - Certification Authority Authorization (CAA) Record Extensions for Account URI and Automatic Certificate Management Environment (ACME) Method Binding
* [RFC 8659](https://datatracker.ietf.org/doc/html/rfc8659) - DNS Certification Authority Authorization (CAA) Resource Record
* [RFC 8737](https://datatracker.ietf.org/doc/html/rfc8737) - Automated Certificate Management Environment (ACME) TLS Application-Layer Protocol Negotiation (ALPN) Challenge Extension
* [RFC 8738](https://datatracker.ietf.org/doc/html/rfc8738) - Automated Certificate Management Environment (ACME) IP Identifier Validation Extension
* [RFC 8954](https://datatracker.ietf.org/doc/html/rfc8954) - Online Certificate Status Protocol (OCSP) Nonce Extension
* [draft-shoemaker-caa-ip-01](https://datatracker.ietf.org/doc/html/draft-shoemaker-caa-ip-01) - Certification Authority Authorization (CAA) Validation for IP Addresses

Note: CAA iodef is not yet supported

## Setup

All components are configured using the [Rocket config system](https://rocket.rs/v0.4/guide/configuration/).
Please see the linked Rocket docs for details on configuring listening ports
and addresses.

### Björn

Björn should be setup behind a HTTP proxy that implements rate limiting and
TLS termination.

#### Example `Rocket.toml`
```toml
[development]
external_uri = "http://localhost:8000"
tos_uri = "https://as207960.net/assets/docs/AS207960_T_C_s.pdf"
tos_agreed_to_after = "2021-09-29T00:00:00Z"
website_uri = "https://as207960.net"
caa_identities = ["bjorn.as207960.net"]
ca_grpc_uri = "http://[::1]:50051"
template_dir = "templates/"

[[development.acme_issuers]]
cert_id = "a"
issuer_cert_file = "python-ca/ca-certs/intermediate-crt.pem"

[development.databases]
db = { url = "postgres://postgres@localhost/bjorn" }
```

#### Configuration explanation.

##### `external_uri`
The URL base at which the ACME server can be reached by external end users,
including protocol and port.

##### `tos_uri`
The URL of the Terms and Conditions page of the ACME server. End users should
be presented with this page by their ACME client to agree to it before proceeding.

##### `tos_agreed_to_after`
An ISO8601 timestamp for which accounts that agreed to tho terms of service 
before which will be required to agree again before continuing with their request.
Useful if the ToS have been updated and users need to be aware of a new/updated clause.

##### `website_uri`
The homepage of the entity running the ACME server.

##### `caa_identities`
Which CAA issuers identities are recognised by the ACME server as allowing
issuance by this CA.

##### `ca_grpc_uri`
The gRPC URL of the CA backend. It should implement the protocol as described
further down.

##### `template_dir`
A directory path in which the HTML templates for the index page (for when
the ACME server is accessed without using an ACME client), and updated 
ToS agreement pages are stored. 

##### `acme_issuers`
A list of issuing certificates for which this server can handle revocation requests.

##### `cert_id`
The ID used by backend CA to identify the issuing certificate.

##### `issuer_cert_file`
The path of the X.509 public key file (PEM encoded) for the issuing certificate.

##### `db.url`
The connection URL of the PostgreSQL database used for storing ACME accounts.

### Benny

Benny should be setup behind a caching HTTP proxy that `Cache-Control`, 
`Expires`, `ETag` etc. HTTP headers set by Benny.

#### Example `Rocket.toml`
```toml
[[development.ocsp_issuers]]
cert_id = "issuer-1"
issuer_cert_file = "python-ca/ca-certs/intermediate-crt.pem"
signer_pkcs12_file = "ocsp-signer.p12"
grpc_uri = "http://[::1]:50051"
```

#### Configuration explanation.

##### `ocsp_issuers`
A list of issuing certificates for which this responder is authoritative.

##### `cert_id`
The ID used by backend CA to identify the issuing certificate.

##### `issuer_cert_file`
The path of the X.509 public key file (PEM encoded) for the issuing certificate.

##### `signer_pkcs12_file`
The PKCS.12 encoded file containing the private key used to sign OCSP
responses, its associated public key, and any certificates needed to chain
up to the root. The signing certificate should either be the issuer certificate
directly (not recommended), or a certificate issued by the issuer certificate
with the `id-kp-OCSPSigning` extended key usage attribute.

##### `grpc_uri`
The gRPC URL of the CA backend for this issuer.
It should implement the protocol as described further down.

### Frida

Frida should be setup on a machine with a local DNSSEC validating resolver
configured. DNSSEC validation is vital to the integrity of CAA.

#### Example `Rocket.toml`
```toml
[development]
caa_identities = ["bjorn.as207960.net"]
```

#### Configuration explanation.

##### `caa_identities`
Which CAA issuers identities are recognised by the ACME server as allowing
issuance by this CA (ideally the same as configured on Björn).

## Inter-working protocol description

### General

#### Errors

Björn understands basic gRPC errors such as not found and internal server errors,
and will convert them into to suitable errors to be transferred to the client.

For greater control and specificity the backend CA can also construct ACME 
errors directly to be sent to the client. The `Error` type is based on the
JSON errors returned in ACME.

```protobuf
enum ErrorType {
  ...
}

message Error {
  ErrorType error_type = 1;
  string title = 2;
  uint32 status = 3;
  string detail = 4;
  google.protobuf.StringValue instance = 5;
  repeated Error sub_problems = 6;
  Identifier identifier = 7;
}
```

The `error_type` field contains an error as defined in [RFC 8555 § 6.7](https://datatracker.ietf.org/doc/html/rfc8555#section-6.7).
The `title` field should contain a general synopsys of the fault.
The `status` field should contain a suitable HTTP error code for the fault.
The `detail` field should contain a detailed description of the fault.
The `instance` field should only be used when the `userActionRequired` field
is returned, and should contain a URL to direct the end user to.
The `sub_problems` field can be used to break a fault down into further
smaller faults.
The `identifier` field can be used to identify to which identifier in the 
order this fault relates.

### Björn

#### `ValidateEAB`

This function is used to check the external account binding specified by
the client is valid. The backend should lookup the HMAC key as specified
by the `kid` field and check that the `signature` field over the `signed_data`
field is valid using the specified `signature_method`.

If the HMAC key does not exist, or the signature is not valid the backend must
return a result with a `valid` field of `false`, else it must return `true`.

#### `CreateOrder`

The backend must check the requested identifiers are not prohibited by policy,
and that the `not_before` and `not_after` are within server policy.

The `account_id` field contains the ID of the ACME account as generated by the
frontend, and the `eab_id` field contains the EAB `kid` if a previous
`ValidateEAB` succeeded.

The backend must either respond with an `Order` in the pending state, or 
an error if it is not willing to create the order exactly as requested.

#### `CreateAuthorization`

The backend must check the requested identifier is not prohibited by policy,
and that it is willing to allow pre-authorizations.

The `account_id` field contains the ID of the ACME account as generated by the
frontend, and the `eab_id` field contains the EAB `kid` if a previous
`ValidateEAB` succeeded.

The backend must either respond with an `Authorization` in the pending state,
or an error if it is not willing to create the order exactly as requested.

#### `FinalizeOrder`

The backend must lookup an order by the ID it generated itself and returned
in a previous order object. The backend need not check permissions, as
the frontend has already completed this check. The standard gRPC `NOT_FOUND`
status code should be used if the order specified does not exist.

The backend must check that the order is in a state in which it is willing
to issue a certificate (i.e. valid), and error otherwise.

The `csr` field contains the DER encoded CSR. The backend must check that
the CSR is valid by policy. If it is it must start issuance of the certificate,
which should happen in the background.

The backend must either respond with an `Order` in the processing state, or 
an error if it is not willing to process the order exactly as requested.

#### `DeactivateAuthorization`

The backend must lookup an authorization by the ID it generated itself 
and returned in a previous authorization object. The backend need not 
check permissions, as the frontend has already completed this check.
The standard gRPC `NOT_FOUND` status code should be used if the
authorization specified does not exist.

If the authorization is in a usable state (i.e. not deactivated, expired,
nor revoked), the backend must mark the authorization as deactivated and make
it unusable for future orders.

#### `CompleteChallenge`

The backend must lookup a challenge by the ID and authorization ID it
generated itself and returned in a previous authorization object.
The backend need not check permissions, as the frontend has already
completed this check. The backend must check that the challenge object 
belongs to the authorization and return a `NOT_FOUND` error otherwise.

The `account_thumbprint` and `account_uri` can be passed onto Frida
to allow the validation to happen. Validation should happen in the
background as the client will poll the server until the challenge
succeeds or fails.

#### `GetOrder`

The backend must lookup an order by the ID it generated itself and returned
in a previous order object. The backend need not check permissions, as
the frontend has already completed this check. The standard gRPC `NOT_FOUND`
status code should be used if the order specified does not exist.

#### `GetAuthorization`

The backend must lookup an authorization by the ID it generated itself 
and returned in a previous authorization object. The backend need not 
check permissions, as the frontend has already completed this check.
The standard gRPC `NOT_FOUND` status code should be used if the
authorization specified does not exist.

#### `GetChallenge`

The backend must lookup a challenge by the ID and authorization ID it
generated itself and returned in a previous authorization object.
The backend need not check permissions, as the frontend has already
completed this check. The backend must check that the challenge object 
belongs to the authorization and return a `NOT_FOUND` error otherwise.

#### `GetCertificate`

The backend must lookup a certificate by the ID generated itself and
returned in a previous order object. The backend need not check permissions,
as the frontend has already completed this check. The backend must return
each certificate in each chain as a DER encoded binary list element. 

#### `RevokeCertificate`

The backend should lookup a certificate corresponding to the `issuer_id`
(as set in the frontend config), and the certificates `serial_number`.
If `revocation_reason` is set, the backend should check that it is a 
reason acceptable by policy.

If `authz_checked` is `true` the backend need not check the permissions
on the request, as the frontend has already completed these checks. If 
not it should check the ACME `account_id` is authorized to revoke 
the certificate. Per RFC 8555 the backend "MUST consider at least the
following accounts authorized for a given certificate:
- the account that issued the certificate. 
- an account that holds authorizations for all of the identifiers in 
  the certificate."
  
If revocation is successful it must return an empty response, otherwise
it must return an error explaining why the request was denied.

### Benny

Benny expects a single method on the backend CA for certificate 
status checking: `CheckCert`.

The request message contains the issuer ID set in the configuration, and
the serial number field from the certificate to be checked.

The response indicates the certificate status and some optional metadata about
revocation.

The backend may indicate that it does not know of the status of the certificate,
that the certificate is known good, the certificate is known revoked, or that
the certificate was never issued.

The revocation reason is the same values as is possible in a CRl.
More information about available revocation reasons is available
in [RFC 5280 § 5.3.1](https://datatracker.ietf.org/doc/html/rfc5280#section-5.3.1)

`revocation_timestamp` indicates the time at which the certificate was revoked (if known).
`invalidity_date` indicates the time at which the certificate is believed to have been compromised (if known).
`this_update` indicates the last time the authoritative source for this certificate was checked.
`next_update` indicates the next earliest time the authoritative source will have more up to date information.
`archive_cutoff` works as defined in [RFC 6960 § 4.4.4](https://datatracker.ietf.org/doc/html/rfc6960#section-4.4.4).

### Frida

Frida has three methods; `ValidateHTTP01`, `ValidateDNS01`, and `ValidateTLSALPN01`. They perform
`http-01`, `dns-01`, and `tls-alpn-01` based validations respectively, along with CAA checking.

Frida supports validating `dns` and `ip` identifier types, `email` validation with `email-reply-00` is not supported.

The `KeyValidationRequest` input message contains;
* `token` - The validation token, generated by the backend CA.
* `account_thumbprint` - The ACME account thumbprint, provided by Björn.
* `identifier` - The name to be validated.
* `account_uri` - The URI of the account requesting validation for RFC 8657 purposes, provided by Björn.

The response message contains a boolean indication validation success or
failure, and in case of failure an error object containing a list of errors
that caused the validation to fail. The error format is described above.
