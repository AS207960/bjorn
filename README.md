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
*-------------*                     |      *-------*               *------------* <--   |
| User server | <--http-01/dns-01---|------| Frida | <----gRPC---- | Backend CA |      /
*-------------*                     |      *-------*               *------------* <----
```

## Repositry layout

| Directory           | Contents                                        |
|---------------------|-------------------------------------------------|
| `migrations`        | SQL database migrations                         |
| `proto`             | gRPC definitions for inter-working              |
| `python-ca`         | Example CA backend **DO NOT USE IN PRODUCTION** |
| `src`               | Common Rust source code                         |
| `src/bin/acme`      | The Björn binary                                |
| `src/acme`          | Björn specific utilities                        |
| `src/bin/ocsp`      | The Benny binary                                |
| `src/ocsp`          | Benny specific utilities                        |
| `src/bin/validator` | The Frida binary                                |
| `src/validator`     | Frida specific utilities                        |

## Implemented RFCs

* [RFC 6960](https://datatracker.ietf.org/doc/html/rfc6960) - Online Certificate Status Protocol - OCSP
* [RFC 8954](https://datatracker.ietf.org/doc/html/rfc8954) - Online Certificate Status Protocol (OCSP) Nonce Extension
* [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555) - Automatic Certificate Management Environment (ACME)
* [RFC 7638](https://datatracker.ietf.org/doc/html/rfc7638) - JSON Web Key (JWK) Thumbprint
* [RFC 8659](https://datatracker.ietf.org/doc/html/rfc8659) - DNS Certification Authority Authorization (CAA) Resource Record

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
website_uri = "https://as207960.net"
caa_identities = ["bjorn.as207960.net"]
ca_grpc_uri = "http://[::1]:50051"

[global.databases]
db = { url = "postgres://postgres@localhost/bjorn" }
```

#### Configuration explanation.

##### `external_uri`
The URL base at which the ACME server can be reached by external end users,
including protocol and port.

##### `tos_uri`
The URL of the Terms and Conditions page of the ACME server. End users should
be presented with this page by their ACME client to agree to it before proceeding.

##### `website_uri`
The homepage of the entity running the ACME server.

##### `caa_identities`
Which CAA issuers identities are recognised by the ACME server as allowing
issuance by this CA.

##### `ca_grpc_uri`
The gRPC URL of the CA backend. It should implement the protocol as described
further down.

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

TODO

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

Frida has two methods; `ValidateHTTP01` and `ValidateDNS01`. They perform
`http-01` and `dns-01` based validations respectively, along with CAA checking.

The `KeyValidationRequest` input message contains;
* `token` - The validation token, generated by the backend CA.
* `account_thumbprint` - The ACME account thumbprint, provided by Björn.
* `identifier` - The domain name to be validated.

The response message contains a boolean indication validation success or
failure, and in case of failure an error object containing a list of errors
that caused the validation to fail. The error format is described above.
