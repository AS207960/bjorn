from google.protobuf import wrappers_pb2 as _wrappers_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

AccountDoesNotExistError: ErrorType
AlreadyRevokedError: ErrorType
AuthorizationDeactivated: AuthorizationStatus
AuthorizationExpired: AuthorizationStatus
AuthorizationInvalid: AuthorizationStatus
AuthorizationPending: AuthorizationStatus
AuthorizationRevoked: AuthorizationStatus
AuthorizationValid: AuthorizationStatus
AutoRenewalCanceledError: ErrorType
AutoRenewalCancellationInvalidError: ErrorType
AutoRenewalExpiredError: ErrorType
AutoRenewalRevocationNotSupportedError: ErrorType
BadCSRError: ErrorType
BadNonceError: ErrorType
BadPublicKeyError: ErrorType
BadRevocationReasonError: ErrorType
BadSignatureAlgorithmError: ErrorType
CAAError: ErrorType
CertGood: CertStatus
CertRevoked: CertStatus
CertUnissued: CertStatus
CertUnknown: CertStatus
ChallengeDNS01: ChallengeType
ChallengeHTTP01: ChallengeType
ChallengeInvalid: ChallengeStatus
ChallengePending: ChallengeStatus
ChallengeProcessing: ChallengeStatus
ChallengeTLSALPN01: ChallengeType
ChallengeValid: ChallengeStatus
CompoundError: ErrorType
ConnectionError: ErrorType
DESCRIPTOR: _descriptor.FileDescriptor
DNSError: ErrorType
DNSIdentifier: IdentifierType
EmailIdentifier: IdentifierType
ExternalAccountRequiredError: ErrorType
HS1: EABSignatureMethod
HS256: EABSignatureMethod
HS384: EABSignatureMethod
HS512: EABSignatureMethod
IPIdentifier: IdentifierType
IncorrectResponseError: ErrorType
InvalidContactError: ErrorType
MalformedError: ErrorType
OrderInvalid: OrderStatus
OrderNotReadyError: ErrorType
OrderPending: OrderStatus
OrderProcessing: OrderStatus
OrderReady: OrderStatus
OrderValid: OrderStatus
RateLimitedError: ErrorType
RejectedIdentifierError: ErrorType
RevocationAACompromise: RevocationReason
RevocationAffiliationChanged: RevocationReason
RevocationCACompromise: RevocationReason
RevocationCertificateHold: RevocationReason
RevocationCessationOfOperation: RevocationReason
RevocationKeyCompromise: RevocationReason
RevocationPrivilegeWithdrawn: RevocationReason
RevocationRemoveFromCRL: RevocationReason
RevocationSuperseded: RevocationReason
RevocationUnknown: RevocationReason
RevocationUnspecified: RevocationReason
ServerInternalError: ErrorType
TLSError: ErrorType
UnauthorizedError: ErrorType
UnknownIdentifier: IdentifierType
UnsupportedContactError: ErrorType
UnsupportedIdentifierError: ErrorType
UserActionRequiredError: ErrorType

class Authorization(_message.Message):
    __slots__ = ["challenges", "expires", "id", "identifier", "status", "wildcard"]
    CHALLENGES_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_FIELD_NUMBER: _ClassVar[int]
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    WILDCARD_FIELD_NUMBER: _ClassVar[int]
    challenges: _containers.RepeatedCompositeFieldContainer[Challenge]
    expires: _timestamp_pb2.Timestamp
    id: bytes
    identifier: Identifier
    status: AuthorizationStatus
    wildcard: _wrappers_pb2.BoolValue
    def __init__(self, id: _Optional[bytes] = ..., status: _Optional[_Union[AuthorizationStatus, str]] = ..., expires: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., identifier: _Optional[_Union[Identifier, _Mapping]] = ..., challenges: _Optional[_Iterable[_Union[Challenge, _Mapping]]] = ..., wildcard: _Optional[_Union[_wrappers_pb2.BoolValue, _Mapping]] = ...) -> None: ...

class AuthorizationResponse(_message.Message):
    __slots__ = ["authorization", "error"]
    AUTHORIZATION_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    authorization: Authorization
    error: ErrorResponse
    def __init__(self, authorization: _Optional[_Union[Authorization, _Mapping]] = ..., error: _Optional[_Union[ErrorResponse, _Mapping]] = ...) -> None: ...

class CertificateChain(_message.Message):
    __slots__ = ["certificates"]
    CERTIFICATES_FIELD_NUMBER: _ClassVar[int]
    certificates: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, certificates: _Optional[_Iterable[bytes]] = ...) -> None: ...

class CertificateChainResponse(_message.Message):
    __slots__ = ["alternative_chains", "primary_chain"]
    ALTERNATIVE_CHAINS_FIELD_NUMBER: _ClassVar[int]
    PRIMARY_CHAIN_FIELD_NUMBER: _ClassVar[int]
    alternative_chains: _containers.RepeatedCompositeFieldContainer[CertificateChain]
    primary_chain: CertificateChain
    def __init__(self, primary_chain: _Optional[_Union[CertificateChain, _Mapping]] = ..., alternative_chains: _Optional[_Iterable[_Union[CertificateChain, _Mapping]]] = ...) -> None: ...

class Challenge(_message.Message):
    __slots__ = ["error", "id", "status", "token", "type", "validated"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    VALIDATED_FIELD_NUMBER: _ClassVar[int]
    error: ErrorResponse
    id: bytes
    status: ChallengeStatus
    token: _wrappers_pb2.StringValue
    type: ChallengeType
    validated: _timestamp_pb2.Timestamp
    def __init__(self, id: _Optional[bytes] = ..., type: _Optional[_Union[ChallengeType, str]] = ..., status: _Optional[_Union[ChallengeStatus, str]] = ..., validated: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., error: _Optional[_Union[ErrorResponse, _Mapping]] = ..., token: _Optional[_Union[_wrappers_pb2.StringValue, _Mapping]] = ...) -> None: ...

class ChallengeIDRequest(_message.Message):
    __slots__ = ["auth_id", "id"]
    AUTH_ID_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    auth_id: bytes
    id: bytes
    def __init__(self, id: _Optional[bytes] = ..., auth_id: _Optional[bytes] = ...) -> None: ...

class ChallengeResponse(_message.Message):
    __slots__ = ["challenge", "error"]
    CHALLENGE_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    challenge: Challenge
    error: ErrorResponse
    def __init__(self, challenge: _Optional[_Union[Challenge, _Mapping]] = ..., error: _Optional[_Union[ErrorResponse, _Mapping]] = ...) -> None: ...

class CheckCertRequest(_message.Message):
    __slots__ = ["issuer_id", "serial_number"]
    ISSUER_ID_FIELD_NUMBER: _ClassVar[int]
    SERIAL_NUMBER_FIELD_NUMBER: _ClassVar[int]
    issuer_id: str
    serial_number: bytes
    def __init__(self, issuer_id: _Optional[str] = ..., serial_number: _Optional[bytes] = ...) -> None: ...

class CheckCertResponse(_message.Message):
    __slots__ = ["archive_cutoff", "invalidity_date", "next_update", "revocation_reason", "revocation_timestamp", "status", "this_update"]
    ARCHIVE_CUTOFF_FIELD_NUMBER: _ClassVar[int]
    INVALIDITY_DATE_FIELD_NUMBER: _ClassVar[int]
    NEXT_UPDATE_FIELD_NUMBER: _ClassVar[int]
    REVOCATION_REASON_FIELD_NUMBER: _ClassVar[int]
    REVOCATION_TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    THIS_UPDATE_FIELD_NUMBER: _ClassVar[int]
    archive_cutoff: _timestamp_pb2.Timestamp
    invalidity_date: _timestamp_pb2.Timestamp
    next_update: _timestamp_pb2.Timestamp
    revocation_reason: RevocationReason
    revocation_timestamp: _timestamp_pb2.Timestamp
    status: CertStatus
    this_update: _timestamp_pb2.Timestamp
    def __init__(self, status: _Optional[_Union[CertStatus, str]] = ..., revocation_reason: _Optional[_Union[RevocationReason, str]] = ..., revocation_timestamp: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., this_update: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., next_update: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., archive_cutoff: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., invalidity_date: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class CompleteChallengeRequest(_message.Message):
    __slots__ = ["account_thumbprint", "account_uri", "auth_id", "id"]
    ACCOUNT_THUMBPRINT_FIELD_NUMBER: _ClassVar[int]
    ACCOUNT_URI_FIELD_NUMBER: _ClassVar[int]
    AUTH_ID_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    account_thumbprint: str
    account_uri: str
    auth_id: bytes
    id: bytes
    def __init__(self, id: _Optional[bytes] = ..., auth_id: _Optional[bytes] = ..., account_thumbprint: _Optional[str] = ..., account_uri: _Optional[str] = ...) -> None: ...

class CreateAuthorizationRequest(_message.Message):
    __slots__ = ["account_id", "eab_id", "identifier"]
    ACCOUNT_ID_FIELD_NUMBER: _ClassVar[int]
    EAB_ID_FIELD_NUMBER: _ClassVar[int]
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    account_id: str
    eab_id: _wrappers_pb2.StringValue
    identifier: Identifier
    def __init__(self, identifier: _Optional[_Union[Identifier, _Mapping]] = ..., account_id: _Optional[str] = ..., eab_id: _Optional[_Union[_wrappers_pb2.StringValue, _Mapping]] = ...) -> None: ...

class CreateOrderRequest(_message.Message):
    __slots__ = ["account_id", "eab_id", "identifiers", "not_after", "not_before"]
    ACCOUNT_ID_FIELD_NUMBER: _ClassVar[int]
    EAB_ID_FIELD_NUMBER: _ClassVar[int]
    IDENTIFIERS_FIELD_NUMBER: _ClassVar[int]
    NOT_AFTER_FIELD_NUMBER: _ClassVar[int]
    NOT_BEFORE_FIELD_NUMBER: _ClassVar[int]
    account_id: str
    eab_id: _wrappers_pb2.StringValue
    identifiers: _containers.RepeatedCompositeFieldContainer[Identifier]
    not_after: _timestamp_pb2.Timestamp
    not_before: _timestamp_pb2.Timestamp
    def __init__(self, identifiers: _Optional[_Iterable[_Union[Identifier, _Mapping]]] = ..., not_before: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., not_after: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., account_id: _Optional[str] = ..., eab_id: _Optional[_Union[_wrappers_pb2.StringValue, _Mapping]] = ...) -> None: ...

class Error(_message.Message):
    __slots__ = ["detail", "error_type", "identifier", "instance", "status", "sub_problems", "title"]
    DETAIL_FIELD_NUMBER: _ClassVar[int]
    ERROR_TYPE_FIELD_NUMBER: _ClassVar[int]
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    INSTANCE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    SUB_PROBLEMS_FIELD_NUMBER: _ClassVar[int]
    TITLE_FIELD_NUMBER: _ClassVar[int]
    detail: str
    error_type: ErrorType
    identifier: Identifier
    instance: _wrappers_pb2.StringValue
    status: int
    sub_problems: _containers.RepeatedCompositeFieldContainer[Error]
    title: str
    def __init__(self, error_type: _Optional[_Union[ErrorType, str]] = ..., title: _Optional[str] = ..., status: _Optional[int] = ..., detail: _Optional[str] = ..., instance: _Optional[_Union[_wrappers_pb2.StringValue, _Mapping]] = ..., sub_problems: _Optional[_Iterable[_Union[Error, _Mapping]]] = ..., identifier: _Optional[_Union[Identifier, _Mapping]] = ...) -> None: ...

class ErrorResponse(_message.Message):
    __slots__ = ["errors"]
    ERRORS_FIELD_NUMBER: _ClassVar[int]
    errors: _containers.RepeatedCompositeFieldContainer[Error]
    def __init__(self, errors: _Optional[_Iterable[_Union[Error, _Mapping]]] = ...) -> None: ...

class FinalizeOrderRequest(_message.Message):
    __slots__ = ["csr", "id"]
    CSR_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    csr: bytes
    id: bytes
    def __init__(self, id: _Optional[bytes] = ..., csr: _Optional[bytes] = ...) -> None: ...

class IDRequest(_message.Message):
    __slots__ = ["id"]
    ID_FIELD_NUMBER: _ClassVar[int]
    id: bytes
    def __init__(self, id: _Optional[bytes] = ...) -> None: ...

class Identifier(_message.Message):
    __slots__ = ["id_type", "identifier"]
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    ID_TYPE_FIELD_NUMBER: _ClassVar[int]
    id_type: IdentifierType
    identifier: str
    def __init__(self, id_type: _Optional[_Union[IdentifierType, str]] = ..., identifier: _Optional[str] = ...) -> None: ...

class KeyValidationRequest(_message.Message):
    __slots__ = ["account_thumbprint", "account_uri", "hs_private_key", "identifier", "token"]
    ACCOUNT_THUMBPRINT_FIELD_NUMBER: _ClassVar[int]
    ACCOUNT_URI_FIELD_NUMBER: _ClassVar[int]
    HS_PRIVATE_KEY_FIELD_NUMBER: _ClassVar[int]
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    account_thumbprint: str
    account_uri: _wrappers_pb2.StringValue
    hs_private_key: bytes
    identifier: Identifier
    token: str
    def __init__(self, token: _Optional[str] = ..., account_thumbprint: _Optional[str] = ..., identifier: _Optional[_Union[Identifier, _Mapping]] = ..., account_uri: _Optional[_Union[_wrappers_pb2.StringValue, _Mapping]] = ..., hs_private_key: _Optional[bytes] = ...) -> None: ...

class Order(_message.Message):
    __slots__ = ["authorizations", "certificate_id", "expires", "id", "identifiers", "not_after", "not_before", "status"]
    AUTHORIZATIONS_FIELD_NUMBER: _ClassVar[int]
    CERTIFICATE_ID_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_FIELD_NUMBER: _ClassVar[int]
    IDENTIFIERS_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    NOT_AFTER_FIELD_NUMBER: _ClassVar[int]
    NOT_BEFORE_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    authorizations: _containers.RepeatedScalarFieldContainer[bytes]
    certificate_id: _wrappers_pb2.BytesValue
    expires: _timestamp_pb2.Timestamp
    id: bytes
    identifiers: _containers.RepeatedCompositeFieldContainer[Identifier]
    not_after: _timestamp_pb2.Timestamp
    not_before: _timestamp_pb2.Timestamp
    status: OrderStatus
    def __init__(self, id: _Optional[bytes] = ..., identifiers: _Optional[_Iterable[_Union[Identifier, _Mapping]]] = ..., not_before: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., not_after: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., expires: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., status: _Optional[_Union[OrderStatus, str]] = ..., authorizations: _Optional[_Iterable[bytes]] = ..., certificate_id: _Optional[_Union[_wrappers_pb2.BytesValue, _Mapping]] = ...) -> None: ...

class OrderResponse(_message.Message):
    __slots__ = ["error", "order"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    ORDER_FIELD_NUMBER: _ClassVar[int]
    error: ErrorResponse
    order: Order
    def __init__(self, order: _Optional[_Union[Order, _Mapping]] = ..., error: _Optional[_Union[ErrorResponse, _Mapping]] = ...) -> None: ...

class RevokeCertRequest(_message.Message):
    __slots__ = ["account_id", "authz_checked", "issuer_id", "revocation_reason", "serial_number"]
    ACCOUNT_ID_FIELD_NUMBER: _ClassVar[int]
    AUTHZ_CHECKED_FIELD_NUMBER: _ClassVar[int]
    ISSUER_ID_FIELD_NUMBER: _ClassVar[int]
    REVOCATION_REASON_FIELD_NUMBER: _ClassVar[int]
    SERIAL_NUMBER_FIELD_NUMBER: _ClassVar[int]
    account_id: str
    authz_checked: bool
    issuer_id: str
    revocation_reason: _wrappers_pb2.UInt32Value
    serial_number: bytes
    def __init__(self, account_id: _Optional[str] = ..., authz_checked: bool = ..., issuer_id: _Optional[str] = ..., serial_number: _Optional[bytes] = ..., revocation_reason: _Optional[_Union[_wrappers_pb2.UInt32Value, _Mapping]] = ...) -> None: ...

class RevokeCertResponse(_message.Message):
    __slots__ = ["error"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    error: ErrorResponse
    def __init__(self, error: _Optional[_Union[ErrorResponse, _Mapping]] = ...) -> None: ...

class ValidateEABRequest(_message.Message):
    __slots__ = ["kid", "signature", "signature_method", "signed_data"]
    KID_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_METHOD_FIELD_NUMBER: _ClassVar[int]
    SIGNED_DATA_FIELD_NUMBER: _ClassVar[int]
    kid: str
    signature: bytes
    signature_method: EABSignatureMethod
    signed_data: bytes
    def __init__(self, kid: _Optional[str] = ..., signature_method: _Optional[_Union[EABSignatureMethod, str]] = ..., signed_data: _Optional[bytes] = ..., signature: _Optional[bytes] = ...) -> None: ...

class ValidateEABResponse(_message.Message):
    __slots__ = ["valid"]
    VALID_FIELD_NUMBER: _ClassVar[int]
    valid: bool
    def __init__(self, valid: bool = ...) -> None: ...

class ValidationResult(_message.Message):
    __slots__ = ["error", "valid"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    VALID_FIELD_NUMBER: _ClassVar[int]
    error: ErrorResponse
    valid: bool
    def __init__(self, valid: bool = ..., error: _Optional[_Union[ErrorResponse, _Mapping]] = ...) -> None: ...

class IdentifierType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class ErrorType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class EABSignatureMethod(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class OrderStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class AuthorizationStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class ChallengeType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class ChallengeStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class CertStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class RevocationReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
