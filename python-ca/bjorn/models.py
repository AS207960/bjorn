from django.db import models
from django.contrib import admin
from django.utils import timezone

import secrets
import base64
import uuid
import cryptography.x509
import google.protobuf.json_format

from . import order_pb2


class Account(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)

    def __str__(self):
        return self.name


def make_account_key():
    return secrets.token_bytes(32)


class AccountKey(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='keys')
    name = models.CharField(max_length=255)
    secret = models.BinaryField(default=make_account_key)

    @admin.display(description='Secret (Base64)')
    def secret_str(self):
        return base64.b64encode(self.secret).decode()

    def __str__(self):
        return f"{self.account.name}: {self.name}"


class Order(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(Account, on_delete=models.CASCADE, blank=True, null=True, related_name='orders')
    acme_account_id = models.TextField(blank=True, null=True)
    expires_at = models.DateTimeField()
    csr = models.BinaryField(blank=True, null=True)
    certificate = models.OneToOneField('Certificate', on_delete=models.SET_NULL, blank=True, null=True, related_name='orders')
    error = models.JSONField(blank=True, null=True)

    @property
    def rpc_status(self):
        authorizations = list(self.authorizations.all())

        if self.certificate:
            return order_pb2.OrderValid
        elif self.error:
            return order_pb2.OrderInvalid
        elif self.csr:
            return order_pb2.OrderProcessing
        elif self.expires_at <= timezone.now():
            return order_pb2.OrderInvalid
        elif all(a.authorization.rpc_status == order_pb2.AuthorizationValid for a in authorizations):
            return order_pb2.OrderReady
        elif any(a.authorization.rpc_status in (
                order_pb2.AuthorizationRevoked,
                order_pb2.AuthorizationDeactivated,
                order_pb2.AuthorizationInvalid,
                order_pb2.AuthorizationExpired,
        ) for a in authorizations):
            return order_pb2.OrderInvalid
        else:
            return order_pb2.OrderPending

    def to_rpc(self):
        authorizations = list(self.authorizations.all())

        errors = None
        if self.error:
            errors = order_pb2.ErrorResponse()
            google.protobuf.json_format.ParseDict(self.error, errors, ignore_unknown_fields=True)

        o = order_pb2.Order(
            id=self.id.bytes,
            identifiers=[i.to_rpc() for i in self.identifiers.all()],
            not_before=None,
            not_after=None,
            status=self.rpc_status,
            authorizations=[a.authorization.id.bytes for a in authorizations],
            error=errors
        )
        o.expires.FromDatetime(self.expires_at)
        if self.certificate:
            o.certificate_id.value = self.certificate.id.bytes

        return o


ID_DNS = "dns"
IDENTIFIERS = (
    (ID_DNS, "DNS"),
)


def id_to_rpc(id_type, identifier):
    return order_pb2.Identifier(
        identifier=identifier,
        id_type=order_pb2.DNSIdentifier if id_type == ID_DNS else order_pb2.UnknownIdentifier
    )


class Authorization(models.Model):
    STATE_PENDING = "p"
    STATE_VALID = "v"
    STATE_INVALID = "i"

    STATES = (
        (STATE_PENDING, "Pending"),
        (STATE_VALID, "Valid"),
        (STATE_INVALID, "Invalid"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    account = models.ForeignKey(Account, on_delete=models.CASCADE, blank=True, null=True, related_name='authorizations')
    acme_account_id = models.TextField(blank=True, null=True)
    state = models.CharField(max_length=1, choices=STATES)
    expires_at = models.DateTimeField()
    deactivated = models.BooleanField(blank=True)
    revoked = models.BooleanField(blank=True)
    id_type = models.CharField(max_length=64, choices=IDENTIFIERS)
    identifier = models.TextField()

    @property
    def rpc_status(self):
        if self.revoked:
            return order_pb2.AuthorizationRevoked
        elif self.deactivated:
            return order_pb2.AuthorizationDeactivated
        elif self.expires_at <= timezone.now():
            return order_pb2.AuthorizationExpired
        elif self.state == self.STATE_INVALID:
            return order_pb2.AuthorizationInvalid
        elif self.state == self.STATE_VALID:
            return order_pb2.AuthorizationValid
        else:
            return order_pb2.AuthorizationPending

    @property
    def id_rpc(self):
        return id_to_rpc(self.id_type, self.identifier)

    def to_rpc(self):
        challenges = []

        if self.state == self.STATE_INVALID:
            failed_challenge = self.challenges.filter(error__isnull=False).first()
            challenges.append(failed_challenge.to_rpc())
        elif self.state == self.STATE_VALID:
            valid_challenge = self.challenges.filter(validated_at__isnull=False).first()
            challenges.append(valid_challenge.to_rpc())
        else:
            for challenge in self.challenges.all():
                challenges.append(challenge.to_rpc())

        a = order_pb2.Authorization(
            id=self.id.bytes,
            status=self.rpc_status,
            identifier=self.id_rpc,
            challenges=challenges,
        )
        a.expires.FromDatetime(self.expires_at)
        return a


class OrderIdentifier(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='identifiers')
    id_type = models.CharField(max_length=64, choices=IDENTIFIERS)
    authorization = models.ForeignKey(Authorization, on_delete=models.SET_NULL, related_name='identifiers', null=True, blank=True)
    identifier = models.TextField()

    def __str__(self):
        return f"{self.get_id_type_display()}: {self.identifier}"

    def to_rpc(self):
        return id_to_rpc(self.id_type, self.identifier)


class AuthorizationChallenge(models.Model):
    TYPE_HTTP01 = "h"
    TYPE_DNS01 = "d"
    TYPE_TLSALPN01 = "t"

    TYPES = (
        (TYPE_HTTP01, "http-01"),
        (TYPE_DNS01, "dns-01"),
        (TYPE_TLSALPN01, "tls-alpn-01"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    authorization = models.ForeignKey(Authorization, on_delete=models.CASCADE, related_name='challenges')
    validated_at = models.DateTimeField(blank=True, null=True)
    processing = models.BooleanField(blank=True, default=False)
    error = models.JSONField(blank=True, null=True)
    type = models.CharField(max_length=1, choices=TYPES)
    token = models.CharField(max_length=255, null=True, blank=True)

    @property
    def rpc_status(self):
        if self.error:
            return order_pb2.ChallengeInvalid
        elif self.validated_at:
            return order_pb2.ChallengeValid
        elif self.processing:
            return order_pb2.ChallengeProcessing
        else:
            return order_pb2.ChallengePending

    def to_rpc(self):
        if self.type == self.TYPE_HTTP01:
            challenge_type = order_pb2.ChallengeHTTP01
        elif self.type == self.TYPE_DNS01:
            challenge_type = order_pb2.ChallengeDNS01
        elif self.type == self.TYPE_TLSALPN01:
            challenge_type = order_pb2.ChallengeTLSALPN01
        else:
            challenge_type = None

        errors = None
        if self.error:
            errors = order_pb2.ErrorResponse()
            google.protobuf.json_format.ParseDict(self.error, errors, ignore_unknown_fields=True)

        a = order_pb2.Challenge(
            id=self.id.bytes,
            status=self.rpc_status,
            type=challenge_type,
            error=errors,
        )
        if self.validated_at:
            a.validated.FromDatetime(self.validated_at)
        if self.token:
            a.token.value = self.token
        return a


class OrderAuthorization(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name='authorizations')
    authorization = models.ForeignKey(Authorization, on_delete=models.PROTECT, related_name='orders')


class IssuingCert(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    issued_by = models.ForeignKey('IssuingCert', on_delete=models.PROTECT, related_name='certificates', null=True, blank=True)
    name = models.CharField(max_length=255)
    cert = models.BinaryField()
    crl_url = models.URLField(blank=True, null=True)
    cert_url = models.URLField(blank=True, null=True)
    ocsp_responder_url = models.URLField(blank=True, null=True)

    def __str__(self):
        return self.name

    def cert_obj(self):
        return cryptography.x509.load_der_x509_certificate(self.cert)


class Certificate(models.Model):
    RevocationUnspecified = 1
    RevocationKeyCompromise = 2
    RevocationCACompromise = 3
    RevocationAffiliationChanged = 4
    RevocationSuperseded = 5
    RevocationCessationOfOperation = 6
    RevocationCertificateHold = 7
    RevocationRemoveFromCRL = 8
    RevocationPrivilegeWithdrawn = 9
    RevocationAACompromise = 10

    REVOCATION_REASONS = (
        (RevocationUnspecified, "Unspecified"),
        (RevocationKeyCompromise, "Key compromise"),
        (RevocationCACompromise, "CA compromise"),
        (RevocationAffiliationChanged, "Affiliation changed"),
        (RevocationSuperseded, "Superseded"),
        (RevocationCessationOfOperation, "Cessation of operation"),
        (RevocationCertificateHold, "Certificate hold"),
        (RevocationRemoveFromCRL, "Remove from CRL"),
        (RevocationPrivilegeWithdrawn, "Privilege withdrawn"),
        (RevocationAACompromise, "AA compromise"),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ee_cert = models.BinaryField()
    issued_at = models.DateTimeField()
    issued_by = models.ForeignKey(IssuingCert, on_delete=models.PROTECT, related_name='ee_certificates')
    revoked = models.BooleanField(blank=True, default=False)
    revocation_reason = models.PositiveSmallIntegerField(blank=True, null=True, choices=REVOCATION_REASONS)
    revocation_timestamp = models.DateTimeField(blank=True, null=True)
    invalidity_date = models.DateTimeField(blank=True, null=True)

    def __str__(self):
        serial = str(self.id.hex)
        return ":".join(serial[i:i+2] for i in range(0, len(serial), 2))

    def ee_cert_obj(self):
        return cryptography.x509.load_der_x509_certificate(self.ee_cert)
