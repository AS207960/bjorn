import base64

import grpc

from . import order_pb2
from . import order_pb2_grpc
from . import models
from . import ca

import hmac
import uuid
import datetime
import cryptography.x509
import cryptography.exceptions
import google.protobuf.timestamp_pb2
import google.protobuf.json_format
import secrets
import concurrent.futures
from django.utils import timezone
from django.db import transaction


def grpc_hook(server):
    order_pb2_grpc.add_CAServicer_to_server(CAServicer(), server)
    order_pb2_grpc.add_OCSPServicer_to_server(OCSPServicer(), server)


class OCSPServicer(order_pb2_grpc.OCSPServicer):
    def CheckCert(self, request: order_pb2.CheckCertRequest, context) -> order_pb2.CheckCertResponse:
        now = timezone.now()

        try:
            cert_id = uuid.UUID(bytes=request.serial_number)
        except ValueError:
            resp = order_pb2.CheckCertResponse(status=order_pb2.CertUnissued)
            resp.this_update.FromDatetime(now)
            resp.next_update.FromDatetime(now + datetime.timedelta(days=365))
            return resp

        certificate = models.Certificate.objects.filter(id=cert_id).first()  # type: models.Certificate
        if not certificate:
            resp = order_pb2.CheckCertResponse(status=order_pb2.CertUnissued)
            resp.this_update.FromDatetime(now)
            resp.next_update.FromDatetime(now + datetime.timedelta(days=7))
            return resp

        if certificate.revoked:
            resp = order_pb2.CheckCertResponse(
                status=order_pb2.CertRevoked,
                revocation_reason=certificate.revocation_reason if certificate.revocation_reason else None
            )
            resp.this_update.FromDatetime(now)
            resp.next_update.FromDatetime(now + datetime.timedelta(days=365))
            if certificate.revocation_timestamp:
                resp.revocation_timestamp.FromDatetime(certificate.revocation_timestamp)
            if certificate.invalidity_date:
                resp.invalidity_date    .FromDatetime(certificate.invalidity_date)
            return resp
        else:
            resp = order_pb2.CheckCertResponse(status=order_pb2.CertGood)
            resp.this_update.FromDatetime(now)
            resp.next_update.FromDatetime(now + datetime.timedelta(days=3))
            return resp


class CAServicer(order_pb2_grpc.CAServicer):
    def __init__(self):
        self._executor = concurrent.futures.ThreadPoolExecutor()

        channel = grpc.insecure_channel('localhost:50052')
        self._validator_stub = order_pb2_grpc.ValidatorStub(channel)

    def ValidateEAB(self, request: order_pb2.ValidateEABRequest, context):
        try:
            kid = uuid.UUID(request.kid)
        except ValueError:
            return order_pb2.ValidateEABResponse(
                valid=False
            )

        account_key = models.AccountKey.objects.filter(id=kid).first()
        if not account_key:
            return order_pb2.ValidateEABResponse(
                valid=False
            )

        if request.signature_method == order_pb2.HS256:
            computed_digest = hmac.digest(account_key.secret, request.signed_data, "sha256")
            return order_pb2.ValidateEABResponse(
                valid=hmac.compare_digest(computed_digest, request.signature)
            )
        elif request.signature_method == order_pb2.HS384:
            computed_digest = hmac.digest(account_key.secret, request.signed_data, "sha384")
            return order_pb2.ValidateEABResponse(
                valid=hmac.compare_digest(computed_digest, request.signature)
            )
        elif request.signature_method == order_pb2.HS512:
            computed_digest = hmac.digest(account_key.secret, request.signed_data, "sha512")
            return order_pb2.ValidateEABResponse(
                valid=hmac.compare_digest(computed_digest, request.signature)
            )

        return order_pb2.ValidateEABResponse(
            valid=False
        )

    def CreateOrder(self, request: order_pb2.CreateOrderRequest, context):
        if request.HasField("eab_id"):
            account_key = models.AccountKey.objects.filter(id=request.eab_id.value).first()
        else:
            account_key = None

        now = timezone.now()

        order = models.Order(
            account=account_key.account if account_key else None,
            acme_account_id=request.account_id,
            expires_at=now + datetime.timedelta(days=1),
        )

        errors = []
        identifiers = []

        for i in request.identifiers:
            if i.id_type == order_pb2.DNSIdentifier:
                is_wildcard = i.identifier.startswith("*.")
                id_value = i.identifier.lstrip("*.")

                if is_wildcard:
                    errors.append(order_pb2.Error(
                        error_type=order_pb2.RejectedIdentifierError,
                        status=400,
                        title="Unsupported identifier",
                        detail="Wildcard identifiers are not supported",
                        identifier=i,
                    ))

                if any(not (c.isdigit() or c.islower()) for c in id_value):
                    errors.append(order_pb2.Error(
                        error_type=order_pb2.RejectedIdentifierError,
                        status=400,
                        title="Unsupported identifier",
                        detail=f"'{i.identifier}' is of an invalid format",
                        identifier=i,
                    ))

                identifiers.append(models.OrderIdentifier(
                    order=order,
                    id_type=models.ID_DNS,
                    identifier=i.identifier
                ))
            else:
                errors.append(order_pb2.Error(
                    error_type=order_pb2.UnsupportedIdentifierError,
                    status=400,
                    title="Unsupported identifier",
                    detail=f"'{i.identifier}' is not an identifier we support",
                    identifier=i,
                ))

        if request.HasField("not_before"):
            errors.append(order_pb2.Error(
                error_type=order_pb2.MalformedError,
                status=400,
                title="Unsupported request",
                detail=f"'notBefore' is not supported by this server",
            ))

        if request.HasField("not_after"):
            errors.append(order_pb2.Error(
                error_type=order_pb2.MalformedError,
                status=400,
                title="Unsupported request",
                detail=f"'notAfter' is not supported by this server",
            ))

        if len(errors):
            return order_pb2.OrderResponse(
                error=order_pb2.ErrorResponse(
                    errors=errors
                )
            )

        authorizations = []
        challenges = []

        for i in identifiers:
            authorization = models.Authorization(
                account=account_key.account if account_key else None,
                acme_account_id=request.account_id if not account_key else None,
                expires_at=now + datetime.timedelta(days=1),
                state=models.Authorization.STATE_PENDING,
                deactivated=False,
                revoked=False,
                id_type=i.id_type,
                identifier=i.identifier,
            )
            challenge = models.AuthorizationChallenge(
                authorization=authorization,
                type=models.AuthorizationChallenge.TYPE_HTTP01,
                token=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().replace("=", "")
            )

            if account_key:
                existing_auth = account_key.account.authorizations \
                    .exclude(revoked=True) \
                    .exclude(deactivated=True) \
                    .exclude(expires_at__lt=now) \
                    .exclude(state=models.Authorization.STATE_INVALID) \
                    .filter(id_type=i.id_type, identifier=i.identifier).first()

                if existing_auth:
                    authorizations.append(existing_auth)
                else:
                    authorizations.append(authorization)
                    challenges.append(challenge)
            else:
                authorizations.append(authorization)
                challenges.append(challenge)

        with transaction.atomic():
            order.save()
            for i in identifiers:
                i.save()
            for a in authorizations:
                a.save()
                models.OrderAuthorization(
                    order=order,
                    authorization=a,
                ).save()
            for c in challenges:
                c.save()

        return order_pb2.OrderResponse(
            order=order.to_rpc()
        )

    def GetOrder(self, request: order_pb2.IDRequest, context):
        oid = uuid.UUID(bytes=request.id)
        order = models.Order.objects.filter(id=oid).first()

        if not order:
            context.set_details("Requested order not found")
            context.set_code(grpc.StatusCode.NOT_FOUND)
            return order_pb2.Order()

        return order.to_rpc()

    def GetAuthorization(self, request: order_pb2.IDRequest, context):
        aid = uuid.UUID(bytes=request.id)

        authz = models.Authorization.objects.filter(id=aid).first()

        if not authz:
            context.set_details("Requested authorization not found")
            context.set_code(grpc.StatusCode.NOT_FOUND)
            return order_pb2.Authorization()

        return authz.to_rpc()

    def GetChallenge(self, request: order_pb2.ChallengeIDRequest, context):
        aid = uuid.UUID(bytes=request.auth_id)
        cid = uuid.UUID(bytes=request.id)

        chall = models.AuthorizationChallenge.objects\
            .filter(id=cid, authorization_id=aid).first() # type: models.AuthorizationChallenge

        if not chall:
            context.set_details("Requested challenge not found")
            context.set_code(grpc.StatusCode.NOT_FOUND)
            return order_pb2.Challenge()

        return chall.to_rpc()

    def complete_challenge_task(self, chall: models.AuthorizationChallenge, thumbprint: str):
        if chall.type == chall.TYPE_HTTP01:
            try:
                req = order_pb2.KeyValidationRequest(
                    token=chall.token,
                    account_thumbprint=thumbprint,
                    identifier=chall.authorization.identifier
                )
                res = self._validator_stub.ValidateHTTP01(req)
                print(res)

                if res.valid:
                    chall.validated_at = timezone.now()
                    chall.save()
                    chall.authorization.state = chall.authorization.STATE_VALID
                    chall.authorization.save()
                else:
                    if res.error:
                        chall.error = google.protobuf.json_format.MessageToDict(res.error)
                    chall.save()
                    chall.authorization.state = chall.authorization.STATE_INVALID
                    chall.authorization.save()
            except grpc.RpcError as e:
                print(e)
                chall.error = google.protobuf.json_format.MessageToDict(order_pb2.ErrorResponse(
                    errors=[order_pb2.Error(
                        error_type=order_pb2.ServerInternalError,
                        title="Internal Server Error",
                        status=500,
                        detail="Challenge verification unexpectedly failed"
                    )]
                ))
                chall.save()
                chall.authorization.state = chall.authorization.STATE_INVALID
                chall.authorization.save()

    def CompleteChallenge(self, request: order_pb2.CompleteChallengeRequest, context):
        aid = uuid.UUID(bytes=request.auth_id)
        cid = uuid.UUID(bytes=request.id)

        chall = models.AuthorizationChallenge.objects\
            .filter(id=cid, authorization_id=aid).first() # type: models.AuthorizationChallenge

        if not chall:
            context.set_details("Requested challenge not found")
            context.set_code(grpc.StatusCode.NOT_FOUND)
            return order_pb2.Challenge()

        if chall.rpc_status not in (order_pb2.ChallengePending, order_pb2.ChallengeProcessing):
            return order_pb2.ChallengeResponse(
                error=order_pb2.ErrorResponse(
                    errors=[order_pb2.Error(
                        error_type=order_pb2.MalformedError,
                        title="Invalid request",
                        status=400,
                        detail="Challenge not in a pending state"
                    )]
                )
            )

        if chall.authorization.rpc_status != order_pb2.AuthorizationPending:
            return order_pb2.ChallengeResponse(
                error=order_pb2.ErrorResponse(
                    errors=[order_pb2.Error(
                        error_type=order_pb2.MalformedError,
                        title="Invalid request",
                        status=400,
                        detail="Authorization not in a pending state"
                    )]
                )
            )

        if not chall.processing:
            chall.processing = True
            chall.save()

        self._executor.submit(self.complete_challenge_task, chall, request.account_thumbprint)

        return order_pb2.ChallengeResponse(
            challenge=chall.to_rpc()
        )

    def FinalizeOrder(self, request: order_pb2.FinalizeOrderRequest, context):
        oid = uuid.UUID(bytes=request.id)
        order = models.Order.objects.filter(id=oid).first()

        if not order:
            context.set_details("Requested order not found")
            context.set_code(grpc.StatusCode.NOT_FOUND)
            return order_pb2.OrderResponse()

        if order.rpc_status != order_pb2.OrderReady:
            return order_pb2.OrderResponse(
                error=order_pb2.ErrorResponse(
                    errors=[order_pb2.Error(
                        error_type=order_pb2.OrderNotReadyError,
                        status=403,
                        title="Order not ready",
                        detail="Some authorizations are still pending"
                    )]
                )
            )

        try:
            csr = cryptography.x509.load_der_x509_csr(request.csr)
        except ValueError:
            return order_pb2.OrderResponse(
                error=order_pb2.ErrorResponse(
                    errors=[order_pb2.Error(
                        error_type=order_pb2.MalformedError,
                        status=400,
                        title="Malformed CSR",
                        detail="CSR could not be read"
                    )]
                )
            )

        if not csr.is_signature_valid:
            return order_pb2.OrderResponse(
                error=order_pb2.ErrorResponse(
                    errors=[order_pb2.Error(
                        error_type=order_pb2.BadCSRError,
                        status=400,
                        title="Malformed CSR",
                        detail="CSR signature could not be verified"
                    )]
                )
            )

        order.csr = request.csr
        order.save()

        self._executor.submit(ca.sign_order, order)

        return order_pb2.OrderResponse(
            order=order.to_rpc()
        )

    def GetCertificate(self, request: order_pb2.IDRequest, context):
        cid = uuid.UUID(bytes=request.id)
        cert = models.Certificate.objects.filter(id=cid).first()

        if not cert:
            context.set_details("Requested certificate not found")
            context.set_code(grpc.StatusCode.NOT_FOUND)
            return order_pb2.CertificateChainResponse()

        certs = [cert.ee_cert]
        issued_by = cert.issued_by
        while issued_by:
            certs.append(issued_by.cert)
            issued_by = issued_by.issued_by

        return order_pb2.CertificateChainResponse(
            primary_chain=order_pb2.CertificateChain(
                certificates=certs
            ),
            alternative_chains=[]
        )
