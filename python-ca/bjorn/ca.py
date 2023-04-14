import traceback
import typing

from . import models
from django.conf import settings
from django.utils import timezone
import datetime
import cryptography.x509
import cryptography.x509.oid
import cryptography.x509.certificate_transparency
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.hashes
import requests
import base64
import uuid


INTERMEDIATE_CA = models.IssuingCert.objects.get(id="3cdc5e60-5cb2-4248-8265-813128fc786c")
with open(settings.BASE_DIR / "ca-certs" / "intermediate-key.pem", "rb") as intermediate:
    INTERMEDIATE_CA_KEY = cryptography.hazmat.primitives.serialization.load_pem_private_key(intermediate.read(), None)


def build_cert(
        issuer_cert: models.IssuingCert,
        csr: cryptography.x509.CertificateSigningRequest, now, order: models.Order,
        builder: cryptography.x509.CertificateBuilder, cert_id
):
    issuer_cert_obj = INTERMEDIATE_CA.cert_obj()
    dns_labels = [i.identifier for i in order.identifiers.all() if i.id_type == models.ID_DNS]

    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(cert_id.int)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + datetime.timedelta(days=30))
    builder = builder.issuer_name(issuer_cert_obj.subject)
    builder = builder.subject_name(cryptography.x509.Name([
        cryptography.x509.NameAttribute(cryptography.x509.NameOID.COMMON_NAME, dns_labels[0]),
    ]))
    builder = builder.add_extension(
        cryptography.x509.SubjectAlternativeName(
            [cryptography.x509.DNSName(i) for i in dns_labels]
        ), critical=False
    )
    builder = builder.add_extension(
        cryptography.x509.BasicConstraints(ca=False, path_length=None), critical=True
    )
    builder = builder.add_extension(
        cryptography.x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False
    )
    builder = builder.add_extension(
        cryptography.x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert_obj.public_key()),
        critical=False
    )
    builder = builder.add_extension(
        cryptography.x509.KeyUsage(
            digital_signature=True, key_encipherment=True, content_commitment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=False, encipher_only=False, decipher_only=False, crl_sign=False,
        ), critical=True
    )
    builder = builder.add_extension(
        cryptography.x509.ExtendedKeyUsage(usages=[
            cryptography.x509.ExtendedKeyUsageOID.SERVER_AUTH,
            cryptography.x509.ExtendedKeyUsageOID.CLIENT_AUTH,
        ]), critical=False
    )

    if issuer_cert.crl_url:
        builder = builder.add_extension(
            cryptography.x509.CRLDistributionPoints([
                cryptography.x509.DistributionPoint(
                    full_name=[
                        cryptography.x509.UniformResourceIdentifier(issuer_cert.crl_url)
                    ],
                    relative_name=None, crl_issuer=None, reasons=None
                )
            ]), critical=False
        )

    access_descriptions = []
    if issuer_cert.cert_url:
        access_descriptions.append(cryptography.x509.AccessDescription(
            access_method=cryptography.x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
            access_location=cryptography.x509.UniformResourceIdentifier(issuer_cert.cert_url)
        ))
    if issuer_cert.ocsp_responder_url:
        access_descriptions.append(cryptography.x509.AccessDescription(
            access_method=cryptography.x509.oid.AuthorityInformationAccessOID.OCSP,
            access_location=cryptography.x509.UniformResourceIdentifier(issuer_cert.ocsp_responder_url)
        ))
    if len(access_descriptions):
        builder = builder.add_extension(cryptography.x509.AuthorityInformationAccess(access_descriptions))

    return builder


class SCT:
    def __init__(self, version: int, log_id: str, timestamp: int, extensions: str, signature: str):
        self._version = version
        self._log_id = base64.b64decode(log_id)
        self._timestamp = timestamp
        self._extensions = base64.b64decode(extensions)
        self._signature = base64.b64decode(signature)

    def encoded(self):
        out = bytearray()
        out.extend(self._version.to_bytes(1, byteorder="big"))
        out.extend(self._log_id[:32])
        out.extend(self._timestamp.to_bytes(8, byteorder="big"))
        out.extend(len(self._extensions).to_bytes(2, byteorder="big"))
        out.extend(self._extensions)
        out.extend(self._signature)
        return bytes(out)


class SCTList:
    def __init__(self, scts: typing.List[SCT]):
        self._scts = scts

    def encoded(self):
        sct_list = bytearray()
        for sct in self._scts:
            sct_encoded = sct.encoded()
            sct_list.extend(len(sct_encoded).to_bytes(2, byteorder="big"))
            sct_list.extend(sct_encoded)

        out = bytearray()
        out.extend(len(sct_list).to_bytes(2, byteorder="big"))
        out.extend(sct_list)

        return bytes(out)

    def encoded_asn1(self):
        out = bytearray([0x04])

        encoded = self.encoded()
        length = len(encoded)

        if length < 128:
            out.append(length)
        else:
            values = []
            while length:
                values.append(length & 0xff)
                length >>= 8
            values.reverse()
            out.append(0x80 | len(values))
            out.extend(values)

        out.extend(encoded)

        return bytes(out)


def sign_order(order: models.Order):
    try:
        chain_bytes = []
        issed_by = INTERMEDIATE_CA
        while issed_by:
            chain_bytes.append(base64.b64encode(issed_by.cert).decode())
            issed_by = issed_by.issued_by

        cert_id = uuid.uuid4()
        now = timezone.now()
        csr = cryptography.x509.load_der_x509_csr(order.csr)

        precert_builder = cryptography.x509.CertificateBuilder()
        precert_builder = build_cert(INTERMEDIATE_CA, csr, now, order, precert_builder, cert_id)
        precert_builder = precert_builder.add_extension(cryptography.x509.PrecertPoison(), critical=True)
        precert = precert_builder.sign(INTERMEDIATE_CA_KEY, cryptography.hazmat.primitives.hashes.SHA512())
        precert_bytes = precert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.DER)

        expiry_date = precert.not_valid_after
        ct_logs = list(map(
            lambda log: log["url"],
            filter(
                lambda log: log["expiry_range"] is None or (
                        log["expiry_range"]["start"] <= expiry_date < log["expiry_range"]["end"]
                ),
                settings.CT_LOGS
            )
        ))

        scts = []
        for ct in ct_logs:
            r = requests.post(f"{ct}/ct/v1/add-pre-chain", json={
                "chain": [base64.b64encode(precert_bytes).decode()] + chain_bytes
            })
            try:
                r.raise_for_status()
            except requests.exceptions.RequestException as e:
                print(f"Failed to submit to {ct}: {r.text}")
                raise e
            sct = r.json()
            scts.append(SCT(
                version=sct["sct_version"],
                log_id=sct["id"],
                timestamp=sct["timestamp"],
                extensions=sct["extensions"],
                signature=sct["signature"],
            ))

        eecert_builder = cryptography.x509.CertificateBuilder()
        eecert_builder = build_cert(INTERMEDIATE_CA, csr, now, order, eecert_builder, cert_id)

        sct_list = SCTList(scts)
        eecert_builder = eecert_builder.add_extension(
            cryptography.x509.UnrecognizedExtension(
                oid=cryptography.x509.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS,
                value=sct_list.encoded_asn1()
            ), critical=False
        )

        eecert = eecert_builder.sign(INTERMEDIATE_CA_KEY, cryptography.hazmat.primitives.hashes.SHA512())
        eecert_bytes = eecert.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.DER)

        for ct in ct_logs:
            r = requests.post(f"{ct}/ct/v1/add-chain", json={
                "chain": [base64.b64encode(eecert_bytes).decode()] + chain_bytes
            })
            r.raise_for_status()

        certificate = models.Certificate(
            id=cert_id,
            issued_at=now,
            ee_cert=eecert_bytes,
            issued_by=INTERMEDIATE_CA
        )
        certificate.save()
        order.certificate = certificate
        order.save()
    except Exception as e:
        traceback.print_exception(e)

