"""Exercises PyHankoPAdESSigner against the real pyHanko library (no
mocking pyHanko itself) — only HSMClient is faked, the same boundary
signing-service actually has with hsm-service. Verifies the produced
signature is a genuine, independently-verifiable PAdES-B signature, not
just "didn't crash"."""

import io
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.general import load_certs_from_pemder_data
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

from app.domain.exceptions.domain_errors import ValidationError
from app.domain.ports.output.HSMClient import HSMClient
from app.infrastructure.crypto.pyhanko_pades_signer import PyHankoPAdESSigner

KEY_ID = UUID(int=42)


class _FakeHsmClient(HSMClient):
    """Signs with a real RSA private key, same contract as the real
    HSMClient: receives raw (unhashed) data, hashes+signs internally."""

    def __init__(self, private_key: rsa.RSAPrivateKey):
        self._private_key = private_key
        self.sign_calls = []

    async def create_key(self, *args, **kwargs):
        raise NotImplementedError

    async def get_public_key(self, key_id):
        raise NotImplementedError

    async def sign_hash(
        self, key_id: UUID, hash_bytes: bytes, bearer_token: str
    ) -> bytes:
        self.sign_calls.append((key_id, hash_bytes, bearer_token))
        return self._private_key.sign(hash_bytes, padding.PKCS1v15(), hashes.SHA256())

    async def ping(self, key_id, bearer_token):
        raise NotImplementedError


def _make_chain():
    def _cert(subject_cn, issuer_cn, issuer_key, public_key, is_ca, path_length=None):
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=is_ca, path_length=path_length), critical=True
            )
        )
        return builder.sign(issuer_key, hashes.SHA256())

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_cert = _cert(
        "Test Root CA", "Test Root CA", root_key, root_key.public_key(), True, 1
    )

    inter_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    inter_cert = _cert(
        "Test Intermediate CA",
        "Test Root CA",
        root_key,
        inter_key.public_key(),
        True,
        0,
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Jane Doe")])
    leaf_issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate CA")]
    )
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject)
        .issuer_name(leaf_issuer)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        # Real certificate-service leaf certs always set this
        # (IssueCertificateRequest: "key_usage siempre digitalSignature+
        # nonRepudiation") — pyHanko's default validation policy
        # requires content_commitment (non-repudiation) on a signing cert.
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(inter_key, hashes.SHA256())
    )

    def pem(cert):
        return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

    return leaf_key, pem(leaf_cert), pem(inter_cert), pem(root_cert)


def _minimal_pdf() -> bytes:
    header = b"%PDF-1.4\n"
    objs = [
        b"<</Type/Catalog/Pages 2 0 R>>",
        b"<</Type/Pages/Kids[3 0 R]/Count 1>>",
        b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>",
    ]
    body = header
    offsets = []
    for i, obj in enumerate(objs, start=1):
        offsets.append(len(body))
        body += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
    xref_offset = len(body)
    xref = b"xref\n0 4\n0000000000 65535 f \n"
    for off in offsets:
        xref += f"{off:010d} 00000 n \n".encode()
    trailer = (
        b"trailer\n<</Size 4/Root 1 0 R>>\nstartxref\n"
        + str(xref_offset).encode()
        + b"\n%%EOF"
    )
    return body + xref + trailer


@pytest.mark.asyncio
async def test_sign_pdf_produces_valid_trusted_pades_signature():
    leaf_key, leaf_pem, inter_pem, root_pem = _make_chain()
    hsm = _FakeHsmClient(leaf_key)
    signer = PyHankoPAdESSigner()

    signed = await signer.sign_pdf(
        document=_minimal_pdf(),
        leaf_cert_pem=leaf_pem,
        chain_pems=[inter_pem],
        key_id=KEY_ID,
        hsm_client=hsm,
        bearer_token="caller-jwt",
    )

    assert signed.startswith(b"%PDF-")

    # hsm-service must receive the raw signed-attrs bytes, never a
    # pre-computed digest (see HSMClient.sign_hash's docstring).
    real_calls = [c for c in hsm.sign_calls if c[1] != b"\0" * (2048 // 8)]
    assert all(c[0] == KEY_ID and c[2] == "caller-jwt" for c in real_calls)

    root_cert = next(load_certs_from_pemder_data(root_pem.encode("ascii")))
    vc = ValidationContext(trust_roots=[root_cert])
    reader = PdfFileReader(io.BytesIO(signed))
    embedded = reader.embedded_signatures[0]
    status = await async_validate_pdf_signature(embedded, signer_validation_context=vc)

    assert status.intact is True
    assert status.valid is True
    assert status.trusted is True


@pytest.mark.asyncio
async def test_sign_pdf_rejects_non_pdf_document():
    leaf_key, leaf_pem, inter_pem, _root_pem = _make_chain()
    hsm = _FakeHsmClient(leaf_key)
    signer = PyHankoPAdESSigner()

    with pytest.raises(ValidationError) as exc_info:
        await signer.sign_pdf(
            document=b"not a pdf",
            leaf_cert_pem=leaf_pem,
            chain_pems=[inter_pem],
            key_id=KEY_ID,
            hsm_client=hsm,
            bearer_token="caller-jwt",
        )

    assert exc_info.value.field == "document_b64"
    assert hsm.sign_calls == []
