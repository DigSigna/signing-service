"""PAdES-B signing via pyHanko (signing-plan.md point 1).

Wires pyHanko's async custom-signer extension point directly to
HSMClient.sign_hash: pyHanko's Signer.async_sign_raw(data,
digest_algorithm, dry_run) hands us the raw signed-attributes bytes and
expects back a signature produced by hashing them with the given
digest algorithm and signing that hash — exactly what hsm-service's
fixed CKM_SHA256_RSA_PKCS mechanism already does internally. No
thread/event-loop bridging is needed here (unlike the old, now-deleted
HSMBackedRSAPrivateKey in certificate-service, which had to bridge a
*synchronous* cryptography.x509 Protocol): pyHanko's signer API is
natively async, so this just awaits hsm_client.sign_hash directly.

pyHanko computes the actual byte-range digest itself (see
PdfSignatureMetadata/async_sign_pdf) — this module never hashes the
document itself, matching signing-plan.md's explicit instruction not to
hand-roll byte-range signing.
"""

from __future__ import annotations

import io
from typing import List
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import load_pem_x509_certificate
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import PdfError
from pyhanko.sign import PdfSignatureMetadata, async_sign_pdf
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.sign.general import load_certs_from_pemder_data
from pyhanko.sign.signers.pdf_cms import Signer
from pyhanko_certvalidator.registry import SimpleCertificateStore

from app.domain.exceptions.domain_errors import ConfigurationError, ValidationError
from app.domain.ports.output.HSMClient import HSMClient
from app.domain.ports.output.PAdESSigner import PAdESSigner

_FIELD_NAME = "Signature1"  # v1 is single-signer; no collision risk yet.
_DIGEST_ALGORITHM = "sha256"  # must match hsm-service's fixed mechanism.
_PDF_MAGIC = b"%PDF-"

# ECDSA's DER-encoded signature length varies by a byte or two depending
# on whether r/s need a leading zero. There is no real-world ECDSA
# certificate in this system yet (IssueCertificateRequest defaults to
# RSA; ECDSA is accepted but unused in practice) — this is a generous
# fixed overestimate, not a precise bound, flagged explicitly rather
# than silently assumed correct. Revisit if/when ECDSA certs are issued.
_ECDSA_PLACEHOLDER_OVERHEAD_BYTES = 16


def _signature_byte_length(leaf_cert_pem: str) -> int:
    public_key = load_pem_x509_certificate(leaf_cert_pem.encode("utf-8")).public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return (public_key.key_size + 7) // 8
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        coordinate_bytes = (public_key.curve.key_size + 7) // 8
        return 2 * coordinate_bytes + _ECDSA_PLACEHOLDER_OVERHEAD_BYTES
    raise ConfigurationError(
        f"Unsupported public key type for PAdES signing: {type(public_key)!r}"
    )


class _HsmBackedSigner(Signer):
    def __init__(
        self,
        signing_cert,
        cert_registry,
        key_id,
        hsm_client,
        bearer_token,
        placeholder_length: int,
    ):
        super().__init__(
            signing_cert=signing_cert,
            cert_registry=cert_registry,
            embed_roots=False,  # belt-and-suspenders: we never register a root anyway.
        )
        self._key_id = key_id
        self._hsm_client = hsm_client
        self._bearer_token = bearer_token
        self._placeholder_length = placeholder_length

    async def async_sign_raw(
        self, data: bytes, digest_algorithm: str, dry_run: bool = False
    ) -> bytes:
        if digest_algorithm.lower() != _DIGEST_ALGORITHM:
            raise ConfigurationError(
                "hsm-service only supports SHA-256 signing "
                f"(got digest_algorithm={digest_algorithm!r})"
            )
        if dry_run:
            return b"\0" * self._placeholder_length
        # hsm-service hashes internally — `data` must stay raw (see
        # HSMClient.sign_hash's own docstring on the double-hashing bug
        # this would otherwise reproduce).
        return await self._hsm_client.sign_hash(self._key_id, data, self._bearer_token)


class PyHankoPAdESSigner(PAdESSigner):
    async def sign_pdf(
        self,
        document: bytes,
        leaf_cert_pem: str,
        chain_pems: List[str],
        key_id: UUID,
        hsm_client: HSMClient,
        bearer_token: str,
    ) -> bytes:
        if not document.startswith(_PDF_MAGIC):
            raise ValidationError(
                "document_b64 does not decode to a PDF (missing %PDF- header)",
                field="document_b64",
            )

        leaf_cert = next(load_certs_from_pemder_data(leaf_cert_pem.encode("utf-8")))
        cert_registry = SimpleCertificateStore()
        for pem in chain_pems:
            cert_registry.register(
                next(load_certs_from_pemder_data(pem.encode("utf-8")))
            )

        signer = _HsmBackedSigner(
            signing_cert=leaf_cert,
            cert_registry=cert_registry,
            key_id=key_id,
            hsm_client=hsm_client,
            bearer_token=bearer_token,
            placeholder_length=_signature_byte_length(leaf_cert_pem),
        )

        try:
            writer = IncrementalPdfFileWriter(io.BytesIO(document))
        except PdfError as exc:
            raise ValidationError(
                f"document_b64 is not a well-formed PDF: {exc}",
                field="document_b64",
            ) from exc

        metadata = PdfSignatureMetadata(
            field_name=_FIELD_NAME,
            md_algorithm=_DIGEST_ALGORITHM,
            subfilter=SigSeedSubFilter.PADES,
        )
        try:
            out = await async_sign_pdf(writer, metadata, signer=signer)
        except PdfError as exc:
            raise ValidationError(
                f"document_b64 is not a well-formed PDF: {exc}",
                field="document_b64",
            ) from exc
        return out.getvalue()
