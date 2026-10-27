"""PAdES-B signing via pyHanko (signing-plan.md point 1), with an
RFC 3161 signature timestamp attempt (ADR-002/signing-plan.md point 3).

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
from datetime import datetime, timezone
from typing import Callable, List, Optional
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import load_pem_x509_certificate
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.misc import PdfError
from pyhanko.sign import PdfSignatureMetadata, async_sign_pdf
from pyhanko.sign.fields import SigSeedSubFilter
from pyhanko.sign.general import SigningError, load_certs_from_pemder_data
from pyhanko.sign.signers.pdf_cms import Signer
from pyhanko.sign.timestamps import TimeStamper
from pyhanko_certvalidator.registry import SimpleCertificateStore

from app.domain.exceptions.domain_errors import ConfigurationError, ValidationError
from app.domain.ports.output.HSMClient import HSMClient
from app.domain.ports.output.PAdESSigner import PAdESSigner, PAdESSignResult
from app.infrastructure.crypto.fallback_timestamper import AllTsaProvidersFailedError

_DIGEST_ALGORITHM = "sha256"  # must match hsm-service's fixed mechanism.
_PDF_MAGIC = b"%PDF-"
_LOCAL_PSEUDO_PROVIDER = "local-pseudo"
_FORMAT_WITH_TIMESTAMP = "PAdES-T"
_FORMAT_WITHOUT_TIMESTAMP = "PAdES-B"

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
    def __init__(self, timestamper_factory: Optional[Callable[[], TimeStamper]] = None):
        """timestamper_factory, if given, is called once per sign_pdf()
        — never reused across calls — to get a *fresh* TimeStamper
        instance (see the comment at its call site for why reuse across
        concurrent requests would race). None means no TSA is configured
        at all: every signature is immediately recorded as a local
        pseudo-timestamp, same outcome as every candidate failing.
        Decoupled from FallbackChainTimeStamper on purpose — this class
        doesn't need to know there's a fallback chain behind it, only
        that it gets a TimeStamper (or doesn't)."""
        self._timestamper_factory = timestamper_factory

    async def sign_pdf(
        self,
        document: bytes,
        leaf_cert_pem: str,
        chain_pems: List[str],
        key_id: UUID,
        hsm_client: HSMClient,
        bearer_token: str,
        field_name: str = "Signature1",
        apply_timestamp: bool = True,
    ) -> PAdESSignResult:
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
        placeholder_length = _signature_byte_length(leaf_cert_pem)

        def _build_signer() -> _HsmBackedSigner:
            return _HsmBackedSigner(
                signing_cert=leaf_cert,
                cert_registry=cert_registry,
                key_id=key_id,
                hsm_client=hsm_client,
                bearer_token=bearer_token,
                placeholder_length=placeholder_length,
            )

        metadata = PdfSignatureMetadata(
            field_name=field_name,
            md_algorithm=_DIGEST_ALGORITHM,
            subfilter=SigSeedSubFilter.PADES,
        )

        if not apply_timestamp:
            # An intermediate signer in a multi-signer request
            # (signing-plan.md point 4.2) — sealing is deferred to
            # whichever call completes the request. Nothing was
            # attempted, so tsa_provider/tsa_token stay None rather than
            # "local-pseudo" (that string specifically means "attempted
            # and every TSA failed").
            out = await self._attempt(document, metadata, _build_signer(), None)
            tsa_provider, tsa_token = None, None
        else:
            # A fresh TimeStamper per call, never a shared/reused
            # instance: pyHanko's own dry-run size-estimation pass also
            # calls it (TimeStamper.async_dummy_response), and
            # FallbackChainTimeStamper tracks which delegate won as
            # *instance* state, read right after async_sign_pdf()
            # returns — sharing one across concurrent requests would
            # let one request's result clobber another's between the
            # real call and the read, since async_sign_pdf awaits
            # multiple times after obtaining the token.
            timestamper = (
                self._timestamper_factory() if self._timestamper_factory else None
            )
            try:
                out = await self._attempt(
                    document, metadata, _build_signer(), timestamper
                )
            except AllTsaProvidersFailedError:
                # Every TSA candidate failed: fall back to an
                # un-timestamped PAdES-B signature rather than blocking
                # the signing operation (signing-plan.md point 3). A
                # fresh writer/signer for the retry — the failed
                # attempt's writer may already have mutated internal
                # state.
                out = await self._attempt(document, metadata, _build_signer(), None)
                tsa_provider, tsa_token = _LOCAL_PSEUDO_PROVIDER, None
            else:
                provider = getattr(timestamper, "last_provider", None)
                if provider is not None:
                    tsa_provider = provider
                    tsa_token = getattr(timestamper, "last_token_der", None)
                else:
                    tsa_provider, tsa_token = _LOCAL_PSEUDO_PROVIDER, None

        signature_format = (
            _FORMAT_WITH_TIMESTAMP
            if tsa_token is not None
            else _FORMAT_WITHOUT_TIMESTAMP
        )
        return PAdESSignResult(
            signed_document=out.getvalue(),
            signature_format=signature_format,
            tsa_provider=tsa_provider,
            tsa_token=tsa_token,
            tsa_sealed_at=datetime.now(timezone.utc),
        )

    @staticmethod
    async def _attempt(
        document: bytes,
        metadata: PdfSignatureMetadata,
        signer: _HsmBackedSigner,
        timestamper: Optional[TimeStamper],
    ):
        try:
            # strict=False: many real-world PDFs (Chrome print-to-PDF,
            # LibreOffice, older Acrobat compatibility settings) carry a
            # hybrid cross-reference section for backward compatibility.
            # pyHanko refuses to append an incremental update to those in
            # strict mode (SigningError below) even though the structure
            # itself is spec-valid — only non-strict parsing tolerates it.
            writer = IncrementalPdfFileWriter(io.BytesIO(document), strict=False)
            return await async_sign_pdf(
                writer, metadata, signer=signer, timestamper=timestamper
            )
        except PdfError as exc:
            raise ValidationError(
                f"document_b64 is not a well-formed PDF: {exc}",
                field="document_b64",
            ) from exc
        except SigningError as exc:
            raise ValidationError(
                f"document_b64 cannot be signed: {exc}",
                field="document_b64",
            ) from exc
