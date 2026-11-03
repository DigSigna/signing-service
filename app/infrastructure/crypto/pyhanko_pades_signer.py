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
from binascii import hexlify
from datetime import datetime, timezone
from typing import Callable, List, Optional, Tuple
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.layout import BoxConstraints
from pyhanko.pdf_utils.misc import PdfError, rd
from pyhanko.pdf_utils.rw_common import find_inherited_value_in_tree
from pyhanko.pdf_utils.text import TextBoxStyle
from pyhanko.pdf_utils.writer import PageObject
from pyhanko.sign import PdfSignatureMetadata
from pyhanko.sign.fields import SigFieldSpec, SigSeedSubFilter
from pyhanko.sign.general import SigningError, load_certs_from_pemder_data
from pyhanko.sign.signers.pdf_cms import Signer
from pyhanko.sign.signers.pdf_signer import PdfSigner
from pyhanko.sign.timestamps import TimeStamper
from pyhanko.stamp import QRPosition, QRStampStyle, TextStampStyle
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

# Visible signature appearance (not required for a valid PAdES-B/T
# signature — pyHanko already produces one with zero visual footprint —
# but end users have no way to tell a document was signed just by
# opening it. One combined stamp box (QR + text) per signer, stacked on
# a dedicated appended page, matching the "página de firmas" pattern
# used by other platforms in this space (one box per signer, a QR next
# to the human-readable text) rather than cluttering the original
# content. See docs/signing-plan.md and the task that added this.
#
# Shows the signer's tenant (the actual organization this signature is
# under — this platform is multi-tenant SaaS, so there's no single
# platform-wide brand name that means anything on a specific tenant's
# document) and the root CA's name (chain.chain[-1] from
# CertificateClient.validate_chain — see signing_core.perform_signature_step)
# rather than any generic text. Both are UI only, same as the rest of
# this appearance — never anything a signature validator checks.
_STAMP_BOX_WIDTH = 320
_STAMP_BOX_HEIGHT = 110
_STAMP_MARGIN = 36
_STAMP_ROW_GAP = 20
_UNKNOWN_ROOT_CA = "N/D"

# Small per-page label repeating the same verification code on every
# page the document had *before* signing (not the appended signatures
# page itself, which already shows it prominently). This is a UI aid
# only — a human skimming a printout can see every page "belongs" to
# the same signed document — not extra cryptographic protection: the
# PAdES byte-range signature already covers 100% of these pages'
# bytes, label included, regardless of whether this label exists.
# (It's technically true that stripping/altering the label post-
# signing would invalidate the signature too, same as altering any
# other byte would — that's a side effect of it being added before
# signing, not a security property this feature was designed to add.)
#
# Run vertically along the left margin (same placement the reference
# document uses) rather than horizontally in a page corner: a corner
# label big enough to read legibly collides with real documents' own
# footer content (page numbers, folio text); the left margin is
# normally empty space on virtually every document layout.
_SIDE_LABEL_MARGIN = 10
_SIDE_LABEL_THICKNESS = 16
_SIDE_LABEL_MAX_LENGTH = 400


# QRStampStyle's 'url' parameter is only ever turned into a clickable
# /Link annotation by QRStamp.apply() — the entry point for stamping an
# arbitrary standalone page (qr_stamp_file). Signing a PDF never goes
# through that: cms_embedder.SigAppearanceSetup calls
# AppearanceContent.apply_appearance() instead (sets the widget's own
# /AP only), so no Link annotation is ever created here regardless of
# what 'url' holds — confirmed by reading both code paths, not assumed.
# That's what makes it safe to put a plain reference code (the
# SigningRequest id) in 'url' rather than an actual resolvable link:
# verification-service's POST /api/v1/verify needs the full PDF as a
# base64 body, not a GET-by-code lookup a scanned link could hit
# directly, and there is no frontend yet to bridge that gap.
_SIGNATURE_STAMP_STYLE = QRStampStyle(
    stamp_text=(
        "Firmado digitalmente por\n%(signer)s\n%(tenant)s\n"
        "Autoridad certificadora: %(root_ca)s\n"
        "%(ts)s\nCodigo de verificacion: %(url)s"
    ),
    text_box_style=TextBoxStyle(font_size=8),
    qr_position=QRPosition.LEFT_OF_TEXT,
    border_width=1,
)

_SIDE_LABEL_STAMP_STYLE = TextStampStyle(
    stamp_text="Codigo de verificacion: %(code)s",
    text_box_style=TextBoxStyle(font_size=9),
    border_width=0,
)


def _signer_display_name(leaf_cert_pem: str) -> str:
    cert = load_pem_x509_certificate(leaf_cert_pem.encode("utf-8"))
    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return cns[0].value if cns else "Firmante"


def _page_media_box(
    writer: IncrementalPdfFileWriter, page_ix: int
) -> Tuple[float, float, float, float]:
    page_ref, _resources = writer.find_page_for_modification(page_ix)
    mb = find_inherited_value_in_tree(page_ref.get_object(), "/MediaBox", "/Parent")
    if mb is None:
        raise ValidationError(
            "document_b64 is not a well-formed PDF: page is missing /MediaBox",
            field="document_b64",
        )
    return tuple(float(v) for v in mb)


def _append_blank_signatures_page(writer: IncrementalPdfFileWriter) -> None:
    """Appends a new blank page, same size as the document's current
    last page, to hold visible signature stamps — called once, for the
    first signer only (signer_index == 0); later signers in the same
    multi-signer request reuse this page (on_page=-1 always resolves to
    it, since nothing is appended after it)."""
    x0, y0, x1, y1 = _page_media_box(writer, -1)
    blank_contents = writer.add_object(generic.StreamObject(stream_data=b""))
    new_page = PageObject(contents=blank_contents, media_box=[x0, y0, x1, y1])
    writer.insert_page(new_page)


def _ensure_page_has_contents(writer: IncrementalPdfFileWriter, page_ix: int) -> None:
    """A page without /Contents at all is spec-legal (an empty page)
    but not something mainstream PDF producers emit — add_stream_to_page
    (used by BaseStamp.apply() below) assumes an existing /Contents to
    extend. Give it an empty one rather than letting that raise a bare
    KeyError."""
    page_ref, _resources = writer.find_page_for_modification(page_ix)
    page_obj = page_ref.get_object()
    if "/Contents" not in page_obj:
        empty_contents = writer.add_object(generic.StreamObject(stream_data=b""))
        page_obj[generic.pdf_name("/Contents")] = empty_contents
        writer.mark_update(page_ref)


def _apply_rotated(
    stamp, writer: IncrementalPdfFileWriter, dest_page: int, x: float, y: float
) -> None:
    """Same placement BaseStamp.apply() does (register the stamp as a
    Form XObject, paint it via a tiny wrapper content stream added to
    the page) but with a 90-degree counterclockwise rotation baked into
    the placement matrix instead of apply()'s plain translation —
    apply() itself has no rotation parameter. (x, y) is where the
    stamp's own local origin lands after rotating, i.e. its bottom-left
    corner once rotated upright: the label runs from there straight up
    the page, its thickness extending left from x."""
    stamp_ref = stamp.register()
    resource_name = b"/Stamp" + hexlify(uuid4().bytes)
    # [a b c d e f] with a=cos90=0, b=sin90=1, c=-sin90=-1, d=cos90=0:
    # rotates 90 deg CCW, then translates to (x, y).
    stamp_paint = b"q 0 1 -1 0 %g %g cm %s Do Q" % (rd(x), rd(y), resource_name)
    stamp_wrapper_stream = generic.StreamObject(stream_data=stamp_paint)
    resources = generic.DictionaryObject(
        {
            generic.pdf_name("/XObject"): generic.DictionaryObject(
                {generic.pdf_name(resource_name.decode("ascii")): stamp_ref}
            )
        }
    )
    writer.add_stream_to_page(
        dest_page, writer.add_object(stamp_wrapper_stream), resources
    )


def _stamp_footer_on_original_pages(
    writer: IncrementalPdfFileWriter, code: str, original_page_count: int
) -> None:
    """Repeats the verification code, running vertically up the left
    margin, on every page the document had before this (first)
    signature — called once, same signer_index == 0 gate as
    _append_blank_signatures_page. Built on the same standalone-page-
    stamping machinery (BaseStamp.register() + writer.add_stream_to_page,
    what BaseStamp.apply() itself uses) pyHanko's own
    qr_stamp_file/text_stamp_file rely on for stamping an existing page
    — distinct from the signature widget's own appearance, which goes
    through apply_appearance() instead (see _SIGNATURE_STAMP_STYLE's
    comment)."""
    for page_ix in range(original_page_count):
        _ensure_page_has_contents(writer, page_ix)
        x0, y0, x1, y1 = _page_media_box(writer, page_ix)
        length = min(
            _SIDE_LABEL_MAX_LENGTH, max(80.0, (y1 - y0) - 2 * _SIDE_LABEL_MARGIN)
        )
        box = BoxConstraints(width=length, height=_SIDE_LABEL_THICKNESS)
        stamp = _SIDE_LABEL_STAMP_STYLE.create_stamp(writer, box, {"code": code})
        _apply_rotated(
            stamp,
            writer,
            page_ix,
            x0 + _SIDE_LABEL_MARGIN + _SIDE_LABEL_THICKNESS,
            y0 + _SIDE_LABEL_MARGIN,
        )


def _stamp_box(
    page_width: float, page_height: float, signer_index: int
) -> Tuple[float, float, float, float]:
    width = min(_STAMP_BOX_WIDTH, max(120.0, page_width - 2 * _STAMP_MARGIN))
    top_y = (
        page_height
        - _STAMP_MARGIN
        - signer_index * (_STAMP_BOX_HEIGHT + _STAMP_ROW_GAP)
    )
    # Known limitation: stamps stack straight down the page and are not
    # re-flowed into a second column/page once they run past the bottom
    # margin — acceptable for the realistic signer counts this system
    # handles (signing-plan.md point 4), revisit if that changes.
    return (
        _STAMP_MARGIN,
        top_y - _STAMP_BOX_HEIGHT,
        _STAMP_MARGIN + width,
        top_y,
    )


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
        signing_request_id: UUID,
        tenant_name: str,
        field_name: str = "Signature1",
        apply_timestamp: bool = True,
        signer_index: int = 0,
        root_ca_name: Optional[str] = None,
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
        appearance_text_params = {
            "signer": _signer_display_name(leaf_cert_pem),
            "tenant": tenant_name,
            "root_ca": root_ca_name or _UNKNOWN_ROOT_CA,
            # 'url' is QRStampStyle's own parameter name, not a claim
            # that this is a resolvable link — see the comment above
            # _SIGNATURE_STAMP_STYLE.
            "url": str(signing_request_id),
        }

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
            out = await self._attempt(
                document,
                metadata,
                _build_signer(),
                None,
                signer_index,
                appearance_text_params,
            )
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
                    document,
                    metadata,
                    _build_signer(),
                    timestamper,
                    signer_index,
                    appearance_text_params,
                )
            except AllTsaProvidersFailedError:
                # Every TSA candidate failed: fall back to an
                # un-timestamped PAdES-B signature rather than blocking
                # the signing operation (signing-plan.md point 3). A
                # fresh writer/signer for the retry — the failed
                # attempt's writer may already have mutated internal
                # state.
                out = await self._attempt(
                    document,
                    metadata,
                    _build_signer(),
                    None,
                    signer_index,
                    appearance_text_params,
                )
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
        signer_index: int,
        appearance_text_params: dict,
    ):
        try:
            # strict=False: many real-world PDFs (Chrome print-to-PDF,
            # LibreOffice, older Acrobat compatibility settings) carry a
            # hybrid cross-reference section for backward compatibility.
            # pyHanko refuses to append an incremental update to those in
            # strict mode (SigningError below) even though the structure
            # itself is spec-valid — only non-strict parsing tolerates it.
            writer = IncrementalPdfFileWriter(io.BytesIO(document), strict=False)
            if signer_index == 0:
                # First signer only: footer every page the document had
                # up to now, then create the dedicated signatures page.
                # Later signers (signer_index > 0) skip both — the
                # footer is already on every original page and the
                # signatures page already exists, both part of
                # `document` from this first signer's incremental
                # update.
                original_page_count = writer.root["/Pages"]["/Count"]
                _stamp_footer_on_original_pages(
                    writer, appearance_text_params["url"], original_page_count
                )
                _append_blank_signatures_page(writer)
            x0, y0, x1, y1 = _page_media_box(writer, -1)
            bx0, by0, bx1, by1 = _stamp_box(x1 - x0, y1 - y0, signer_index)
            # Offset into the page's own coordinate space — MediaBox
            # isn't guaranteed to start at (0, 0). SigFieldSpec.box
            # wants ints.
            box = (
                round(x0 + bx0),
                round(y0 + by0),
                round(x0 + bx1),
                round(y0 + by1),
            )
            field_spec = SigFieldSpec(
                sig_field_name=metadata.field_name, on_page=-1, box=box
            )
            pdf_signer = PdfSigner(
                metadata,
                signer,
                timestamper=timestamper,
                stamp_style=_SIGNATURE_STAMP_STYLE,
                new_field_spec=field_spec,
            )
            return await pdf_signer.async_sign_pdf(
                writer, appearance_text_params=appearance_text_params
            )
        except (PdfError, KeyError) as exc:
            # KeyError alongside PdfError: a page missing /Contents
            # entirely (spec-legal for a blank page, but not something
            # mainstream PDF producers emit) makes the footer-stamping
            # pass above (add_stream_to_page) raise a bare KeyError
            # rather than pyHanko's own PdfError — same "not usable as
            # a signing target" outcome from the caller's point of view.
            raise ValidationError(
                f"document_b64 is not a well-formed PDF: {exc}",
                field="document_b64",
            ) from exc
        except SigningError as exc:
            raise ValidationError(
                f"document_b64 cannot be signed: {exc}",
                field="document_b64",
            ) from exc
