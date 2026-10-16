"""Produces a real PAdES-B signature embedded in a PDF via an
incremental update — signing-plan.md point 1: replaces the earlier
"RAW" output (a detached signature over the whole file), which never
produced a standards-compliant PDF signature at all.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional
from uuid import UUID

from app.domain.ports.output.HSMClient import HSMClient


@dataclass
class PAdESSignResult:
    signed_document: bytes
    # "PAdES-T" when a real RFC 3161 token got embedded, "PAdES-B"
    # when it fell back to a local pseudo-timestamp — matches
    # signatures.signature_format's ENUM (migration 025; the original
    # migration-003 ENUM only had PKCS7/CMS/RAW/JWS, none of which
    # describe a PAdES signature at all).
    signature_format: str
    # None when no real TSA could be reached (signing-plan.md point 3):
    # a local pseudo-timestamp was used instead, and tsa_token stays
    # None rather than holding something that looks like a real RFC
    # 3161 token but isn't one.
    tsa_provider: Optional[str]
    tsa_token: Optional[bytes]
    tsa_sealed_at: datetime


class PAdESSigner(ABC):
    @abstractmethod
    async def sign_pdf(
        self,
        document: bytes,
        leaf_cert_pem: str,
        chain_pems: List[str],
        key_id: UUID,
        hsm_client: HSMClient,
        bearer_token: str,
    ) -> PAdESSignResult:
        """Produces the complete signed PDF (the original document plus
        an incremental update containing the PAdES-B signature) and
        attempts to timestamp the signature itself (ADR-002/signing-
        plan.md point 3) — never the document or its hash, and only
        ever *after* signing, since a signature timestamp's message
        imprint is computed over the signature value, which doesn't
        exist beforehand.

        If every configured TSA is unreachable, this does not fail or
        block the signature: it falls back to a local pseudo-timestamp
        (PAdESSignResult.tsa_provider="local-pseudo", tsa_token=None)
        and the signed PDF still comes back as a valid PAdES-B
        signature, just without an embedded RFC 3161 token. The caller
        persists tsa_provider/tsa_token/tsa_sealed_at verbatim —
        tsa_provider == "local-pseudo" is the marker a future re-seal
        job would query for; building that job is explicitly out of
        scope here (signing-plan.md point 3's own text).

        The actual signature is produced by calling
        hsm_client.sign_hash(key_id, ..., bearer_token) one or more
        times during the signing process — hsm_client is a stateless,
        reusable port (same one SignDocumentUseCaseImpl already holds),
        passed per-call rather than at construction, so this adapter
        itself stays a long-lived singleton with no per-request state.

        chain_pems are the non-leaf certificates to embed (leaf +
        intermediate for v1 — never the root; see
        IntermediateCertificateCache). Raises ValidationError
        (field="document_b64") if `document` is not a well-formed PDF.
        """
        raise NotImplementedError
