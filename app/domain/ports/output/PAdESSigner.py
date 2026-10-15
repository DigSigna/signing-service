"""Produces a real PAdES-B signature embedded in a PDF via an
incremental update — signing-plan.md point 1: replaces the earlier
"RAW" output (a detached signature over the whole file), which never
produced a standards-compliant PDF signature at all.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List
from uuid import UUID

from app.domain.ports.output.HSMClient import HSMClient


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
    ) -> bytes:
        """Returns the complete signed PDF (the original document plus
        an incremental update containing the PAdES-B signature).

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
