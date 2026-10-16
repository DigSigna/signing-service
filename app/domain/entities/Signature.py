"""One signer's completed cryptographic artifact, belonging to a
SigningRequest (1:N since migration 026 — signing-plan.md point 4).

`signature_value` holds only this signer's incremental delta — the
bytes pyHanko appended to the PDF for this specific signature, not a
redundant full-document snapshot. PDF incremental updates are strictly
append-only, so `delta = document_after[len(document_before):]` is
exactly that signer's contribution. This is deliberate, not an
oversight: signing-plan.md point 5 explicitly rules out persisting a
per-signer "document as it stood when I signed" snapshot — the only
full document that exists is SigningRequest.document_blob, read back
solely via GET /signing-requests/{id}. This table is for traceability
(point 5, bullet 1), never for reconstructing the document.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID


@dataclass
class Signature:
    id: UUID
    signing_request_id: UUID
    key_id: UUID
    certificate_id: UUID
    signature_value: bytes  # this signer's incremental delta only — see docstring
    signature_format: str
    signing_time: datetime
    # None when this signature wasn't the final one in a multi-signer
    # request (sealing is deferred to the signer that completes the
    # request — signing-plan.md point 4.2); "local-pseudo" when sealing
    # was attempted (this was the final signature) but every TSA failed.
    tsa_provider: Optional[str] = None
    tsa_token: Optional[bytes] = None
    tsa_sealed_at: Optional[datetime] = None
