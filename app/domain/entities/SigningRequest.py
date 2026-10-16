"""The N-signer aggregate (signing-plan.md point 4): groups a document
and the process of collecting `signers_number` incremental signatures
over it. `document_blob` is always the current full PDF state (original
document plus every incremental signature applied so far) — the only
supported way to read it back is GET /signing-requests/{id}; it is
never reconstructed from `signatures` rows (point 5).

`version` backs optimistic concurrency on the signatures_count/
document_blob update (see SigningRequestRepository.append_signature) —
two /sign calls racing on the same signing_request_id must not silently
drop one signer's work via last-write-wins.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID

from app.domain.valueobjects.SigningRequestStatus import SigningRequestStatus


@dataclass
class SigningRequest:
    id: UUID
    tenant_id: UUID
    document_name: Optional[str]
    document_hash: str  # SHA-256, hex — of the originally submitted document
    hash_algorithm: str
    signers_number: int
    signatures_count: int
    status: SigningRequestStatus
    document_blob: Optional[bytes]
    user_id: Optional[UUID]
    organization_id: Optional[UUID]
    created_at: datetime
    completed_at: Optional[datetime]
    version: int

    def is_final_signature(self) -> bool:
        return self.signatures_count + 1 >= self.signers_number
