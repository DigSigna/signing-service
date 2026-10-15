"""A completed signature, spanning two tables in the shared schema
(migration 003 of the `migrations` repo): `signing_requests` (the
request-level record — tenant/owner/document identity) and `signatures`
(the cryptographic artifact itself). Flattened into one entity here
because this service always writes both rows together, atomically, in
one call — there is no partial/pending state yet (that would require
async signing, which doesn't exist); see
SignatureRecordRepository.create()."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID


@dataclass
class SignatureRecord:
    id: UUID  # signing_requests.id
    tenant_id: UUID
    key_id: UUID
    certificate_id: UUID
    document_hash: str  # SHA-256, hex (64 chars) — signing_requests.document_hash
    hash_algorithm: str
    signature_id: UUID  # signatures.id
    # The complete signed PDF (PAdES-B: original document + an
    # incremental update embedding the CMS signature), not a detached
    # signature blob — see PAdESSigner. signatures.signature_value is
    # LONGBLOB (migration 024) for exactly this reason.
    signature_value: bytes
    signature_format: str
    signing_time: datetime
    document_name: Optional[str] = None
    user_id: Optional[UUID] = None
    organization_id: Optional[UUID] = None
