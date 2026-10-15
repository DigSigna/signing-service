"""Unit tests for DomainError.to_dict().

Regression for a cross-cutting bug: to_dict() only ever serialized the
base message/details, so every subclass's own extra field
(NotFoundError.entity_id, ValidationError.field, ...) was silently
dropped from the HTTP error response — a caller could never actually
learn entity_id, defeating the whole point of that field.
"""

import json
from datetime import datetime, timezone

from app.domain.exceptions.domain_errors import (
    DuplicateRequestError,
    NotFoundError,
    SigningPinInvalidError,
    SigningPinLockedError,
    ValidationError,
)


def test_to_dict_includes_subclass_specific_field():
    error = NotFoundError("key not found", entity="key", entity_id="key-123")

    assert error.to_dict() == {
        "code": "NOT_FOUND",
        "message": "key not found",
        "details": {"entity": "key", "entity_id": "key-123"},
    }


def test_to_dict_merges_subclass_field_with_manual_details():
    error = ValidationError(
        "bad input", details={"extra": "context"}, field="algorithm"
    )

    assert error.to_dict() == {
        "code": "VALIDATION_ERROR",
        "message": "bad input",
        "details": {"field": "algorithm", "extra": "context"},
    }


def test_to_dict_omits_unset_subclass_field():
    error = NotFoundError("not found")  # entity/entity_id left unset (None)

    assert error.to_dict() == {
        "code": "NOT_FOUND",
        "message": "not found",
        "details": {},
    }


def test_to_dict_with_only_base_fields_is_unaffected():
    error = DuplicateRequestError("duplicate", idempotency_key="abc")

    assert error.to_dict() == {
        "code": "DUPLICATE_REQUEST",
        "message": "duplicate",
        "details": {"idempotency_key": "abc"},
    }


def test_to_dict_serializes_remaining_attempts():
    error = SigningPinInvalidError("wrong pin", remaining_attempts=2)

    assert error.to_dict() == {
        "code": "SIGNING_PIN_INVALID",
        "message": "wrong pin",
        "details": {"remaining_attempts": 2},
    }


def test_to_dict_serializes_datetime_field_as_isoformat():
    """locked_until is a raw datetime; json.dumps() (used by
    JSONResponse.render() in ErrorHandlingMiddleware) has no default
    encoder for it and would raise TypeError, turning a 423 lockout
    response into an unhandled error — see the same fix/regression test
    in certificate-service, where this file was copied from."""
    locked_until = datetime(2026, 1, 1, tzinfo=timezone.utc)
    error = SigningPinLockedError("locked", locked_until=locked_until)

    result = error.to_dict()
    assert result == {
        "code": "SIGNING_PIN_LOCKED",
        "message": "locked",
        "details": {"locked_until": "2026-01-01T00:00:00+00:00"},
    }
    json.dumps(result)  # must not raise
