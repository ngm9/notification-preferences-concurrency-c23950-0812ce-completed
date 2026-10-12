from typing import Optional
from uuid import UUID

from app.authz import ensure_can_access
from app.concurrency import if_match_allows
from app.errors import PreconditionRequired, RecordNotFound, VersionConflict
from app.models.auth import TokenClaims
from app.models.preferences import NotificationPreferences, PreferencesUpdateRequest
from app.repositories.preferences_repository import (
    get_preferences_by_user,
    update_preferences_if_current,
)


def fetch_user_preferences(claims: TokenClaims, user_id: UUID) -> NotificationPreferences:
    prefs = get_preferences_by_user(user_id)
    if prefs is None:
        raise RecordNotFound(user_id)
    ensure_can_access(claims, target_user_id=user_id, target_tenant_id=prefs.tenant_id)
    return prefs


def apply_preference_updates(
    claims: TokenClaims,
    user_id: UUID,
    request: PreferencesUpdateRequest,
    if_match: Optional[str],
) -> NotificationPreferences:
    prefs = get_preferences_by_user(user_id)
    if prefs is None:
        raise RecordNotFound(user_id)
    ensure_can_access(claims, target_user_id=user_id, target_tenant_id=prefs.tenant_id)

    if not if_match or not if_match.strip():
        raise PreconditionRequired(
            "Updates must send an If-Match header with the ETag from a prior "
            "GET, so concurrent edits cannot silently overwrite each other."
        )
    if not if_match_allows(if_match, prefs.version):
        raise VersionConflict(
            f"The record changed since it was read (current version "
            f"{prefs.version}); GET the preferences again and retry with the "
            f"new ETag."
        )

    updates = request.model_dump(exclude_none=True)
    if not updates:
        return prefs  # nothing to change; leave the version untouched

    updated = update_preferences_if_current(user_id, prefs.tenant_id, prefs.version, updates)
    if updated is None:
        # Someone else won the write between our read and our UPDATE.
        raise VersionConflict(
            "The record was updated concurrently; GET the preferences again "
            "and retry with the new ETag."
        )
    return updated
