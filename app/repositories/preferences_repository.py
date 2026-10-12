from typing import Optional
from uuid import UUID

from app.database import get_db
from app.models.preferences import NotificationPreferences

_COLUMNS = "user_id, tenant_id, email_enabled, sms_enabled, push_enabled, frequency, version"


def get_preferences_by_user(user_id: UUID) -> Optional[NotificationPreferences]:
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT {_COLUMNS} FROM notification_preferences WHERE user_id = %s",
                (str(user_id),),
            )
            row = cur.fetchone()
            return NotificationPreferences(**row) if row else None


def update_preferences_if_current(
    user_id: UUID,
    tenant_id: UUID,
    expected_version: int,
    updates: dict,
) -> Optional[NotificationPreferences]:
    """Apply `updates` only if the row is still at `expected_version`.

    The version guard lives in the WHERE clause and the increment in the SET
    clause of one statement, so two racing updates built from the same
    snapshot can never both apply: the winner bumps the version, the loser
    matches zero rows and gets None. The tenant scope is defense in depth on
    top of the authorization layer.
    """
    # Column names come from a validated Pydantic model, never from user input.
    set_clauses = ", ".join(f"{key} = %s" for key in updates)
    values = list(updates.values())

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"UPDATE notification_preferences "
                f"SET {set_clauses}, version = version + 1, updated_at = NOW() "
                f"WHERE user_id = %s AND tenant_id = %s AND version = %s "
                f"RETURNING {_COLUMNS}",
                values + [str(user_id), str(tenant_id), expected_version],
            )
            row = cur.fetchone()
            return NotificationPreferences(**row) if row else None
