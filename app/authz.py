"""Access rules for notification preferences.

Pure decisions over (caller claims, target record) — no HTTP, no database.
Deny by default: a caller is allowed only when one of the rules below
explicitly grants it.
"""
from uuid import UUID

from app.errors import AccessDenied
from app.models.auth import TokenClaims

ADMIN_ROLE = "admin"


def ensure_can_access(claims: TokenClaims, target_user_id: UUID, target_tenant_id: UUID) -> None:
    """Raise AccessDenied with a specific reason unless `claims` may read and
    update the preferences of `target_user_id`, which belongs to
    `target_tenant_id`.

    Rules, in order:
      1. Tenant isolation applies to every role without exception: the
         caller's tenant must match the record's tenant.
      2. A tenant admin may reach any user inside their own tenant.
      3. Any other role (including unknown roles) may only reach their own
         record.
    """
    if claims.tenant_id != target_tenant_id:
        raise AccessDenied(
            "This record belongs to a different tenant; cross-tenant access is "
            "not allowed for any role."
        )
    if claims.role == ADMIN_ROLE:
        return
    if claims.user_id == target_user_id:
        return
    raise AccessDenied(
        "Only the record owner or an admin of the same tenant may access "
        "these preferences."
    )
