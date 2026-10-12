from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Response

from app.concurrency import etag_for
from app.middleware.auth import decode_token
from app.models.auth import TokenClaims
from app.models.preferences import NotificationPreferences, PreferencesResponse, PreferencesUpdateRequest
from app.services.preferences_service import apply_preference_updates, fetch_user_preferences

router = APIRouter()


def _respond(prefs: NotificationPreferences, response: Response) -> PreferencesResponse:
    response.headers["ETag"] = etag_for(prefs.version)
    return PreferencesResponse(
        user_id=prefs.user_id,
        email_enabled=prefs.email_enabled,
        sms_enabled=prefs.sms_enabled,
        push_enabled=prefs.push_enabled,
        frequency=prefs.frequency,
    )


@router.get("/users/{user_id}/preferences", response_model=PreferencesResponse)
def get_preferences(
    user_id: UUID,
    response: Response,
    claims: TokenClaims = Depends(decode_token),
):
    return _respond(fetch_user_preferences(claims, user_id), response)


@router.put("/users/{user_id}/preferences", response_model=PreferencesResponse)
def update_preferences(
    user_id: UUID,
    body: PreferencesUpdateRequest,
    response: Response,
    claims: TokenClaims = Depends(decode_token),
    if_match: Optional[str] = Header(default=None, alias="If-Match"),
):
    return _respond(apply_preference_updates(claims, user_id, body, if_match), response)
