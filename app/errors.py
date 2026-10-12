"""Domain error types and their translation to HTTP responses.

The service and policy layers raise these exceptions to state *why* a request
was refused; `register_exception_handlers` is the single place that maps them
to status codes, so the rules themselves stay free of request-handling code.
"""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


class PreferencesError(Exception):
    """Base class for every refusal raised by the preferences domain."""


class RecordNotFound(PreferencesError):
    def __init__(self, user_id):
        self.user_id = user_id
        super().__init__(f"Preferences not found for user {user_id}")


class AccessDenied(PreferencesError):
    """The caller is authenticated but not entitled to this record."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


class PreconditionRequired(PreferencesError):
    """The request omitted the concurrency precondition it needed."""


class VersionConflict(PreferencesError):
    """The record changed since the caller last read it."""


_STATUS_BY_ERROR = {
    RecordNotFound: 404,
    AccessDenied: 403,
    PreconditionRequired: 428,
    VersionConflict: 412,
}


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(PreferencesError)
    async def handle_preferences_error(request: Request, exc: PreferencesError):
        status_code = _STATUS_BY_ERROR.get(type(exc), 400)
        return JSONResponse(status_code=status_code, content={"detail": str(exc)})
