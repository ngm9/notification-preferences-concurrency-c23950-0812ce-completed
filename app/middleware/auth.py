from typing import Optional

from fastapi import Header, HTTPException
from jose import JWTError, jwt

from app.config import settings
from app.models.auth import TokenClaims


def decode_token(authorization: Optional[str] = Header(default=None)) -> TokenClaims:
    """Authenticate the caller from the Authorization header.

    Every failure mode — missing header, wrong scheme, bad signature,
    expired token, missing or wrongly-typed claims — is a 401. Malformed
    claims must surface as 401, not crash into a 500.
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    # The auth scheme is case-insensitive per RFC 7235.
    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise HTTPException(
            status_code=401,
            detail="Authorization header must be a Bearer token",
        )

    token = parts[1].strip()
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            options={"require_exp": settings.jwt_require_exp},
        )
        return TokenClaims(
            user_id=payload["user_id"],
            tenant_id=payload["tenant_id"],
            role=payload["role"],
        )
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    # KeyError: a required claim is absent. ValueError/TypeError: a claim has
    # the wrong shape (pydantic's ValidationError subclasses ValueError).
    except (KeyError, TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Token claims are malformed")
