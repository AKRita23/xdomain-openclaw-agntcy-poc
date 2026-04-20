"""
Resource Authorization Server for Cross App Access (XAA) PoC.

Validates ID-JAG (ID-Token JWT-Authorization-Grant) assertions issued by Okta
and mints local access tokens for the protected resource.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from threading import Lock
from typing import Any

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Form, HTTPException
from fastapi.responses import JSONResponse
from jose import jwt
from jose.exceptions import JWTError

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("resource-auth-server")

OKTA_ISSUER: str = os.environ["OKTA_ISSUER"].rstrip("/")
RESOURCE_AUDIENCE: str = os.environ["RESOURCE_AUDIENCE"]
REGISTERED_CLIENT_ID: str = os.environ["REGISTERED_CLIENT_ID"]
LOCAL_SIGNING_KEY: str = os.environ["LOCAL_SIGNING_KEY"]
ACCESS_TOKEN_TTL: int = int(os.environ.get("ACCESS_TOKEN_TTL", "3600"))

JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
JWKS_URL = f"{OKTA_ISSUER}/oauth2/v1/keys"
JWKS_TTL_SECONDS = 3600

# TODO: Production deployments must use RS256 with a dedicated signing key pair
# and publish a JWKS endpoint (`/.well-known/jwks.json`) so resource servers can
# verify access tokens without sharing a symmetric secret. HS256 + shared secret
# is a PoC shortcut only.
ACCESS_TOKEN_ALG = "HS256"

app = FastAPI(title="XAA Resource Authorization Server", version="0.1.0")


class JWKSCache:
    """Thread-safe JWKS cache with a single forced-refresh guard per lookup."""

    def __init__(self, url: str, ttl_seconds: int) -> None:
        self._url = url
        self._ttl = ttl_seconds
        self._keys: list[dict[str, Any]] = []
        self._fetched_at: float = 0.0
        self._lock = Lock()

    def _fetch(self) -> None:
        logger.info("fetching JWKS from %s", self._url)
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(self._url)
            resp.raise_for_status()
            payload = resp.json()
        with self._lock:
            self._keys = payload.get("keys", [])
            self._fetched_at = time.time()

    def _is_stale(self) -> bool:
        return (time.time() - self._fetched_at) > self._ttl or not self._keys

    def get_key(self, kid: str, allow_refresh: bool = True) -> dict[str, Any] | None:
        if self._is_stale():
            self._fetch()
        for key in self._keys:
            if key.get("kid") == kid:
                return key
        if allow_refresh:
            logger.info("kid %s not in cached JWKS, forcing refresh", kid)
            self._fetch()
            for key in self._keys:
                if key.get("kid") == kid:
                    return key
        return None


jwks_cache = JWKSCache(JWKS_URL, JWKS_TTL_SECONDS)


def _oauth_error(description: str, error: str = "invalid_grant") -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={"error": error, "error_description": description},
    )


def _validate_id_jag(assertion: str, client_id: str) -> dict[str, Any]:
    """Validate an ID-JAG assertion and return its claims.

    Raises HTTPException(400) with OAuth-style error body on failure.
    """
    try:
        header = jwt.get_unverified_header(assertion)
    except JWTError as exc:
        raise HTTPException(status_code=400, detail=("invalid_grant", f"malformed assertion header: {exc}"))

    kid = header.get("kid")
    if not kid:
        raise HTTPException(status_code=400, detail=("invalid_grant", "assertion header missing kid"))

    key = jwks_cache.get_key(kid)
    if key is None:
        raise HTTPException(status_code=400, detail=("invalid_grant", "no matching signing key for kid"))

    try:
        claims = jwt.decode(
            assertion,
            key,
            algorithms=["RS256"],
            audience=RESOURCE_AUDIENCE,
            issuer=OKTA_ISSUER,
        )
    except JWTError as exc:
        raise HTTPException(status_code=400, detail=("invalid_grant", f"assertion signature/claims invalid: {exc}"))

    asserted_client = claims.get("client_id") or claims.get("azp")
    if asserted_client != REGISTERED_CLIENT_ID:
        raise HTTPException(
            status_code=400,
            detail=("invalid_grant", "assertion client_id/azp does not match registered client"),
        )
    if client_id != REGISTERED_CLIENT_ID:
        raise HTTPException(
            status_code=400,
            detail=("invalid_client", "client_id does not match registered client"),
        )
    if not claims.get("sub"):
        raise HTTPException(status_code=400, detail=("invalid_grant", "assertion missing sub claim"))

    return claims


def _mint_access_token(claims: dict[str, Any]) -> tuple[str, int]:
    now = int(time.time())
    exp = now + ACCESS_TOKEN_TTL
    payload = {
        "iss": RESOURCE_AUDIENCE,
        "aud": RESOURCE_AUDIENCE,
        "sub": claims["sub"],
        "client_id": REGISTERED_CLIENT_ID,
        "scope": claims.get("scope", ""),
        "iat": now,
        "exp": exp,
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(payload, LOCAL_SIGNING_KEY, algorithm=ACCESS_TOKEN_ALG)
    return token, ACCESS_TOKEN_TTL


@app.exception_handler(HTTPException)
async def _oauth_exception_handler(_, exc: HTTPException) -> JSONResponse:
    if exc.status_code == 400 and isinstance(exc.detail, tuple) and len(exc.detail) == 2:
        error, description = exc.detail
        logger.warning("token request rejected: %s - %s", error, description)
        return _oauth_error(description, error=error)
    return JSONResponse(status_code=exc.status_code, content={"error": "server_error", "error_description": str(exc.detail)})


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/.well-known/oauth-authorization-server")
def oauth_metadata() -> dict[str, Any]:
    return {
        "issuer": RESOURCE_AUDIENCE,
        "token_endpoint": f"{RESOURCE_AUDIENCE}/oauth2/token",
        "grant_types_supported": [JWT_BEARER_GRANT],
        "scopes_supported": ["read", "write"],
        "token_endpoint_auth_methods_supported": ["none"],
    }


@app.post("/oauth2/token")
def token_endpoint(
    grant_type: str = Form(...),
    assertion: str = Form(...),
    client_id: str = Form(...),
) -> dict[str, Any]:
    if grant_type != JWT_BEARER_GRANT:
        raise HTTPException(
            status_code=400,
            detail=("unsupported_grant_type", f"grant_type must be {JWT_BEARER_GRANT}"),
        )

    claims = _validate_id_jag(assertion, client_id)
    access_token, ttl = _mint_access_token(claims)
    logger.info("issued access token for sub=%s client_id=%s", claims["sub"], REGISTERED_CLIENT_ID)
    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ttl,
        "scope": claims.get("scope", ""),
    }
