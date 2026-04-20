"""
Resource server exchange — second half of the Okta XAA (ID-JAG) flow.

After :mod:`identity.okta_xaa` obtains an ID-JAG assertion from Okta, this
module POSTs that assertion to our Resource Authorization Server (see
``resource-auth-server/main.py``) under the RFC 7523 ``jwt-bearer`` grant
type to mint a local, HS256-signed access token the agent can present to the
protected resource.

Flow (Version A, two-org XAA):

    1. Okta issues an ID-JAG (handled by :mod:`identity.okta_xaa`).
    2. Agent POSTs the ID-JAG as ``assertion`` to
       ``{RESOURCE_AUTH_SERVER_URL}/oauth2/token`` — this module.
    3. Resource Auth Server validates the ID-JAG signature against Okta's JWKS
       and returns a short-lived access token scoped to the resource.

This module is intentionally additive — it does not import or modify
:mod:`identity.okta_xaa`. Chaining the two halves is the responsibility of
the agent orchestration code.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Any, Dict, Optional, Tuple

import httpx
import jwt

logger = logging.getLogger(__name__)


DEFAULT_RESOURCE_AUTH_SERVER_URL = "http://18.233.200.161:5001"
DEFAULT_RESOURCE_AUTH_CLIENT_ID = "openclaw-agent"

JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
TOKEN_ENDPOINT_PATH = "/oauth2/token"
DEFAULT_HTTP_TIMEOUT_SECONDS = 10.0


class ResourceExchangeError(Exception):
    """Raised when the resource auth server rejects a token exchange.

    Mirrors the OAuth 2.0 error response shape returned by the resource
    server's ``_oauth_error`` helper (``error`` + ``error_description``).
    """

    def __init__(
        self,
        error: str,
        description: str = "",
        status_code: Optional[int] = None,
    ) -> None:
        msg = f"{error}: {description}" if description else error
        super().__init__(msg)
        self.error = error
        self.description = description
        self.status_code = status_code


class TokenExpiredError(Exception):
    """Raised when a cached or presented access token is past its ``exp``."""

    def __init__(self, exp: int, now: int) -> None:
        super().__init__(f"token expired at {exp} (now={now})")
        self.exp = exp
        self.now = now


@dataclass
class ResourceAccessToken:
    """Access token minted by the Resource Authorization Server.

    Attributes mirror the OAuth 2.0 token response fields. ``expires_at`` is
    a wall-clock Unix timestamp computed at receipt — callers should check
    this rather than ``expires_in`` (which is relative to exchange time).
    """

    access_token: str
    token_type: str
    expires_in: int
    scope: str
    expires_at: int

    def is_expired(self, skew_seconds: int = 0) -> bool:
        return int(time.time()) >= (self.expires_at - skew_seconds)


def _resource_auth_server_url() -> str:
    return os.environ.get(
        "RESOURCE_AUTH_SERVER_URL", DEFAULT_RESOURCE_AUTH_SERVER_URL
    ).rstrip("/")


def _default_client_id() -> str:
    return os.environ.get(
        "RESOURCE_AUTH_CLIENT_ID", DEFAULT_RESOURCE_AUTH_CLIENT_ID
    )


def _parse_oauth_error(resp: httpx.Response) -> ResourceExchangeError:
    """Build a :class:`ResourceExchangeError` from a non-200 token response."""
    error = "server_error"
    description = ""
    try:
        body = resp.json()
    except ValueError:
        description = resp.text[:500]
    else:
        error = body.get("error", error) or error
        description = body.get("error_description", "") or ""
    return ResourceExchangeError(
        error=error, description=description, status_code=resp.status_code
    )


def exchange_id_jag_for_access_token(
    id_jag: str,
    client_id: Optional[str] = None,
    scope: str = "read write",
) -> ResourceAccessToken:
    """Exchange an Okta ID-JAG for a resource-server-issued access token.

    This is the second half of the XAA flow. The ``id_jag`` must be a JWT
    assertion previously obtained from Okta's token endpoint (see
    :class:`identity.okta_xaa.OktaXAAClient`).

    Args:
        id_jag: The ID-JAG JWT assertion issued by Okta.
        client_id: OAuth client id registered with the resource server.
            Defaults to ``$RESOURCE_AUTH_CLIENT_ID``.
        scope: Space-separated scopes requested for the access token.

    Returns:
        A :class:`ResourceAccessToken` populated from the token response,
        with ``expires_at`` computed from receipt time + ``expires_in``.

    Raises:
        ResourceExchangeError: If the server returns a non-200 response.
            ``error`` and ``description`` are populated from the OAuth
            error body when present.
        httpx.HTTPError: For network / transport-level failures.
    """
    resolved_client_id = client_id or _default_client_id()
    url = f"{_resource_auth_server_url()}{TOKEN_ENDPOINT_PATH}"
    form = {
        "grant_type": JWT_BEARER_GRANT,
        "assertion": id_jag,
        "client_id": resolved_client_id,
        "scope": scope,
    }

    logger.info(
        "exchanging ID-JAG at resource auth server url=%s client_id=%s scope=%s",
        url,
        resolved_client_id,
        scope,
    )
    with httpx.Client(timeout=DEFAULT_HTTP_TIMEOUT_SECONDS) as client:
        resp = client.post(
            url,
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    if resp.status_code != 200:
        err = _parse_oauth_error(resp)
        logger.warning(
            "resource exchange rejected status=%s error=%s description=%s",
            err.status_code,
            err.error,
            err.description,
        )
        raise err

    body = resp.json()
    expires_in = int(body.get("expires_in", 0))
    token = ResourceAccessToken(
        access_token=body["access_token"],
        token_type=body.get("token_type", "Bearer"),
        expires_in=expires_in,
        scope=body.get("scope", scope),
        expires_at=int(time.time()) + expires_in,
    )
    logger.info(
        "resource exchange succeeded scope=%s expires_in=%ds",
        token.scope,
        token.expires_in,
    )
    return token


def validate_access_token(token: str) -> Dict[str, Any]:
    """Decode and expiry-check an access token without verifying its signature.

    The resource auth server signs with a symmetric key (HS256) it does not
    share with agents, so agents cannot fully verify locally — they trust the
    token as received over TLS and only perform expiry / claim inspection.
    Production deployments should migrate to RS256 + JWKS so agents can
    cryptographically verify (see the TODO in ``resource-auth-server/main.py``).

    Args:
        token: The access token JWT.

    Returns:
        The decoded claims dict.

    Raises:
        TokenExpiredError: If the ``exp`` claim has already passed.
        jwt.DecodeError: If the token is not a decodable JWT.
    """
    claims = jwt.decode(token, options={"verify_signature": False})
    exp = claims.get("exp")
    if exp is not None:
        now = int(time.time())
        if now >= int(exp):
            raise TokenExpiredError(exp=int(exp), now=now)
    return claims


@dataclass
class CachedTokenStore:
    """In-process cache of resource-server access tokens.

    Keyed by ``(client_id, scope, subject)`` so that distinct delegating
    subjects and scope sets do not share a cache entry. Thread-safe via a
    single lock — contention is not expected since the agent is single-user.

    ``expiry_skew_seconds`` treats tokens within the skew of expiry as
    already expired so callers don't race the exact boundary.
    """

    expiry_skew_seconds: int = 30
    _entries: Dict[Tuple[str, str, str], ResourceAccessToken] = field(
        default_factory=dict
    )
    _lock: Lock = field(default_factory=Lock)

    @staticmethod
    def _key(client_id: str, scope: str, subject: str) -> Tuple[str, str, str]:
        return (client_id, scope, subject)

    def get(
        self, client_id: str, scope: str, subject: str
    ) -> Optional[ResourceAccessToken]:
        """Return a cached token if present and not within the expiry skew."""
        with self._lock:
            entry = self._entries.get(self._key(client_id, scope, subject))
        if entry is None:
            return None
        if entry.is_expired(skew_seconds=self.expiry_skew_seconds):
            logger.info(
                "cache entry expired client_id=%s scope=%s subject=%s",
                client_id,
                scope,
                subject,
            )
            self.invalidate(client_id, scope, subject)
            return None
        return entry

    def set(
        self,
        client_id: str,
        scope: str,
        subject: str,
        token: ResourceAccessToken,
    ) -> None:
        with self._lock:
            self._entries[self._key(client_id, scope, subject)] = token

    def invalidate(self, client_id: str, scope: str, subject: str) -> None:
        with self._lock:
            self._entries.pop(self._key(client_id, scope, subject), None)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
