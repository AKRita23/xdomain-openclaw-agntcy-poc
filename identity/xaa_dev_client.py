"""
xaa.dev protocol client.

xaa.dev is Okta's official Cross-App Access (XAA) playground. This module
implements the three-step XAA protocol against xaa.dev endpoints, used as
the PoC's XAA provider while the production Okta tenant's audience config
is pending vendor support. All requests use ``client_secret_post`` (form
body), never HTTP Basic auth.

Protocol steps:

  1A. Authorize — browser GET to ``{idp_url}/authorize`` with PKCE.
      (URL construction only; no HTTP call from here.)
  1B. Code exchange — POST ``{idp_url}/token`` with
      ``grant_type=authorization_code`` to obtain the user's ID token.
  2.  Token exchange — POST ``{idp_url}/token`` with
      ``grant_type=urn:ietf:params:oauth:grant-type:token-exchange`` and
      ``requested_token_type=...:id-jag`` to mint the ID-JAG assertion.
  3.  JWT Bearer — POST ``{auth_server_url}/token`` (different host!) with
      ``grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`` to redeem
      the ID-JAG for a scoped access token.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import httpx

logger = logging.getLogger(__name__)


TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
ID_JAG_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id-jag"
ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token"
DEFAULT_HTTP_TIMEOUT_SECONDS = 30.0


class XAADevError(Exception):
    """Raised when a xaa.dev request returns a non-200 response.

    Carries the HTTP ``status_code``, the request URL, the parsed OAuth
    ``error`` code (if the response was JSON), and the raw response body
    for debugging.
    """

    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        response_body: str = "",
        request_url: str = "",
        error_code: str = "",
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body
        self.request_url = request_url
        self.error_code = error_code


def generate_pkce_pair() -> tuple[str, str]:
    """Return a ``(code_verifier, code_challenge)`` PKCE pair.

    The verifier is 64 bytes of urlsafe random; the challenge is the
    ``S256`` hash (urlsafe-base64, no padding) per RFC 7636.
    """
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


@dataclass
class XAADevConfig:
    """Static configuration for :class:`XAADevClient`."""

    idp_url: str
    auth_server_url: str
    client_id: str
    client_secret: str
    resource_client_id: str
    resource_client_secret: str
    redirect_uri: str
    resource_audience: str
    scope: str = "openid email"


class XAADevClient:
    """Client for the xaa.dev XAA protocol (auth-code + token-exchange + jwt-bearer).

    Credentials are always sent in the form body (``client_secret_post``);
    ``Authorization: Basic …`` is never used because xaa.dev rejects it.
    """

    def __init__(
        self,
        config: XAADevConfig,
        http_timeout_seconds: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
    ) -> None:
        self.config = config
        self._timeout = http_timeout_seconds

    async def build_authorize_url(
        self, state: str, code_challenge: str,
    ) -> str:
        """Construct the Step 1A browser authorize URL with PKCE + state."""
        params = {
            "response_type": "code",
            "scope": self.config.scope,
            "redirect_uri": self.config.redirect_uri,
            "client_id": self.config.client_id,
            "code_challenge_method": "S256",
            "code_challenge": code_challenge,
            "state": state,
        }
        return f"{self.config.idp_url}/authorize?{urlencode(params)}"

    async def exchange_code_for_id_token(
        self, code: str, code_verifier: str,
    ) -> Dict[str, Any]:
        """Step 1B — exchange the authorization code for an ID token."""
        url = f"{self.config.idp_url}/token"
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.config.redirect_uri,
            "code_verifier": code_verifier,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }
        logger.info(
            "[xaa.dev] Step 1B: POST %s grant=authorization_code client_id=%s",
            url, self.config.client_id,
        )
        return await self._post_form(url, form)

    async def exchange_id_token_for_id_jag(
        self, id_token: str,
    ) -> Dict[str, Any]:
        """Step 2 — token-exchange the ID token for an ID-JAG assertion."""
        url = f"{self.config.idp_url}/token"
        form = {
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "requested_token_type": ID_JAG_TOKEN_TYPE,
            "subject_token_type": ID_TOKEN_TYPE,
            "subject_token": id_token,
            "audience": self.config.auth_server_url,
            "resource": self.config.resource_audience,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }
        logger.info(
            "[xaa.dev] Step 2: POST %s grant=token-exchange audience=%s resource=%s",
            url, self.config.auth_server_url, self.config.resource_audience,
        )
        return await self._post_form(url, form)

    async def exchange_id_jag_for_access_token(
        self, id_jag: str,
    ) -> Dict[str, Any]:
        """Step 3 — JWT Bearer grant to redeem the ID-JAG for an access token.

        Note: this hits ``auth_server_url``, a different host from Steps 1
        and 2, and uses the **resource** client credentials (distinct from
        the main client used for 1B and 2).
        """
        url = f"{self.config.auth_server_url}/token"
        form = {
            "grant_type": JWT_BEARER_GRANT,
            "assertion": id_jag,
            "client_id": self.config.resource_client_id,
            "client_secret": self.config.resource_client_secret,
        }
        logger.info(
            "[xaa.dev] Step 3: POST %s grant=jwt-bearer resource_client_id=%s",
            url, self.config.resource_client_id,
        )
        return await self._post_form(url, form)

    async def _post_form(
        self, url: str, form: Dict[str, str],
    ) -> Dict[str, Any]:
        """POST a form-encoded body and return the JSON response dict.

        On non-200, raises :class:`XAADevError` with the parsed OAuth error
        code (if the body is JSON) plus the raw body for debugging.
        """
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(url, data=form, headers=headers)
        except httpx.HTTPError as exc:
            raise XAADevError(
                message=f"xaa.dev request to {url} failed: {exc}",
                request_url=url,
            ) from exc

        if resp.status_code != 200:
            error_code = ""
            body_text = resp.text
            try:
                body = resp.json()
                error_code = body.get("error", "") or ""
                description = body.get("error_description", "") or ""
            except ValueError:
                description = body_text[:500]

            raise XAADevError(
                message=(
                    f"xaa.dev returned HTTP {resp.status_code} at {url}: "
                    f"{error_code or description or body_text[:200]}"
                ),
                status_code=resp.status_code,
                response_body=body_text,
                request_url=url,
                error_code=error_code,
            )

        try:
            return resp.json()
        except ValueError as exc:
            raise XAADevError(
                message=f"xaa.dev response at {url} was not JSON: {exc}",
                status_code=resp.status_code,
                response_body=resp.text,
                request_url=url,
            ) from exc
