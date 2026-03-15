"""
Okta XAA Token Exchange (ID-JAG — Identity Assertion Authorization Grant).

Implements the Okta Identity Assertion Authorization Grant flow to obtain
domain-specific access tokens for cross-domain delegation.

Flow:
  1. Agent requests an Identity Assertion JWT (ID-JAG) from Okta using
     client_credentials with assertion context.
  2. Agent exchanges the ID-JAG (plus an AGNTCY badge JWT as actor proof)
     for a scoped access token to the target resource application.
"""
import logging
import time
from typing import Any, Dict, List, Optional

import httpx
import jwt

logger = logging.getLogger(__name__)


class TokenExchangeError(Exception):
    """Raised when token exchange fails."""

    def __init__(self, reason: str, status_code: Optional[int] = None,
                 details: Optional[Dict[str, Any]] = None):
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code
        self.details = details or {}


class OktaXAAClient:
    """Handles Okta ID-JAG token exchange for cross-domain access."""

    ID_JAG_GRANT = "urn:okta:params:oauth:grant-type:id-jag"
    CLIENT_CREDENTIALS_GRANT = "client_credentials"
    JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"

    def __init__(
        self,
        domain: str,
        client_id: str,
        client_secret: str,
        auth_server_id: str = "default",
        audience: str = "",
        token_endpoint: str = "",
        issuer: str = "",
    ):
        self.domain = domain
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_server_id = auth_server_id
        self.audience = audience
        self.issuer = issuer
        self.token_endpoint = (
            token_endpoint
            or f"https://{domain}/oauth2/{auth_server_id}/v1/token"
        )

    async def exchange_token(
        self,
        subject_token: str,
        target_audience: str,
        scopes: Optional[List[str]] = None,
        badge_jwt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Perform cross-domain token exchange via Okta ID-JAG flow.

        Step 1: Request an Identity Assertion JWT (ID-JAG) from Okta using
                client_credentials with the requested scopes.
        Step 2: Exchange the ID-JAG plus the AGNTCY badge JWT (actor proof)
                for a scoped access token to the target resource application.

        Parameters:
            subject_token: The AGNTCY badge JWT (subject of the exchange)
            target_audience: Okta API identifier for the target domain
            scopes: Requested scopes at the target domain
            badge_jwt: AGNTCY badge JWT used as actor_token proof

        Returns:
            Token response with access_token, token_type, expires_in, scope

        Raises:
            TokenExchangeError: If token exchange fails or validation fails
        """
        id_jag_jwt = await self._request_id_jag(scopes=scopes)
        result = await self._exchange_id_jag_for_token(
            id_jag_jwt=id_jag_jwt,
            target_audience=target_audience,
            badge_jwt=badge_jwt or subject_token,
        )
        self._validate_token_response(result, target_audience)
        return result

    @staticmethod
    def _validate_token_response(
        token_response: Dict[str, Any],
        expected_audience: str,
    ) -> None:
        """
        Validate the token response from Okta.

        Checks:
          - expires_in is present and positive
          - access_token is present and non-empty

        Raises TokenExchangeError if validation fails.
        """
        access_token = token_response.get("access_token", "")
        if not access_token:
            raise TokenExchangeError(reason="Token response missing access_token")

        expires_in = token_response.get("expires_in")
        if expires_in is None or expires_in <= 0:
            raise TokenExchangeError(
                reason="Token response has invalid or missing expires_in"
            )

        # Attempt to decode the access token (without verification) to check
        # audience claim. Okta access tokens are JWTs with an aud claim.
        try:
            unverified = jwt.decode(
                access_token,
                options={"verify_signature": False},
                algorithms=["RS256", "ES256"],
            )
            token_aud = unverified.get("aud")
            if token_aud and token_aud != expected_audience:
                raise TokenExchangeError(
                    reason=(
                        f"Token audience mismatch: "
                        f"expected '{expected_audience}', got '{token_aud}'"
                    )
                )
        except jwt.DecodeError:
            # Opaque tokens don't have decodable claims — skip aud check
            logger.info("Token is opaque (non-JWT), skipping audience validation")

    async def _request_id_jag(
        self,
        scopes: Optional[List[str]] = None,
    ) -> str:
        """
        Step 1: Request an Identity Assertion JWT (ID-JAG) from Okta.

        Uses client_credentials grant to obtain the ID-JAG assertion.
        """
        scope_str = "openid"
        if scopes:
            scope_str = "openid " + " ".join(scopes)

        payload = {
            "grant_type": self.CLIENT_CREDENTIALS_GRANT,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": scope_str,
            "audience": self.audience,
        }

        logger.info(
            "Requesting ID-JAG: audience=%s scopes=%s",
            self.audience, scopes,
        )
        result = await self._post_token(payload)
        return result.get("access_token", "")

    async def _exchange_id_jag_for_token(
        self,
        id_jag_jwt: str,
        target_audience: str,
        badge_jwt: str,
    ) -> Dict[str, Any]:
        """
        Step 2: Exchange the ID-JAG for a scoped access token.

        Sends the ID-JAG as the assertion and the AGNTCY badge JWT as
        the actor_token for delegation proof.
        """
        payload = {
            "grant_type": self.ID_JAG_GRANT,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "assertion": id_jag_jwt,
            "audience": target_audience,
            "actor_token": badge_jwt,
            "actor_token_type": self.JWT_TOKEN_TYPE,
        }

        logger.info(
            "Exchanging ID-JAG for token: target_audience=%s",
            target_audience,
        )
        return await self._post_token(payload)

    async def _post_token(self, payload: Dict[str, str]) -> Dict[str, Any]:
        """POST to Okta token endpoint and return the parsed response."""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self.token_endpoint,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30.0,
            )

        if resp.status_code != 200:
            error_body = {}
            try:
                error_body = resp.json()
            except Exception:
                pass
            raise TokenExchangeError(
                reason=f"Okta token request failed: {resp.status_code}",
                status_code=resp.status_code,
                details=error_body,
            )

        return resp.json()
