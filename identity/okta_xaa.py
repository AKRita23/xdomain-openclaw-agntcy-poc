"""
Okta XAA Token Exchange (RFC 8693).

Implements the OAuth 2.0 Token Exchange flow via Okta to obtain
domain-specific access tokens for cross-domain delegation.

Falls back to client_credentials grant with badge context when
the Okta authorization server does not support the token-exchange grant type.
"""
import logging
from typing import Any, Dict, List, Optional

import httpx

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
    """Handles Okta token exchange for cross-domain access."""

    TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
    CLIENT_CREDENTIALS_GRANT = "client_credentials"
    JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
    ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

    def __init__(
        self,
        domain: str,
        client_id: str,
        client_secret: str,
        auth_server_id: str = "default",
    ):
        self.domain = domain
        self.client_id = client_id
        self.client_secret = client_secret
        self.auth_server_id = auth_server_id
        self.token_endpoint = (
            f"https://{domain}/oauth2/{auth_server_id}/v1/token"
        )

    async def exchange_token(
        self,
        subject_token: str,
        target_audience: str,
        scopes: Optional[List[str]] = None,
        actor_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Perform cross-domain token exchange via Okta.

        Attempts RFC 8693 token exchange first. If the Okta authorization
        server returns an unsupported_grant_type error, falls back to
        client_credentials with the badge JWT passed as context.

        Parameters:
            subject_token: The AGNTCY badge JWT (subject of the exchange)
            target_audience: Okta API identifier for the target domain
            scopes: Requested scopes at the target domain
            actor_token: Optional actor token for delegation chain

        Returns:
            Token response with access_token, token_type, expires_in, scope
        """
        try:
            return await self._rfc8693_exchange(
                subject_token=subject_token,
                target_audience=target_audience,
                scopes=scopes,
                actor_token=actor_token,
            )
        except TokenExchangeError as e:
            if e.status_code == 403 or "unsupported_grant_type" in str(e.details):
                logger.info(
                    "RFC 8693 not supported, falling back to client_credentials"
                )
                return await self._client_credentials_fallback(
                    target_audience=target_audience,
                    scopes=scopes,
                    badge_jwt=subject_token,
                )
            raise

    async def _rfc8693_exchange(
        self,
        subject_token: str,
        target_audience: str,
        scopes: Optional[List[str]] = None,
        actor_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Attempt RFC 8693 token exchange."""
        payload = {
            "grant_type": self.TOKEN_EXCHANGE_GRANT,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "subject_token": subject_token,
            "subject_token_type": self.JWT_TOKEN_TYPE,
            "requested_token_type": self.ACCESS_TOKEN_TYPE,
            "audience": target_audience,
        }
        if scopes:
            payload["scope"] = " ".join(scopes)
        if actor_token:
            payload["actor_token"] = actor_token
            payload["actor_token_type"] = self.JWT_TOKEN_TYPE

        logger.info(
            "RFC 8693 token exchange: audience=%s scopes=%s",
            target_audience, scopes,
        )
        return await self._post_token(payload)

    async def _client_credentials_fallback(
        self,
        target_audience: str,
        scopes: Optional[List[str]] = None,
        badge_jwt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Fallback: use client_credentials grant with badge as custom context.

        Okta client_credentials flow issues a token for a registered API
        (audience). The badge JWT is not sent to Okta in this flow but is
        retained locally for TBAC enforcement by the middleware.
        """
        payload = {
            "grant_type": self.CLIENT_CREDENTIALS_GRANT,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": " ".join(scopes) if scopes else "",
        }

        logger.info(
            "Client credentials fallback: audience=%s scopes=%s",
            target_audience, scopes,
        )
        result = await self._post_token(payload)
        # Attach badge reference so callers know which badge was used
        if badge_jwt:
            result["_badge_jwt"] = badge_jwt
        return result

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
