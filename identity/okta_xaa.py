"""
Okta XAA — Identity Assertion Authorization Grant (ID-JAG).

Implements the Okta ID-JAG flow to obtain domain-specific access tokens
for cross-domain delegation. The agent loads Sarah's pre-obtained token
from AWS Secrets Manager, then exchanges it for a scoped access token
at the resource domain (Org 2).
"""
import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

import boto3
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
    """Handles Okta XAA (ID-JAG) token exchange for cross-domain access."""

    ID_JAG_GRANT = "urn:okta:params:oauth:grant-type:id-jag"
    CLIENT_CREDENTIALS_GRANT = "client_credentials"
    JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
    ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

    TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"

    SARAH_TOKEN_SECRET_ID = "xdomain-agent-poc/sarah-token"

    # Map scopes to resource domain targets
    SCOPE_TO_RESOURCE = {
        "weather:read": "weather",
        "slack:chat:write": "slack",
    }

    def __init__(
        self,
        domain: str,
        client_id: str,
        client_secret: str,
        auth_server_id: str = "default",
        audience: str = "",
        token_endpoint: str = "",
        issuer: str = "",
        # Org 2 (resource domain) parameters
        org2_domain: str = "",
        resource_app_client_id: str = "",
        resource_app_client_secret: str = "",
        weather_auth_server_id: str = "",
        slack_auth_server_id: str = "",
        weather_audience: str = "",
        slack_audience: str = "",
        aws_region: str = "us-east-1",
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
        # Org 2 config
        self.org2_domain = org2_domain
        self.resource_app_client_id = resource_app_client_id
        self.resource_app_client_secret = resource_app_client_secret
        self.weather_auth_server_id = weather_auth_server_id
        self.slack_auth_server_id = slack_auth_server_id
        self.weather_audience = weather_audience
        self.slack_audience = slack_audience
        self.aws_region = aws_region

    def _resolve_org2_target(
        self, target_audience: str, scopes: Optional[List[str]],
    ) -> Tuple[str, str]:
        """Resolve Org 2 auth server ID and audience from scopes or target_audience."""
        if scopes:
            for scope in scopes:
                resource = self.SCOPE_TO_RESOURCE.get(scope)
                if resource == "weather":
                    return self.weather_auth_server_id, self.weather_audience
                if resource == "slack":
                    return self.slack_auth_server_id, self.slack_audience

        # Fall back to matching target_audience directly
        if target_audience == self.weather_audience:
            return self.weather_auth_server_id, self.weather_audience
        if target_audience == self.slack_audience:
            return self.slack_auth_server_id, self.slack_audience

        raise TokenExchangeError(
            reason=f"Cannot resolve Org 2 auth server for audience '{target_audience}' "
                   f"and scopes {scopes}"
        )

    def load_sarah_token(self) -> str:
        """Load Sarah's pre-obtained access token.

        Checks the SARAH_ACCESS_TOKEN env var first; falls back to
        AWS Secrets Manager if the env var is not set.

        Returns the access_token string.

        Raises:
            TokenExchangeError: If the secret cannot be fetched or parsed.
        """
        env_token = os.getenv("SARAH_ACCESS_TOKEN")
        if env_token:
            logger.info("Loaded Sarah's token from SARAH_ACCESS_TOKEN env var")
            return env_token

        try:
            sm = boto3.client("secretsmanager", region_name=self.aws_region)
            resp = sm.get_secret_value(SecretId=self.SARAH_TOKEN_SECRET_ID)
            secret = json.loads(resp["SecretString"])
            token = secret.get("access_token")
            if not token:
                raise TokenExchangeError(
                    reason="Secret missing 'access_token' field",
                    details={"secret_id": self.SARAH_TOKEN_SECRET_ID},
                )
            logger.info("Loaded Sarah's token from Secrets Manager")
            return token
        except TokenExchangeError:
            raise
        except Exception as exc:
            raise TokenExchangeError(
                reason=f"Failed to load Sarah's token from Secrets Manager: {exc}",
                details={"secret_id": self.SARAH_TOKEN_SECRET_ID},
            ) from exc

    async def exchange_token(
        self,
        subject_token: str,
        target_audience: str,
        scopes: Optional[List[str]] = None,
        badge_jwt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Perform token exchange using Sarah's pre-obtained token.

        Step 1: Load Sarah's access token from AWS Secrets Manager
        Step 2: Exchange it at Org 2 for a scoped access token

        Returns token response with access_token, token_type, expires_in, scope.

        Raises:
            TokenExchangeError: If any step fails or validation fails
        """
        org2_auth_server_id, resolved_audience = self._resolve_org2_target(
            target_audience, scopes,
        )

        # Step 1 — Load Sarah's token from Secrets Manager
        sarah_token = self.load_sarah_token()

        # Step 2 — Exchange Sarah's token at Org 2
        org2_token_endpoint = (
            f"https://{self.org2_domain}/oauth2/{org2_auth_server_id}/v1/token"
        )
        logger.info(
            "Exchanging Sarah's token at Org 2: %s audience=%s scopes=%s",
            org2_token_endpoint, resolved_audience, scopes,
        )
        exchange_data = {
            "grant_type": self.TOKEN_EXCHANGE_GRANT,
            "client_id": self.resource_app_client_id,
            "client_secret": self.resource_app_client_secret,
            "subject_token": sarah_token,
            "subject_token_type": self.ACCESS_TOKEN_TYPE,
            "audience": resolved_audience,
            "scope": " ".join(scopes) if scopes else "",
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(org2_token_endpoint, data=exchange_data)

        if resp.status_code != 200:
            raise TokenExchangeError(
                reason=f"Token exchange failed: Org 2 returned {resp.status_code}",
                status_code=resp.status_code,
                details=resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"body": resp.text},
            )

        result = resp.json()
        logger.info("Token exchange complete: obtained scoped access token")

        self._validate_token_response(result, resolved_audience)
        return result

    @staticmethod
    def _validate_token_response(
        token_response: Dict[str, Any],
        expected_audience: str,
    ) -> None:
        """
        Validate the token response.

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
