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
    ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token"
    ID_JAG_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id-jag"

    TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"

    SARAH_TOKEN_SECRET_ID = "xdomain-agent-poc/sarah-token"

    # Map scopes to resource domain targets
    SCOPE_TO_RESOURCE = {
        "weather.read": "weather",
        "slack.post.agent-weather-alerts": "slack",
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
            or f"https://{domain}/oauth2/v1/token"
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
            f"https://{self.org2_domain}/oauth2/v1/token"
        )
        logger.info(
            "Exchanging Sarah's token at Org 2: %s audience=%s scopes=%s "
            "actor_token=%s",
            org2_token_endpoint, resolved_audience, scopes,
            "<badge_jwt>" if badge_jwt else "<absent>",
        )
        exchange_data = {
            "grant_type": self.TOKEN_EXCHANGE_GRANT,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "requested_token_type": self.ID_JAG_TOKEN_TYPE,
            "subject_token": sarah_token,
            "subject_token_type": self.ID_TOKEN_TYPE,
            "audience": resolved_audience,
            "resource": resolved_audience,
            "scope": " ".join(scopes) if scopes else "",
        }
        # Phase-1 fix #5: re-wire AGNTCY badge as actor_token (RFC 8693 §2.1).
        # Git history shows actor_token was wired through ba99c60→aa6cfc0→e7287d8
        # and REMOVED in 959fbd6 ("Implement Sarah token XAA exchange...") when
        # the flow pivoted to Sarah's pre-obtained subject_token. The
        # ``badge_jwt`` parameter survived as dead weight; the delegation-proof
        # leg of the architecture did not.
        if badge_jwt:
            exchange_data["actor_token"] = badge_jwt
            exchange_data["actor_token_type"] = self.JWT_TOKEN_TYPE

        async with httpx.AsyncClient() as client:
            resp = await client.post(org2_token_endpoint, data=exchange_data)

        if resp.status_code != 200:
            error_body = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"body": resp.text}
            logger.error("Okta token exchange rejected: status=%s body=%s", resp.status_code, error_body)
            raise TokenExchangeError(
                reason=f"Token exchange failed: Org 2 returned {resp.status_code}: {error_body}",
                status_code=resp.status_code,
                details=error_body,
            )

        result = resp.json()
        logger.info("Token exchange complete: obtained scoped access token")

        # Phase-1 fix #5: make "did Okta echo `act`?" reproducible from logs.
        # PoC-grade observation only — the resource auth server is authoritative
        # for signature; here we just decode and report claim presence.
        _log_act_claim_presence(
            label="Okta ID-JAG",
            token=result.get("access_token", ""),
            actor_token_was_sent=bool(badge_jwt),
        )

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


def _log_act_claim_presence(
    label: str, token: str, actor_token_was_sent: bool,
) -> None:
    """Decode an ID-JAG (no signature check) and log whether ``act`` is present.

    This is the *reproducible observation* the blog centerpiece rests on:
    after wiring AGNTCY badge as ``actor_token``, does the issued ID-JAG
    carry an ``act`` claim echoing the delegation chain? Each call emits
    one line at INFO so the answer is grep-able from log output alone.
    """
    if not token:
        logger.info(
            "[%s] act-claim observation: cannot decode (empty token); "
            "actor_token sent=%s",
            label, actor_token_was_sent,
        )
        return
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.exceptions.DecodeError as exc:
        logger.info(
            "[%s] act-claim observation: token is opaque/undecodable (%s); "
            "actor_token sent=%s",
            label, exc, actor_token_was_sent,
        )
        return

    act = claims.get("act")
    if act is None:
        logger.info(
            "[%s] act-claim observation: act claim ABSENT in issued token; "
            "actor_token sent=%s",
            label, actor_token_was_sent,
        )
    else:
        logger.info(
            "[%s] act-claim observation: act claim PRESENT (%s); "
            "actor_token sent=%s",
            label, act, actor_token_was_sent,
        )
