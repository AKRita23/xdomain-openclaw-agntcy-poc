"""
AGNTCY Identity Badge Verification.

Verifies badges issued by the AGNTCY Identity Service, checking
JWT signature against JWKS, expiration, and issuer DID.
"""
import logging
from typing import Any, Dict, Optional

import jwt

logger = logging.getLogger(__name__)


class BadgeVerificationError(Exception):
    """Raised when badge verification fails."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class BadgeVerifier:
    """Verifies AGNTCY identity badges using JWKS-based signature verification."""

    def __init__(self, identity_service_url: str, jwks_url: str = ""):
        self.identity_service_url = identity_service_url
        self.jwks_url = jwks_url
        self._jwks_client: Optional[jwt.PyJWKClient] = None

    def _get_jwks_client(self) -> jwt.PyJWKClient:
        """Lazily initialize the JWKS client."""
        if self._jwks_client is None:
            url = self.jwks_url or f"{self.identity_service_url}/.well-known/jwks.json"
            self._jwks_client = jwt.PyJWKClient(url)
        return self._jwks_client

    async def verify_badge(self, badge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify an AGNTCY identity badge.

        Checks:
          - badge_id and jwt fields are present
          - JWT signature against issuer JWKS
          - Badge expiration (exp claim)
          - Issuer claim (iss)

        Returns verification result with 'valid' bool and 'reason' on failure.
        """
        badge_id = badge.get("badge_id", "")
        badge_jwt = badge.get("jwt", "")

        if not badge_id or not badge_jwt:
            return {"valid": False, "reason": "Missing badge_id or jwt"}

        try:
            jwks_client = self._get_jwks_client()
            signing_key = jwks_client.get_signing_key_from_jwt(badge_jwt)

            claims = jwt.decode(
                badge_jwt,
                signing_key.key,
                algorithms=["RS256", "ES256"],
                options={
                    "require": ["exp", "iss", "sub"],
                    "verify_exp": True,
                    "verify_iss": True,
                },
            )

            logger.info("Badge verified: %s", badge_id)
            return {
                "valid": True,
                "badge_id": badge_id,
                "claims": claims,
            }

        except jwt.ExpiredSignatureError:
            logger.warning("Badge expired: %s", badge_id)
            return {"valid": False, "reason": "Badge JWT has expired"}

        except jwt.InvalidIssuerError:
            logger.warning("Badge issuer invalid: %s", badge_id)
            return {"valid": False, "reason": "Badge JWT issuer is not trusted"}

        except jwt.InvalidSignatureError:
            logger.warning("Badge signature invalid: %s", badge_id)
            return {"valid": False, "reason": "Badge JWT signature verification failed"}

        except jwt.PyJWKClientError:
            logger.warning("JWKS fetch failed for badge: %s", badge_id)
            return {"valid": False, "reason": "Unable to fetch issuer JWKS for verification"}

        except jwt.InvalidTokenError as e:
            logger.warning("Badge token invalid: %s — %s", badge_id, type(e).__name__)
            return {"valid": False, "reason": "Badge JWT is invalid"}
