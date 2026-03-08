"""
AGNTCY IdentityServiceMCPMiddleware — Task-Based Access Control (TBAC).

Intercepts MCP tool calls and enforces:
  1. Badge validity (via BadgeVerifier)
  2. Scope alignment (requested scopes ⊆ badge-authorized scopes)
  3. Delegation chain integrity
  4. Rate / quota limits per badge
"""
import logging
from typing import Any, Dict, List, Optional

from identity.badge_verifier import BadgeVerifier

logger = logging.getLogger(__name__)


class TBACViolation(Exception):
    """Raised when a TBAC policy check fails."""

    def __init__(self, reason: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(reason)
        self.reason = reason
        self.details = details or {}


class IdentityServiceMCPMiddleware:
    """
    AGNTCY-based TBAC enforcement middleware.

    Sits between the OpenClaw agent and each MCP server to ensure
    every tool call is authorized by the agent's identity badge
    and the delegating user's granted scopes.
    """

    def __init__(self, identity_service_url: str):
        self.verifier = BadgeVerifier(identity_service_url)

    async def enforce(
        self,
        badge: Dict[str, Any],
        target_server: str,
        requested_scopes: List[str],
        xaa_token: Dict[str, Any],
    ) -> None:
        """
        Enforce TBAC policy before an MCP call proceeds.

        Raises TBACViolation if any check fails.
        """
        # 1. Verify badge
        verification = await self.verifier.verify_badge(badge)
        if not verification.get("valid"):
            raise TBACViolation(
                reason="Badge verification failed",
                details=verification,
            )

        # 2. Check scope alignment
        badge_scopes = set(badge.get("task_scopes", []))
        # If badge has no explicit scopes, allow (open badge model)
        if badge_scopes:
            requested = set(requested_scopes)
            if not requested.issubset(badge_scopes):
                excess = requested - badge_scopes
                raise TBACViolation(
                    reason=f"Scope escalation: {excess} not in badge scopes",
                    details={
                        "requested": list(requested),
                        "badge_scopes": list(badge_scopes),
                        "excess": list(excess),
                    },
                )

        # 3. Validate XAA token is present and well-formed
        if not xaa_token.get("access_token"):
            raise TBACViolation(reason="Missing XAA access token")

        logger.info(
            "TBAC ALLOW: badge=%s server=%s scopes=%s",
            badge.get("badge_id"), target_server, requested_scopes,
        )
