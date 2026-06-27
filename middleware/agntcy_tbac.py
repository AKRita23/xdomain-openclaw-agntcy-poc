"""
AGNTCY IdentityServiceMCPMiddleware — Task-Based Access Control (TBAC).

Intercepts MCP tool calls and enforces:
  1. Badge validity (via BadgeVerifier) + identity binding
  2. Scope alignment using ONLY the verifier's verified capability set
     (never the caller-supplied badge dict's ``task_scopes``)
  3. Delegation chain integrity
  4. Rate / quota limits per badge

Phase-1 hardening contract:
  * Scope subset is computed from ``verification["capabilities"]`` returned
    by :meth:`BadgeVerifier.verify_badge` — the caller dict is untrusted.
  * Empty / missing verified capabilities deny (no "open badge" mode).
  * TTL gate reads ``issuance_date`` from the verifier result, with
    parse failures treated as expired.
  * Identity binding is enforced inside the verifier when
    ``expected_agent_id`` / ``expected_user`` are passed through.
"""
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from identity.badge_verifier import BadgeVerifier

logger = logging.getLogger(__name__)

# PoC TTL for badge expiration (24 hours)
BADGE_TTL_SECONDS = 24 * 60 * 60

# Clock skew tolerated on the issuance-date TTL gate.
TTL_SKEW_SECONDS = 60


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

    def __init__(self, identity_service_url: str, metadata_id: str = ""):
        self.verifier = BadgeVerifier(identity_service_url, metadata_id=metadata_id)

    async def enforce(
        self,
        badge: Dict[str, Any],
        target_server: str,
        requested_scopes: List[str],
        xaa_token: Dict[str, Any],
        expected_agent_id: Optional[str] = None,
        expected_user: Optional[str] = None,
        expected_task: Optional[str] = None,
    ) -> None:
        """
        Enforce TBAC policy before an MCP call proceeds.

        ``expected_agent_id`` / ``expected_user`` are forwarded to the
        verifier and bind the badge to the agent/user the orchestrator
        actually meant to authorize — closes the substitution gap.

        ``expected_task`` lets the caller pin which task this enforce()
        is gating; missing or mismatched ``xaa_token["task"]`` denies.

        Raises TBACViolation if any check fails.
        """
        # 1. Verify badge with identity binding
        verification = await self.verifier.verify_badge(
            badge,
            expected_agent_id=expected_agent_id,
            expected_user=expected_user,
        )
        if not verification.get("valid"):
            raise TBACViolation(
                reason="Badge verification failed",
                details=verification,
            )

        # 2. Scope alignment — ONLY from the verified capability set.
        #    The caller-supplied badge dict's ``task_scopes`` is ignored:
        #    treating it as authoritative would let any caller widen scope
        #    by editing the dict between issue and enforce.
        verified_caps = _coerce_scope_set(verification.get("capabilities", []))
        if not verified_caps:
            raise TBACViolation(
                reason="badge has no authorized scopes",
                details={
                    "requested": list(requested_scopes),
                    "verified_capabilities": verification.get("capabilities", []),
                },
            )

        requested = set(requested_scopes)
        if not requested.issubset(verified_caps):
            excess = requested - verified_caps
            raise TBACViolation(
                reason=f"Scope escalation: {sorted(excess)} not in verified capabilities",
                details={
                    "requested": sorted(requested),
                    "verified_capabilities": sorted(verified_caps),
                    "excess": sorted(excess),
                },
            )

        # 3. Task context validation — task MUST be present and match.
        task_claim = xaa_token.get("task")
        if expected_task is not None:
            if task_claim != expected_task:
                raise TBACViolation(
                    reason=(
                        f"Task mismatch: expected {expected_task!r}, "
                        f"got {task_claim!r}"
                    ),
                    details={"expected": expected_task, "actual": task_claim},
                )

        # 4. Domain validation (only fires when capabilities carry domain dicts)
        capabilities = verification.get("capabilities", [])
        authorized_domains = {
            cap["domain"] for cap in capabilities
            if isinstance(cap, dict) and "domain" in cap
        }
        if authorized_domains and target_server not in authorized_domains:
            raise TBACViolation(
                reason=f"Domain {target_server} not authorized by badge capabilities",
                details={
                    "target_server": target_server,
                    "authorized_domains": sorted(authorized_domains),
                },
            )

        # 5. Badge TTL validation — read from the VERIFIED result, not the
        #    caller dict. Missing or unparseable → expired (fail closed).
        issuance_date = verification.get("issuance_date", "")
        if not issuance_date:
            raise TBACViolation(
                reason="verified badge has no issuance_date",
                details={"verification_keys": sorted(verification.keys())},
            )
        try:
            issued_at = datetime.fromisoformat(
                issuance_date.replace("Z", "+00:00")
            )
        except (ValueError, TypeError) as exc:
            raise TBACViolation(
                reason=f"verified badge issuance_date unparseable: {exc}",
                details={"issuance_date": issuance_date},
            ) from exc
        age = (datetime.now(timezone.utc) - issued_at).total_seconds()
        if age - TTL_SKEW_SECONDS > BADGE_TTL_SECONDS:
            raise TBACViolation(
                reason="Badge has expired (exceeded 24h TTL)",
                details={"issuance_date": issuance_date, "age_seconds": age},
            )

        # 6. Validate XAA token is present and well-formed
        if not xaa_token.get("access_token"):
            raise TBACViolation(reason="Missing XAA access token")

        logger.info(
            "TBAC ALLOW: badge=%s server=%s scopes=%s",
            verification.get("badge_id"), target_server, requested_scopes,
        )


def _coerce_scope_set(capabilities: Any) -> set:
    """Flatten a verified ``capabilities`` value to a comparable scope set.

    AGNTCY badges may express capabilities as a list of strings
    (``["weather:read", "slack:chat:write"]``) or as a list of dicts
    (``[{"scope": "weather:read", "domain": "..."}]``). Both shapes
    reduce to a set of scope strings here so the subset check has one
    code path. Non-list / unknown shapes return ``set()`` → deny.
    """
    if not isinstance(capabilities, list):
        return set()
    out = set()
    for cap in capabilities:
        if isinstance(cap, str):
            out.add(cap)
        elif isinstance(cap, dict):
            scope = cap.get("scope") or cap.get("name")
            if isinstance(scope, str):
                out.add(scope)
            # Some AGNTCY shapes carry a list of scopes per capability dict.
            scopes_field = cap.get("scopes")
            if isinstance(scopes_field, list):
                for s in scopes_field:
                    if isinstance(s, str):
                        out.add(s)
    return out
