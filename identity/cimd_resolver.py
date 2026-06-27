"""
CIMD resolver — consumer side of the Client ID Metadata Document.

A relying party (TBAC middleware, federated IdP, peer agent) takes an
agent's CIMD ``client_id`` URL and uses :class:`CIMDResolver` to:

  1. Fetch the JSON document from that URL.
  2. Enforce the self-reference invariant — the document's
     ``client_id`` MUST equal the URL it was fetched from. Mismatch
     means whoever signed up to host the document has decoupled it
     from its identity; reject as spoofed.
  3. Extract the inline ``vc+jwt`` (AGNTCY badge JWT).
  4. Verify the badge via :class:`BadgeVerifier.verify_badge`,
     passing ``expected_agent_id`` / ``expected_user`` derived from
     the CIMD document's own declared claims. This inherits the
     Phase-1 fix #4 identity-match guard: a hostile CIMD endpoint
     cannot pair a valid badge with a different identity, because
     the verifier will refuse to certify the mismatch.

The resolved result contains the verified ``capabilities`` and
``delegating_user`` so the downstream TBAC layer can authorize tool
calls without ever touching the badge JWT directly.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx

from identity.badge_verifier import BadgeVerifier
from identity.cimd_document import VC_JWT_FIELD

logger = logging.getLogger(__name__)

DEFAULT_HTTP_TIMEOUT_SECONDS = 30.0


class CIMDResolutionError(Exception):
    """Raised when a CIMD document cannot be resolved or its badge rejected.

    Attributes:
        reason: Human-readable failure description.
        cimd_client_id: URL the resolver was attempting to dereference.
        details: Verifier output (when failure was at the verify step).
    """

    def __init__(
        self,
        reason: str,
        cimd_client_id: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.cimd_client_id = cimd_client_id
        self.details = details or {}


@dataclass(frozen=True)
class ResolvedCIMDIdentity:
    """Result of a successful CIMD resolution + badge verification."""

    cimd_client_id: str
    badge_jwt: str
    agent_id: str
    delegating_user: str
    capabilities: List[Any]
    client_name: str
    jwks_uri: str
    verification: Dict[str, Any]

    def as_badge_dict(self) -> Dict[str, Any]:
        """Return a badge-shaped dict the orchestrator pipeline can consume."""
        return {
            "badge_id": self.verification.get("badge_id", ""),
            "agent_id": self.agent_id,
            "delegating_user": self.delegating_user,
            "issuer_did": self.verification.get("issuer", ""),
            "jwt": self.badge_jwt,
            "issued_at": self.verification.get("issuance_date", ""),
            "task_scopes": list(self.capabilities),
        }


class CIMDResolver:
    """Resolves CIMD ``client_id`` URLs to verified agent identities."""

    def __init__(
        self,
        badge_verifier: BadgeVerifier,
        http_timeout_seconds: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
    ) -> None:
        self._verifier = badge_verifier
        self._timeout = http_timeout_seconds

    async def resolve(self, cimd_client_id: str) -> ResolvedCIMDIdentity:
        """Resolve a CIMD URL to a verified agent identity.

        Steps 1–3 (fetch / self-ref / extract) raise
        :class:`CIMDResolutionError` immediately on failure. Step 4
        delegates to :class:`BadgeVerifier`, which performs the
        Phase-1 identity-match check — so this method cannot return
        a result where the verified badge's identity differs from the
        document's declared identity.
        """
        if not cimd_client_id:
            raise CIMDResolutionError("cimd_client_id must be non-empty")

        document = await self._fetch_document(cimd_client_id)

        # Self-reference invariant.
        declared_client_id = document.get("client_id")
        if declared_client_id != cimd_client_id:
            raise CIMDResolutionError(
                reason=(
                    "self-reference mismatch: document client_id="
                    f"{declared_client_id!r}, fetched from {cimd_client_id!r}"
                ),
                cimd_client_id=cimd_client_id,
            )

        badge_jwt = document.get(VC_JWT_FIELD, "")
        if not badge_jwt:
            raise CIMDResolutionError(
                reason=f"CIMD document missing {VC_JWT_FIELD!r} field",
                cimd_client_id=cimd_client_id,
            )

        declared_agent_id = (document.get("agent_id") or "").strip()
        declared_user = (document.get("delegating_user") or "").strip()
        if not declared_agent_id or not declared_user:
            raise CIMDResolutionError(
                reason=(
                    "CIMD document missing declared identity "
                    "(agent_id / delegating_user) — verifier cannot bind"
                ),
                cimd_client_id=cimd_client_id,
            )

        # Phase-1 fix #4 inheritance: expected identity comes from the
        # CIMD document's own declared claims, so the verifier refuses to
        # certify a badge whose verified content disagrees with those claims.
        verification = await self._verifier.verify_badge(
            {"jwt": badge_jwt},
            expected_agent_id=declared_agent_id,
            expected_user=declared_user,
        )
        if not verification.get("valid"):
            raise CIMDResolutionError(
                reason=(
                    "badge verification failed: "
                    f"{verification.get('reason', 'unknown')}"
                ),
                cimd_client_id=cimd_client_id,
                details=verification,
            )

        logger.info(
            "CIMD resolved: client_id=%s agent_id=%s user=%s caps=%s",
            cimd_client_id, declared_agent_id, declared_user,
            verification.get("capabilities", []),
        )
        return ResolvedCIMDIdentity(
            cimd_client_id=cimd_client_id,
            badge_jwt=badge_jwt,
            agent_id=declared_agent_id,
            delegating_user=declared_user,
            capabilities=list(verification.get("capabilities", [])),
            client_name=document.get("client_name", ""),
            jwks_uri=document.get("jwks_uri", ""),
            verification=verification,
        )

    async def _fetch_document(self, url: str) -> Dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(url)
        except httpx.HTTPError as exc:
            raise CIMDResolutionError(
                reason=f"failed to fetch CIMD document: {exc}",
                cimd_client_id=url,
            ) from exc

        if resp.status_code != 200:
            raise CIMDResolutionError(
                reason=f"CIMD endpoint returned HTTP {resp.status_code}",
                cimd_client_id=url,
            )

        try:
            doc = resp.json()
        except ValueError as exc:
            raise CIMDResolutionError(
                reason=f"CIMD endpoint body was not JSON: {exc}",
                cimd_client_id=url,
            ) from exc

        if not isinstance(doc, dict):
            raise CIMDResolutionError(
                reason=f"CIMD endpoint returned non-object JSON: {type(doc).__name__}",
                cimd_client_id=url,
            )
        return doc
