"""
AGNTCY Identity Badge Issuance.

Fetches pre-provisioned agent identity badges from the AGNTCY Identity
Node's well-known endpoint. The badge is minted by the Identity Node
out-of-band; this module pulls the VC JWT, packages it into the dict
shape the rest of the XAA flow expects, and surfaces fetch failures as
``RuntimeError`` so upstream callers can wrap them as step-1 errors.
"""
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class BadgeIssuer:
    """Fetches AGNTCY identity badges for agent attestation."""

    def __init__(self, identity_service_url: str):
        self.identity_service_url = identity_service_url

    async def issue_badge(
        self,
        agent_id: str,
        delegating_user: str,
        issuer_did: str,
        task_scopes: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Fetch the pre-provisioned identity badge from AGNTCY's well-known endpoint.

        The badge itself is issued and signed by the AGNTCY Identity Node;
        this method retrieves the VC JOSE envelope and returns a dict
        containing the JWT plus delegation metadata so the verifier can
        cryptographically validate it downstream.

        Returns a badge dict with:
          - badge_id
          - agent_id
          - delegating_user
          - issuer_did
          - jwt (VC JOSE envelope value — verifiable by BadgeVerifier)
          - issued_at
          - task_scopes

        Raises:
            RuntimeError: if ``AGNTCY_BADGE_WELL_KNOWN`` is unset, the HTTP
                call fails, the response is non-200, or the payload is
                missing the expected ``vcs[0].value`` JWT.
        """
        well_known_url = os.getenv("AGNTCY_BADGE_WELL_KNOWN", "").strip()
        if not well_known_url:
            raise RuntimeError(
                "AGNTCY_BADGE_WELL_KNOWN env var is required to fetch the badge"
            )

        badge_id = os.getenv("AGNTCY_BADGE_ID", "").strip() or agent_id

        logger.info(
            "Fetching AGNTCY badge from well-known URL: %s (badge_id=%s, "
            "agent=%s, user=%s)",
            well_known_url, badge_id, agent_id, delegating_user,
        )

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(well_known_url)
        except httpx.HTTPError as exc:
            raise RuntimeError(
                f"Failed to fetch badge from {well_known_url}: {exc}"
            ) from exc

        if response.status_code != 200:
            raise RuntimeError(
                f"Badge well-known endpoint returned HTTP "
                f"{response.status_code}: {response.text[:200]}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise RuntimeError(
                f"Badge well-known endpoint returned non-JSON body: {exc}"
            ) from exc

        vcs = payload.get("vcs") or []
        if not vcs:
            raise RuntimeError(
                f"Badge well-known response has empty 'vcs' array: {payload}"
            )

        vc_jwt = vcs[0].get("value", "")
        if not vc_jwt:
            raise RuntimeError(
                "Badge well-known response 'vcs[0]' is missing the 'value' JWT"
            )

        return {
            "badge_id": badge_id,
            "agent_id": agent_id,
            "delegating_user": delegating_user,
            "issuer_did": issuer_did,
            "jwt": vc_jwt,
            "issued_at": datetime.utcnow().isoformat() + "Z",
            "task_scopes": task_scopes or [],
        }
