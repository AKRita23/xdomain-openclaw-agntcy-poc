"""
AGNTCY Identity Badge Verification via Identity Node REST API.

Fetches and verifies badges using the AGNTCY Identity Node's
cryptographic verification endpoint — no local JWT decoding needed.
"""
import json
import logging
import os
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)


class BadgeVerificationError(Exception):
    """Raised when badge verification fails."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class BadgeVerifier:
    """Verifies AGNTCY identity badges via the Identity Node REST API."""

    ENVELOPE_TYPE = "CREDENTIAL_ENVELOPE_TYPE_JOSE"

    def __init__(self, node_url: str, metadata_id: str = ""):
        self.node_url = node_url.rstrip("/")
        self.metadata_id = metadata_id or os.getenv("AGNTCY_METADATA_ID", "")

    async def fetch_and_verify(self) -> Dict[str, Any]:
        """
        Fetch badge VC from well-known endpoint and verify via Identity Node.

        1. GET well-known endpoint to retrieve the VC JWT
        2. POST to verify endpoint for full cryptographic verification
        3. Parse capabilities from document.content.badge
        4. Return structured result

        Returns verification result with 'valid' bool, capabilities,
        delegating_user, issuer, and issuance_date on success.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Step 1: Fetch VC JWT from well-known endpoint
            well_known_url = (
                f"{self.node_url}/v1alpha1/vc/{self.metadata_id}"
                f"/.well-known/vcs.json"
            )
            try:
                resp = await client.get(well_known_url)
            except httpx.HTTPError as e:
                return {"valid": False, "reason": f"Failed to fetch badge: {e}"}

            if resp.status_code != 200:
                return {
                    "valid": False,
                    "reason": f"Well-known endpoint returned {resp.status_code}",
                }

            vcs_data = resp.json()
            vcs_list = vcs_data.get("vcs", [])
            if not vcs_list:
                return {"valid": False, "reason": "No VCs found at well-known endpoint"}

            vc_jwt = vcs_list[0].get("value", "")
            if not vc_jwt:
                return {"valid": False, "reason": "VC envelope has no JWT value"}

            # Step 2: Verify via Identity Node
            return await self._verify_vc_jwt(client, vc_jwt)

    async def verify_badge(self, badge: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify an existing badge dict by POSTing its JWT to the Identity Node.

        Accepts badge dicts with a 'jwt' field (used by middleware.enforce).
        Returns verification result with 'valid' bool.
        """
        badge_jwt = badge.get("jwt", "")
        if not badge_jwt:
            return {"valid": False, "reason": "Missing jwt in badge"}

        async with httpx.AsyncClient(timeout=30.0) as client:
            return await self._verify_vc_jwt(client, badge_jwt)

    async def _verify_vc_jwt(
        self, client: httpx.AsyncClient, vc_jwt: str
    ) -> Dict[str, Any]:
        """POST a VC JWT to the Identity Node verify endpoint."""
        verify_url = f"{self.node_url}/v1alpha1/vc/verify"
        body = {
            "vc": {
                "envelopeType": self.ENVELOPE_TYPE,
                "value": vc_jwt,
            }
        }

        try:
            resp = await client.post(verify_url, json=body)
        except httpx.HTTPError as e:
            return {"valid": False, "reason": f"Verification request failed: {e}"}

        if resp.status_code != 200:
            return {
                "valid": False,
                "reason": f"Verify endpoint returned {resp.status_code}",
            }

        result = resp.json()
        status = result.get("status", False)
        errors = result.get("errors", [])

        if not status or errors:
            return {
                "valid": False,
                "reason": f"Badge verification failed: {errors}",
            }

        # Parse the verified document
        document = result.get("document", {})
        content = document.get("content", {})
        badge_json_str = content.get("badge", "")

        capabilities = []
        delegating_user = ""
        if badge_json_str:
            try:
                badge_data = json.loads(badge_json_str)
                capabilities = badge_data.get("capabilities", [])
                delegating_user = badge_data.get("delegating_user", "")
            except (json.JSONDecodeError, TypeError):
                logger.warning("Failed to parse badge JSON from document content")

        badge_id = content.get("id", "")
        issuer = document.get("issuer", "")
        issuance_date = document.get("issuanceDate", "")

        logger.info("Badge verified via Identity Node: %s", badge_id)
        return {
            "valid": True,
            "badge_id": badge_id,
            "capabilities": capabilities,
            "delegating_user": delegating_user,
            "issuer": issuer,
            "issuance_date": issuance_date,
        }
