"""
AGNTCY Identity Badge Verification via Identity Node REST API.

Fetches and verifies badges using the AGNTCY Identity Node's
cryptographic verification endpoint — no local JWT decoding for trust,
but a local ``exp`` freshness gate so a node-side bug (stale cache,
revocation lag) cannot extend a badge past its own expiry.

Identity binding (Phase-1 hardening): both ``fetch_and_verify`` and
``verify_badge`` accept ``expected_agent_id`` / ``expected_user`` and
refuse to return ``valid: True`` for a VC whose verified content does
not match. This closes the ``vcs[0]`` blind-trust gap — a hostile
well-known endpoint can no longer steer the agent to validate against a
different identity.
"""
import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

import httpx
import jwt

logger = logging.getLogger(__name__)


class BadgeVerificationError(Exception):
    """Raised when badge verification fails."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


# Maximum clock skew tolerated when checking VC ``exp`` locally.
EXP_SKEW_SECONDS = 60


class BadgeVerifier:
    """Verifies AGNTCY identity badges via the Identity Node REST API."""

    ENVELOPE_TYPE = "CREDENTIAL_ENVELOPE_TYPE_JOSE"

    def __init__(self, node_url: str, metadata_id: str = ""):
        self.node_url = node_url.rstrip("/")
        self.metadata_id = metadata_id or os.getenv("AGNTCY_METADATA_ID", "")

    async def fetch_and_verify(
        self,
        expected_agent_id: Optional[str] = None,
        expected_user: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Fetch badge VCs from well-known endpoint and verify via Identity Node.

        Iterates the ``vcs`` list (no longer ``[0]`` blind-trust): each VC
        whose envelope type matches :attr:`ENVELOPE_TYPE` is verified via
        the Identity Node, and the first verified VC whose content matches
        the expected ``(agent_id, delegating_user)`` is returned. If no
        VC matches, returns ``{"valid": False, ...}``.

        When ``expected_agent_id`` / ``expected_user`` are ``None`` the
        identity-match step is skipped — used only by tests and the
        well-known smoke check.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
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

            mismatch_reasons: List[str] = []
            for idx, vc_envelope in enumerate(vcs_list):
                envelope_type = vc_envelope.get("envelopeType", "")
                if envelope_type != self.ENVELOPE_TYPE:
                    logger.info(
                        "Skipping VC %d: envelopeType=%r != expected %r",
                        idx, envelope_type, self.ENVELOPE_TYPE,
                    )
                    continue

                vc_jwt = vc_envelope.get("value", "")
                if not vc_jwt:
                    continue

                result = await self._verify_vc_jwt(
                    client, vc_jwt,
                    expected_agent_id=expected_agent_id,
                    expected_user=expected_user,
                )
                if result.get("valid"):
                    return result
                mismatch_reasons.append(
                    f"vc[{idx}]: {result.get('reason', 'unknown')}"
                )

            return {
                "valid": False,
                "reason": (
                    "no badge matches expected agent identity; "
                    f"checked {len(vcs_list)} VC(s): {'; '.join(mismatch_reasons)}"
                ),
            }

    async def verify_badge(
        self,
        badge: Dict[str, Any],
        expected_agent_id: Optional[str] = None,
        expected_user: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Verify an existing badge dict by POSTing its JWT to the Identity Node.

        Identity binding: when ``expected_agent_id`` or ``expected_user`` is
        supplied, the verified VC's content must match. Mismatch returns
        ``{"valid": False, "reason": ...}`` — a previously-valid badge
        cannot be substituted for a different agent / user.

        Local freshness gate: even if the Identity Node reports ``status:
        true``, an ``exp`` claim in the VC JWT that has already passed
        (with :data:`EXP_SKEW_SECONDS` of skew) causes a hard fail. The
        Identity Node is authoritative for signature; the local check is
        belt-and-suspenders for stale-cache / revocation-lag scenarios.
        """
        badge_jwt = badge.get("jwt", "")
        if not badge_jwt:
            return {"valid": False, "reason": "Missing jwt in badge"}

        async with httpx.AsyncClient(timeout=30.0) as client:
            return await self._verify_vc_jwt(
                client, badge_jwt,
                expected_agent_id=expected_agent_id,
                expected_user=expected_user,
            )

    async def _verify_vc_jwt(
        self,
        client: httpx.AsyncClient,
        vc_jwt: str,
        expected_agent_id: Optional[str] = None,
        expected_user: Optional[str] = None,
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

        capabilities: List[Any] = []
        delegating_user = ""
        verified_agent_id = ""
        if badge_json_str:
            try:
                badge_data = json.loads(badge_json_str)
                capabilities = badge_data.get("capabilities", [])
                delegating_user = badge_data.get("delegating_user", "")
                verified_agent_id = badge_data.get("agent_id", "")
            except (json.JSONDecodeError, TypeError):
                logger.warning("Failed to parse badge JSON from document content")

        badge_id = content.get("id", "")
        issuer = document.get("issuer", "")
        issuance_date = document.get("issuanceDate", "")

        # ----- Identity binding check -----
        if expected_agent_id is not None:
            # An expected agent_id was supplied. If the verified VC has no
            # agent_id field, we cannot prove the binding — fail closed.
            if not verified_agent_id:
                return {
                    "valid": False,
                    "reason": "verified VC has no agent_id; cannot bind to expected identity",
                }
            if verified_agent_id != expected_agent_id:
                return {
                    "valid": False,
                    "reason": (
                        f"agent_id mismatch: VC says {verified_agent_id!r}, "
                        f"expected {expected_agent_id!r}"
                    ),
                }
        if expected_user is not None:
            if not delegating_user:
                return {
                    "valid": False,
                    "reason": "verified VC has no delegating_user; cannot bind to expected user",
                }
            if delegating_user != expected_user:
                return {
                    "valid": False,
                    "reason": (
                        f"delegating_user mismatch: VC says {delegating_user!r}, "
                        f"expected {expected_user!r}"
                    ),
                }

        # ----- Local freshness gate on the VC JWT exp -----
        exp_check = _check_jwt_exp(vc_jwt)
        if not exp_check["ok"]:
            return {"valid": False, "reason": exp_check["reason"]}

        logger.info("Badge verified via Identity Node: %s", badge_id)
        return {
            "valid": True,
            "badge_id": badge_id,
            "capabilities": capabilities,
            "delegating_user": delegating_user,
            "agent_id": verified_agent_id,
            "issuer": issuer,
            "issuance_date": issuance_date,
        }


def _check_jwt_exp(token: str) -> Dict[str, Any]:
    """Decode the VC JWT (no signature check) and verify ``exp`` is in the future.

    The Identity Node already validated the signature; this is a local
    belt-and-suspenders gate against a node returning ``status: true`` for
    a JWT that is technically expired (stale cache, revocation lag). A
    JWT with no ``exp`` claim passes — AGNTCY VCs aren't required to
    carry one. Decode failures also pass; the node's verdict is
    authoritative for signature validity.
    """
    try:
        claims = jwt.decode(
            token, options={"verify_signature": False, "verify_exp": False},
        )
    except jwt.exceptions.DecodeError:
        # Opaque / malformed token — trust the node's "status: true"
        return {"ok": True}

    exp = claims.get("exp")
    if exp is None:
        return {"ok": True}

    try:
        exp_int = int(exp)
    except (TypeError, ValueError):
        return {"ok": False, "reason": f"VC has non-numeric exp: {exp!r}"}

    now = int(time.time())
    if exp_int + EXP_SKEW_SECONDS < now:
        return {
            "ok": False,
            "reason": (
                f"VC expired locally: exp={exp_int} now={now} "
                f"(skew={EXP_SKEW_SECONDS}s)"
            ),
        }
    return {"ok": True}
