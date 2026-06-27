"""
CIMD (Client ID Metadata Document) builder.

CIMD here is a *projection* of the existing AGNTCY identity-node
registration: each agent already has a ``metadata_id`` and a badge JWT
published at AGNTCY's well-known endpoint. The CIMD document carries
that same badge inline (as ``vc+jwt``) inside an OAuth-client-shaped
JSON envelope so consumers can dereference a single URL — the
``client_id`` — and discover both the agent's OAuth client metadata
and its AGNTCY identity credential in one round-trip.

No new registry is introduced; no draft-narajala / LF-ANS adoption.
The CIMD document's authority is exactly the authority of the AGNTCY
badge it embeds, which is verified by :class:`BadgeVerifier` on the
consumer side.

The document satisfies the **self-reference invariant**: the value of
its top-level ``client_id`` field MUST equal the URL the document is
served from. :func:`build_cimd_document` asserts this at construction
so a misconfigured server fails loudly at startup rather than producing
a document a resolver will (correctly) reject.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from identity.badge_verifier import fetch_first_vc_jwt

GRANT_TYPES_DEFAULT: List[str] = [
    "urn:ietf:params:oauth:grant-type:token-exchange",
]
TOKEN_ENDPOINT_AUTH_METHOD = "private_key_jwt"

# The CIMD field name carrying the inline AGNTCY badge JWT.
# Spelled with a "+" because the value's media type is application/vc+jwt
# (W3C Verifiable Credential, JWT-encoded). Field name preserves that
# media-type tag so consumers can match on the literal "vc+jwt" key.
VC_JWT_FIELD = "vc+jwt"


class CIMDDocumentError(Exception):
    """Raised when a CIMD document cannot be built (e.g. self-ref violation)."""


@dataclass(frozen=True)
class CIMDDocumentSpec:
    """Static inputs for :func:`build_cimd_document`.

    Kept as a frozen dataclass so a CIMD server can construct one from
    its config at startup and reuse it per-request; values never change
    over the lifetime of a deployed agent identity.
    """

    self_url: str  # The URL the document will be served from.
    client_name: str
    agent_id: str  # Declared agent identity; verifier MUST match.
    delegating_user: str  # Declared delegating user; verifier MUST match.
    jwks_uri: str  # AGNTCY issuer JWKS URL.
    grant_types: List[str] = field(
        default_factory=lambda: list(GRANT_TYPES_DEFAULT)
    )


def build_cimd_document(
    spec: CIMDDocumentSpec, badge_jwt: str,
) -> Dict[str, Any]:
    """Construct the CIMD JSON document for an agent.

    Returns a dict with:
      * ``client_id``                  — equal to ``spec.self_url`` (self-ref)
      * ``client_name``                — human-readable agent name
      * ``grant_types``                — defaults to token-exchange only
      * ``token_endpoint_auth_method`` — ``private_key_jwt``
      * ``jwks_uri``                   — AGNTCY issuer JWKS URL
      * ``agent_id``                   — declared identity claim
      * ``delegating_user``            — declared delegation claim
      * ``vc+jwt``                     — the inline AGNTCY badge JWT

    The ``agent_id`` and ``delegating_user`` fields are **declared
    claims** the document makes about the embedded badge. The resolver
    proves they match the badge's verified content via Phase-1
    :meth:`BadgeVerifier.verify_badge` identity binding — so a hostile
    CIMD endpoint cannot pair a valid badge with mismatched declared
    identity.

    Raises:
        CIMDDocumentError: if the badge JWT is empty, the self URL is
            empty, or any other invariant is violated.
    """
    if not spec.self_url:
        raise CIMDDocumentError("spec.self_url must be non-empty")
    if not badge_jwt:
        raise CIMDDocumentError("badge_jwt must be non-empty")
    if not spec.agent_id:
        raise CIMDDocumentError("spec.agent_id must be non-empty")
    if not spec.delegating_user:
        raise CIMDDocumentError("spec.delegating_user must be non-empty")

    document: Dict[str, Any] = {
        "client_id": spec.self_url,
        "client_name": spec.client_name,
        "grant_types": list(spec.grant_types),
        "token_endpoint_auth_method": TOKEN_ENDPOINT_AUTH_METHOD,
        "jwks_uri": spec.jwks_uri,
        "agent_id": spec.agent_id,
        "delegating_user": spec.delegating_user,
        VC_JWT_FIELD: badge_jwt,
    }

    # Self-reference invariant — fail loudly here, not at the resolver.
    if document["client_id"] != spec.self_url:
        raise CIMDDocumentError(
            "self-reference invariant violated: "
            f"client_id={document['client_id']!r} != self_url={spec.self_url!r}"
        )
    return document


async def build_cimd_document_from_agntcy(
    spec: CIMDDocumentSpec,
    agntcy_node_url: str,
    agntcy_metadata_id: str,
) -> Dict[str, Any]:
    """Fetch the badge from the AGNTCY well-known endpoint and build the doc.

    Convenience wrapper used by :mod:`identity.cimd_server` — fetches
    the same VC JWT that :class:`BadgeVerifier` consumes, so the CIMD
    projection and the standalone badge-verify path provably reference
    the same artifact. The "no new registry" promise depends on this.

    Multi-VC safety: ``spec.agent_id`` is passed as
    ``expected_agent_id`` so a well-known endpoint hosting badges for
    multiple agents under the same ``metadata_id`` returns the badge
    the CIMD document is being built FOR. The selector is unverified
    (lightweight disambiguation); the resolver's downstream
    cryptographic check still binds the badge's verified content to
    the document's declared identity.
    """
    badge_jwt = await fetch_first_vc_jwt(
        agntcy_node_url,
        agntcy_metadata_id,
        expected_agent_id=spec.agent_id,
    )
    return build_cimd_document(spec, badge_jwt)


def cimd_document_self_url(base_url: str, metadata_id: str) -> str:
    """Canonical CIMD URL for an agent's ``metadata_id``.

    Used by both the server (to set ``client_id`` correctly) and the
    deployer (to publish the URL as the agent's OAuth ``client_id``).
    """
    return f"{base_url.rstrip('/')}/.well-known/cimd/{metadata_id}"
