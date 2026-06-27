"""Tests for the CIMD projection (Phase 2).

Covers the four cases the brief mandates plus the document-shape
assertion:
  1. CIMD doc contains ``vc+jwt`` + self-referential ``client_id``.
  2. Resolver rejects a document whose ``client_id`` ≠ fetched URL.
  3. Resolver extracts the badge and verification succeeds for valid,
     fails for tampered.
  4. Resolver rejects a badge whose verified ``agent_id`` /
     ``delegating_user`` don't match the CIMD document's declared
     identity (Phase-1 fix #4 inheritance).

Plus integration-style checks:
  * CIMD server endpoint returns a self-consistent document.
  * Builder asserts self-reference + non-empty invariants.
  * Orchestrator wired through CIMD discovery converges on the same
    badge that lands in the actor_token presentation.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from agent.config import AgentConfig, MCPServerConfig
from agent.xaa_orchestrator import XAAFlowError, XAAOrchestrator
from identity.badge_verifier import BadgeVerifier
from identity.cimd_document import (
    CIMDDocumentError,
    CIMDDocumentSpec,
    VC_JWT_FIELD,
    build_cimd_document,
    cimd_document_self_url,
)
from identity.cimd_resolver import CIMDResolutionError, CIMDResolver
from identity.cimd_server import create_app
from identity.resource_exchange import CachedTokenStore


# --------------------------------------------------------------------------- fixtures


FAKE_BADGE_JWT = "eyJ.fake.badge"
AGENT_ID = "openclaw-agent-001"
DELEGATING_USER = "sarah@example.com"
SELF_URL = "https://cimd.test/.well-known/cimd/AGNTCY-abc"
JWKS_URI = "http://identity.test/v1alpha1/issuer/openclaw/.well-known/jwks.json"


def _fresh_iso() -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()


def _verifier_payload(
    *,
    agent_id: str = AGENT_ID,
    delegating_user: str = DELEGATING_USER,
):
    """Identity Node response body shape consumed by ``_verify_vc_jwt``."""
    return {
        "status": True,
        "document": {
            "issuer": "did:web:example.com:issuer",
            "issuanceDate": _fresh_iso(),
            "content": {
                "id": "badge-test-001",
                "badge": json.dumps({
                    "capabilities": ["weather:read", "slack:chat:write"],
                    "delegating_user": delegating_user,
                    "agent_id": agent_id,
                }),
            },
        },
    }


def _make_spec(self_url: str = SELF_URL) -> CIMDDocumentSpec:
    return CIMDDocumentSpec(
        self_url=self_url,
        client_name="OpenClaw Cross-Domain Agent",
        agent_id=AGENT_ID,
        delegating_user=DELEGATING_USER,
        jwks_uri=JWKS_URI,
    )


# --------------------------------------------------------------------------- (#1) document shape


def test_cimd_document_contains_vc_jwt_and_self_referential_client_id():
    doc = build_cimd_document(_make_spec(), badge_jwt=FAKE_BADGE_JWT)

    assert doc["client_id"] == SELF_URL
    assert doc[VC_JWT_FIELD] == FAKE_BADGE_JWT
    assert doc["client_name"] == "OpenClaw Cross-Domain Agent"
    assert doc["grant_types"] == [
        "urn:ietf:params:oauth:grant-type:token-exchange",
    ]
    assert doc["token_endpoint_auth_method"] == "private_key_jwt"
    assert doc["jwks_uri"] == JWKS_URI
    assert doc["agent_id"] == AGENT_ID
    assert doc["delegating_user"] == DELEGATING_USER


def test_cimd_builder_rejects_empty_badge_jwt():
    with pytest.raises(CIMDDocumentError):
        build_cimd_document(_make_spec(), badge_jwt="")


def test_cimd_builder_rejects_empty_declared_identity():
    spec = CIMDDocumentSpec(
        self_url=SELF_URL,
        client_name="x",
        agent_id="",  # invalid
        delegating_user=DELEGATING_USER,
        jwks_uri=JWKS_URI,
    )
    with pytest.raises(CIMDDocumentError, match="agent_id"):
        build_cimd_document(spec, badge_jwt=FAKE_BADGE_JWT)


def test_self_url_helper_produces_canonical_path():
    assert (
        cimd_document_self_url("http://cimd.test", "AGNTCY-abc")
        == "http://cimd.test/.well-known/cimd/AGNTCY-abc"
    )
    # Trailing slash on base URL must not produce a double slash.
    assert (
        cimd_document_self_url("http://cimd.test/", "AGNTCY-abc")
        == "http://cimd.test/.well-known/cimd/AGNTCY-abc"
    )


# --------------------------------------------------------------------------- (#2) self-ref check


@pytest.mark.asyncio
async def test_resolver_rejects_self_reference_mismatch():
    """A document fetched from URL X but declaring client_id=Y must be rejected."""
    resolver = CIMDResolver(BadgeVerifier("http://identity.test"))
    tampered_doc = build_cimd_document(
        _make_spec(self_url="https://other.test/cimd/AGNTCY-abc"),
        badge_jwt=FAKE_BADGE_JWT,
    )
    with respx.mock:
        respx.get(SELF_URL).mock(
            return_value=httpx.Response(200, json=tampered_doc)
        )
        with pytest.raises(CIMDResolutionError) as excinfo:
            await resolver.resolve(SELF_URL)
    assert "self-reference mismatch" in excinfo.value.reason
    assert excinfo.value.cimd_client_id == SELF_URL


# --------------------------------------------------------------------------- (#3) verify pass / tampered fail


@pytest.mark.asyncio
async def test_resolver_succeeds_for_valid_badge():
    resolver = CIMDResolver(BadgeVerifier("http://identity.test"))
    doc = build_cimd_document(_make_spec(), badge_jwt=FAKE_BADGE_JWT)
    with respx.mock:
        respx.get(SELF_URL).mock(return_value=httpx.Response(200, json=doc))
        respx.post("http://identity.test/v1alpha1/vc/verify").mock(
            return_value=httpx.Response(200, json=_verifier_payload())
        )
        resolved = await resolver.resolve(SELF_URL)

    assert resolved.cimd_client_id == SELF_URL
    assert resolved.badge_jwt == FAKE_BADGE_JWT
    assert resolved.agent_id == AGENT_ID
    assert resolved.delegating_user == DELEGATING_USER
    assert "weather:read" in resolved.capabilities


@pytest.mark.asyncio
async def test_resolver_fails_when_identity_node_rejects_tampered_badge():
    """If the AGNTCY node says ``status: false`` (e.g. tampered signature)
    the resolver must surface a CIMDResolutionError with the node's reason."""
    resolver = CIMDResolver(BadgeVerifier("http://identity.test"))
    doc = build_cimd_document(_make_spec(), badge_jwt=FAKE_BADGE_JWT)
    with respx.mock:
        respx.get(SELF_URL).mock(return_value=httpx.Response(200, json=doc))
        respx.post("http://identity.test/v1alpha1/vc/verify").mock(
            return_value=httpx.Response(200, json={
                "status": False,
                "errors": ["ERROR_REASON_INVALID_SIGNATURE"],
            })
        )
        with pytest.raises(CIMDResolutionError) as excinfo:
            await resolver.resolve(SELF_URL)

    assert "badge verification failed" in excinfo.value.reason
    assert "ERROR_REASON_INVALID_SIGNATURE" in excinfo.value.reason


# --------------------------------------------------------------------------- (#4) Phase-1 #4 inheritance


@pytest.mark.asyncio
async def test_resolver_rejects_badge_whose_agent_id_mismatches_declared():
    """The CIMD document declares ``agent_id=openclaw-agent-001`` but the
    verified badge claims a different agent — the resolver must reject."""
    resolver = CIMDResolver(BadgeVerifier("http://identity.test"))
    doc = build_cimd_document(_make_spec(), badge_jwt=FAKE_BADGE_JWT)
    with respx.mock:
        respx.get(SELF_URL).mock(return_value=httpx.Response(200, json=doc))
        respx.post("http://identity.test/v1alpha1/vc/verify").mock(
            return_value=httpx.Response(
                200, json=_verifier_payload(agent_id="some-other-agent"),
            )
        )
        with pytest.raises(CIMDResolutionError) as excinfo:
            await resolver.resolve(SELF_URL)

    assert "badge verification failed" in excinfo.value.reason
    assert "agent_id mismatch" in excinfo.value.reason


@pytest.mark.asyncio
async def test_resolver_rejects_badge_whose_user_mismatches_declared():
    resolver = CIMDResolver(BadgeVerifier("http://identity.test"))
    doc = build_cimd_document(_make_spec(), badge_jwt=FAKE_BADGE_JWT)
    with respx.mock:
        respx.get(SELF_URL).mock(return_value=httpx.Response(200, json=doc))
        respx.post("http://identity.test/v1alpha1/vc/verify").mock(
            return_value=httpx.Response(
                200, json=_verifier_payload(delegating_user="mallory@evil.test"),
            )
        )
        with pytest.raises(CIMDResolutionError) as excinfo:
            await resolver.resolve(SELF_URL)

    assert "delegating_user mismatch" in excinfo.value.reason


# --------------------------------------------------------------------------- resolver missing fields


@pytest.mark.asyncio
async def test_resolver_rejects_document_missing_vc_jwt():
    resolver = CIMDResolver(BadgeVerifier("http://identity.test"))
    incomplete = {
        "client_id": SELF_URL,
        "client_name": "x",
        "agent_id": AGENT_ID,
        "delegating_user": DELEGATING_USER,
        # no vc+jwt
    }
    with respx.mock:
        respx.get(SELF_URL).mock(
            return_value=httpx.Response(200, json=incomplete)
        )
        with pytest.raises(CIMDResolutionError, match="vc\\+jwt"):
            await resolver.resolve(SELF_URL)


@pytest.mark.asyncio
async def test_resolver_rejects_document_missing_declared_identity():
    resolver = CIMDResolver(BadgeVerifier("http://identity.test"))
    incomplete = {
        "client_id": SELF_URL,
        "client_name": "x",
        VC_JWT_FIELD: FAKE_BADGE_JWT,
        # no agent_id / delegating_user
    }
    with respx.mock:
        respx.get(SELF_URL).mock(
            return_value=httpx.Response(200, json=incomplete)
        )
        with pytest.raises(CIMDResolutionError, match="declared identity"):
            await resolver.resolve(SELF_URL)


# --------------------------------------------------------------------------- CIMD server


def test_cimd_server_serves_self_consistent_document(monkeypatch):
    monkeypatch.setenv("CIMD_BASE_URL", "http://cimd.test")
    monkeypatch.setenv("AGNTCY_NODE_URL", "http://identity.test")
    monkeypatch.setenv("AGNTCY_ISSUER_JWKS_URI", JWKS_URI)
    monkeypatch.setenv("AGENT_CLIENT_NAME", "OpenClaw Cross-Domain Agent")
    monkeypatch.setenv("AGENT_DECLARED_ID", AGENT_ID)
    monkeypatch.setenv("AGENT_DECLARED_USER", DELEGATING_USER)

    well_known = (
        "http://identity.test/v1alpha1/vc/AGNTCY-abc/.well-known/vcs.json"
    )

    with respx.mock:
        respx.get(well_known).mock(return_value=httpx.Response(200, json={
            "vcs": [{
                "envelopeType": "CREDENTIAL_ENVELOPE_TYPE_JOSE",
                "value": FAKE_BADGE_JWT,
            }],
        }))
        client = TestClient(create_app())
        resp = client.get("/.well-known/cimd/AGNTCY-abc")

    assert resp.status_code == 200
    body = resp.json()
    # Self-reference: client_id matches the URL the test client fetched.
    assert body["client_id"] == "http://cimd.test/.well-known/cimd/AGNTCY-abc"
    assert body[VC_JWT_FIELD] == FAKE_BADGE_JWT
    assert body["agent_id"] == AGENT_ID
    assert body["delegating_user"] == DELEGATING_USER


def test_cimd_server_returns_503_when_unconfigured(monkeypatch):
    """Fail-fast: if required env vars are missing the endpoint reports 503."""
    for key in (
        "CIMD_BASE_URL", "AGNTCY_NODE_URL", "AGNTCY_ISSUER_JWKS_URI",
        "AGENT_CLIENT_NAME", "AGENT_DECLARED_ID", "AGENT_DECLARED_USER",
    ):
        monkeypatch.delenv(key, raising=False)
    client = TestClient(create_app())
    resp = client.get("/.well-known/cimd/anything")
    assert resp.status_code == 503


# --------------------------------------------------------------------------- orchestrator wiring


@pytest.mark.asyncio
async def test_orchestrator_cimd_discovery_path(monkeypatch):
    """CIMD-enabled orchestrator resolves the badge via CIMD and feeds the
    same JWT into the downstream pipeline (actor_token convergence)."""
    cfg = AgentConfig(
        identity_service_url="http://identity.test",
        use_cimd_discovery=True,
        cimd_client_id=SELF_URL,
        mcp_servers={
            "weather": MCPServerConfig(
                name="weather", url="http://weather.test",
                auth_domain="api.open-meteo.com", scopes=["weather:read"],
            ),
            "slack": MCPServerConfig(
                name="slack", url="http://slack.test",
                auth_domain="slack.com", scopes=["slack:chat:write"],
            ),
        },
    )

    # Build a CIMDResolver that uses a real BadgeVerifier hitting a mocked
    # identity node — this exercises the full resolver path end-to-end.
    verifier = BadgeVerifier("http://identity.test")
    cimd_resolver = CIMDResolver(verifier)

    badge_issuer = MagicMock()
    badge_issuer.issue_badge = AsyncMock(side_effect=AssertionError(
        "BadgeIssuer.issue_badge must NOT be called on the CIMD path"
    ))

    # Step-2 verifier is a separate instance — replace its verify_badge so
    # we control what step 2 sees independently of the resolver's verifier.
    step2_verifier = MagicMock()
    step2_verifier.verify_badge = AsyncMock(return_value={
        "valid": True, "badge_id": "badge-test-001",
        "capabilities": ["weather:read"],
        "delegating_user": DELEGATING_USER,
        "agent_id": AGENT_ID,
        "issuance_date": _fresh_iso(),
    })

    xaa_client = MagicMock()
    xaa_client.exchange_token = AsyncMock(return_value={
        "access_token": "okta.id-jag.jwt",
        "token_type": "Bearer",
        "expires_in": 300,
    })

    middleware = MagicMock()
    middleware.enforce = AsyncMock(return_value=None)

    weather_client = MagicMock()
    weather_client.config = cfg.mcp_servers["weather"]
    weather_client.call = AsyncMock(return_value={
        "tool": "get_current_weather", "result": {"location": "Austin, TX"},
    })
    slack_client = MagicMock()
    slack_client.config = cfg.mcp_servers["slack"]
    slack_client.call = AsyncMock(return_value={
        "tool": "slack_post_message", "result": {"ok": True},
    })

    from identity.resource_exchange import ResourceAccessToken
    import time as _time
    monkeypatch.setattr(
        "agent.xaa_orchestrator.exchange_id_jag_for_access_token",
        lambda id_jag, client_id, scope: ResourceAccessToken(
            access_token="minted.access.token",
            token_type="Bearer", expires_in=3600,
            scope="weather:read",
            expires_at=int(_time.time()) + 3600,
        ),
    )
    monkeypatch.setenv("SLACK_CHANNEL", "#xaa-demo")

    orchestrator = XAAOrchestrator(
        config=cfg,
        badge_issuer=badge_issuer,
        badge_verifier=step2_verifier,
        xaa_client=xaa_client,
        middleware=middleware,
        weather_client=weather_client,
        slack_client=slack_client,
        token_cache=CachedTokenStore(),
        cimd_resolver=cimd_resolver,
        cimd_client_id=SELF_URL,
    )

    doc = build_cimd_document(_make_spec(), badge_jwt=FAKE_BADGE_JWT)
    with respx.mock:
        respx.get(SELF_URL).mock(return_value=httpx.Response(200, json=doc))
        respx.post("http://identity.test/v1alpha1/vc/verify").mock(
            return_value=httpx.Response(200, json=_verifier_payload())
        )
        result = await orchestrator.execute(
            task_name="weather_slack_notification",
            target_audience="api.open-meteo.com",
            scopes=["weather:read"],
            subject=DELEGATING_USER,
        )

    # CIMD-discovered badge JWT is the one sent as actor_token in step 3
    # (Phase-1 fix #5 + Phase-2 convergence).
    xaa_call = xaa_client.exchange_token.await_args
    assert xaa_call.kwargs["badge_jwt"] == FAKE_BADGE_JWT
    assert xaa_call.kwargs["subject_token"] == FAKE_BADGE_JWT

    # Legacy BadgeIssuer must not have run.
    badge_issuer.issue_badge.assert_not_called()

    assert result.mcp_result["weather"]["result"]["location"] == "Austin, TX"


@pytest.mark.asyncio
async def test_orchestrator_surfaces_cimd_failure_as_step_1(monkeypatch):
    cfg = AgentConfig(
        identity_service_url="http://identity.test",
        use_cimd_discovery=True,
        cimd_client_id=SELF_URL,
        mcp_servers={
            "weather": MCPServerConfig(
                name="weather", url="", auth_domain="x", scopes=[],
            ),
            "slack": MCPServerConfig(
                name="slack", url="", auth_domain="x", scopes=[],
            ),
        },
    )
    cimd_resolver = CIMDResolver(BadgeVerifier("http://identity.test"))

    orchestrator = XAAOrchestrator(
        config=cfg,
        badge_issuer=MagicMock(),
        badge_verifier=MagicMock(),
        xaa_client=MagicMock(),
        middleware=MagicMock(),
        weather_client=MagicMock(),
        slack_client=MagicMock(),
        cimd_resolver=cimd_resolver,
        cimd_client_id=SELF_URL,
    )

    with respx.mock:
        respx.get(SELF_URL).mock(return_value=httpx.Response(404, text="nope"))
        with pytest.raises(XAAFlowError) as excinfo:
            await orchestrator.execute(
                task_name="t",
                target_audience="x",
                scopes=["weather:read"],
                subject=DELEGATING_USER,
            )
    assert excinfo.value.step == 1
    assert "CIMD" in excinfo.value.reason
