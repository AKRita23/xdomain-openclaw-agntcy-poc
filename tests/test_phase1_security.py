"""Phase-1 security-hardening tests.

Five focused assertions on the new contract from the security audit:
  1. Wrong-identity badge rejected (verifier identity binding)
  2. Empty-scope badge denied (TBAC verified-caps requirement)
  3. Expired badge denied (TBAC issuance_date TTL gate)
  4. Out-of-capability scope denied + subset allowed (TBAC scope check
     reads from verifier result, not caller dict)
  5. Exchange includes actor_token and the IdJag response records ``act``
     presence/absence (fix #5: reproducible observation)
"""
from __future__ import annotations

import base64
import json
import logging
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from identity.badge_verifier import BadgeVerifier
from identity.okta_xaa import OktaXAAClient
from identity.xaa_dev_client import (
    JWT_TOKEN_TYPE,
    XAADevClient,
    XAADevConfig,
)
from middleware.agntcy_tbac import IdentityServiceMCPMiddleware, TBACViolation


# --------------------------------------------------------------------------- helpers


def _b64u(payload: dict) -> str:
    raw = json.dumps(payload).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _jwt_with(claims: dict) -> str:
    """Build an unsigned JWT carrying the supplied claims."""
    header = _b64u({"alg": "RS256", "typ": "JWT"})
    payload = _b64u(claims)
    return f"{header}.{payload}.sig"


def _fresh_iso() -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()


def _verifier_payload(
    *,
    capabilities=None,
    delegating_user="sarah@example.com",
    agent_id="openclaw-agent-001",
    badge_id="badge-x",
):
    """Identity Node response body shape consumed by ``_verify_vc_jwt``."""
    badge_content = {
        "capabilities": capabilities if capabilities is not None else ["weather:read"],
        "delegating_user": delegating_user,
        "agent_id": agent_id,
    }
    return {
        "status": True,
        "document": {
            "issuer": "did:web:example.com:issuer",
            "issuanceDate": _fresh_iso(),
            "content": {
                "id": badge_id,
                "badge": json.dumps(badge_content),
            },
        },
    }


# --------------------------------------------------------------------------- #1 wrong identity


@pytest.mark.asyncio
async def test_badge_verifier_rejects_wrong_agent_id():
    verifier = BadgeVerifier("http://identity.test")
    with respx.mock:
        respx.post("http://identity.test/v1alpha1/vc/verify").mock(
            return_value=httpx.Response(
                200, json=_verifier_payload(agent_id="some-other-agent"),
            )
        )
        result = await verifier.verify_badge(
            {"jwt": "eyJ.fake.jwt"},
            expected_agent_id="openclaw-agent-001",
            expected_user="sarah@example.com",
        )
    assert result["valid"] is False
    assert "agent_id mismatch" in result["reason"]


@pytest.mark.asyncio
async def test_badge_verifier_rejects_wrong_user():
    verifier = BadgeVerifier("http://identity.test")
    with respx.mock:
        respx.post("http://identity.test/v1alpha1/vc/verify").mock(
            return_value=httpx.Response(
                200, json=_verifier_payload(delegating_user="mallory@evil.test"),
            )
        )
        result = await verifier.verify_badge(
            {"jwt": "eyJ.fake.jwt"},
            expected_agent_id="openclaw-agent-001",
            expected_user="sarah@example.com",
        )
    assert result["valid"] is False
    assert "delegating_user mismatch" in result["reason"]


@pytest.mark.asyncio
async def test_badge_verifier_accepts_matching_identity():
    verifier = BadgeVerifier("http://identity.test")
    with respx.mock:
        respx.post("http://identity.test/v1alpha1/vc/verify").mock(
            return_value=httpx.Response(200, json=_verifier_payload())
        )
        result = await verifier.verify_badge(
            {"jwt": "eyJ.fake.jwt"},
            expected_agent_id="openclaw-agent-001",
            expected_user="sarah@example.com",
        )
    assert result["valid"] is True


# --------------------------------------------------------------------------- envelope type


@pytest.mark.asyncio
async def test_fetch_and_verify_skips_wrong_envelope_type():
    """A VC with the wrong envelope type must be skipped, not blindly trusted."""
    verifier = BadgeVerifier("http://identity.test", metadata_id="AGNTCY-x")
    well_known = "http://identity.test/v1alpha1/vc/AGNTCY-x/.well-known/vcs.json"
    with respx.mock:
        respx.get(well_known).mock(return_value=httpx.Response(200, json={
            "vcs": [
                {"envelopeType": "SOMETHING_ELSE", "value": "should-skip"},
                {"envelopeType": "CREDENTIAL_ENVELOPE_TYPE_JOSE",
                 "value": "eyJ.real.jwt"},
            ],
        }))
        respx.post("http://identity.test/v1alpha1/vc/verify").mock(
            return_value=httpx.Response(200, json=_verifier_payload())
        )
        result = await verifier.fetch_and_verify(
            expected_agent_id="openclaw-agent-001",
            expected_user="sarah@example.com",
        )
    assert result["valid"] is True


# --------------------------------------------------------------------------- VC exp gate


@pytest.mark.asyncio
async def test_badge_verifier_local_exp_gate_rejects_stale_vc():
    """Node says 'status: true' but VC ``exp`` already passed → DENY."""
    verifier = BadgeVerifier("http://identity.test")
    stale_token = _jwt_with({"exp": int(datetime.now(tz=timezone.utc).timestamp()) - 3600})
    with respx.mock:
        respx.post("http://identity.test/v1alpha1/vc/verify").mock(
            return_value=httpx.Response(200, json=_verifier_payload())
        )
        result = await verifier.verify_badge({"jwt": stale_token})
    assert result["valid"] is False
    assert "expired locally" in result["reason"]


# --------------------------------------------------------------------------- #2 empty scopes


@pytest.mark.asyncio
async def test_tbac_denies_badge_with_empty_verified_scopes():
    mw = IdentityServiceMCPMiddleware("http://identity.test")
    mw.verifier.verify_badge = AsyncMock(return_value={
        "valid": True, "badge_id": "x",
        "capabilities": [], "issuance_date": _fresh_iso(),
    })
    with pytest.raises(TBACViolation, match="no authorized scopes"):
        await mw.enforce(
            badge={"jwt": "x"},
            target_server="weather",
            requested_scopes=["weather:read"],
            xaa_token={"access_token": "t"},
        )


# --------------------------------------------------------------------------- #3 expired badge


@pytest.mark.asyncio
async def test_tbac_denies_expired_badge_via_verifier_issuance_date():
    mw = IdentityServiceMCPMiddleware("http://identity.test")
    old = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
    mw.verifier.verify_badge = AsyncMock(return_value={
        "valid": True, "badge_id": "x",
        "capabilities": ["weather:read"], "issuance_date": old,
    })
    with pytest.raises(TBACViolation, match="exceeded 24h TTL"):
        await mw.enforce(
            badge={"jwt": "x"},
            target_server="weather",
            requested_scopes=["weather:read"],
            xaa_token={"access_token": "t"},
        )


# --------------------------------------------------------------------------- #4 scope subset


@pytest.mark.asyncio
async def test_tbac_denies_scope_not_in_verified_capabilities():
    mw = IdentityServiceMCPMiddleware("http://identity.test")
    mw.verifier.verify_badge = AsyncMock(return_value={
        "valid": True, "badge_id": "x",
        "capabilities": ["weather:read"], "issuance_date": _fresh_iso(),
    })
    with pytest.raises(TBACViolation, match="Scope escalation"):
        await mw.enforce(
            # Caller dict CLAIMS the scope — ignored.
            badge={"jwt": "x", "task_scopes": ["slack:admin"]},
            target_server="weather",
            requested_scopes=["slack:admin"],
            xaa_token={"access_token": "t"},
        )


@pytest.mark.asyncio
async def test_tbac_allows_subset_of_verified_capabilities():
    mw = IdentityServiceMCPMiddleware("http://identity.test")
    mw.verifier.verify_badge = AsyncMock(return_value={
        "valid": True, "badge_id": "x",
        "capabilities": ["weather:read", "slack:chat:write"],
        "issuance_date": _fresh_iso(),
    })
    await mw.enforce(
        badge={"jwt": "x"},
        target_server="weather",
        requested_scopes=["weather:read"],
        xaa_token={"access_token": "t"},
    )


# --------------------------------------------------------------------------- #5 actor_token


@pytest.mark.asyncio
async def test_xaa_dev_exchange_sends_actor_token_and_logs_act_presence(caplog):
    """Re-wired actor_token reaches the IdP; act-claim observation is logged."""
    config = XAADevConfig(
        idp_url="https://idp.test",
        auth_server_url="https://auth.test",
        client_id="cid", client_secret="csec",
        resource_client_id="rcid", resource_client_secret="rsec",
        redirect_uri="http://localhost:8000/callback",
        resource_audience="http://res.test",
    )
    client = XAADevClient(config)
    badge_jwt = _jwt_with({"sub": "sarah", "iss": "agntcy"})
    id_jag_with_act = _jwt_with({
        "aud": "https://auth.test",
        "sub": "sarah@example.com",
        "act": {"sub": "openclaw-agent-001"},
    })

    with respx.mock(assert_all_called=True) as mock, caplog.at_level(logging.INFO):
        route = mock.post("https://idp.test/token").mock(
            return_value=httpx.Response(200, json={
                "access_token": id_jag_with_act,
                "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
                "token_type": "Bearer",
                "expires_in": 300,
            })
        )
        await client.exchange_id_token_for_id_jag(
            id_token="sarah-id-token", actor_token=badge_jwt,
        )

    sent = dict(httpx.QueryParams(route.calls[0].request.content.decode()))
    assert sent["actor_token"] == badge_jwt
    assert sent["actor_token_type"] == JWT_TOKEN_TYPE
    assert any(
        "act claim PRESENT" in rec.message
        for rec in caplog.records
    )


@pytest.mark.asyncio
async def test_xaa_dev_exchange_logs_act_absent_when_not_echoed(caplog):
    """When the IdP returns an ID-JAG with no ``act`` claim, log it explicitly."""
    config = XAADevConfig(
        idp_url="https://idp.test",
        auth_server_url="https://auth.test",
        client_id="cid", client_secret="csec",
        resource_client_id="rcid", resource_client_secret="rsec",
        redirect_uri="http://localhost:8000/callback",
        resource_audience="http://res.test",
    )
    client = XAADevClient(config)
    badge_jwt = _jwt_with({"sub": "sarah"})
    id_jag_no_act = _jwt_with({"aud": "https://auth.test", "sub": "sarah"})

    with respx.mock, caplog.at_level(logging.INFO):
        respx.post("https://idp.test/token").mock(
            return_value=httpx.Response(200, json={
                "access_token": id_jag_no_act,
                "token_type": "Bearer",
                "expires_in": 300,
            })
        )
        await client.exchange_id_token_for_id_jag(
            id_token="sarah-id-token", actor_token=badge_jwt,
        )

    assert any(
        "act claim ABSENT" in rec.message
        for rec in caplog.records
    )


def test_okta_exchange_data_includes_actor_token_and_type(monkeypatch):
    """White-box: OktaXAAClient now adds actor_token/actor_token_type when
    badge_jwt is supplied. We assert the dict the client would POST.

    This is a synchronous, no-network probe — we monkey-patch the verify
    helpers and capture the form payload by intercepting httpx.AsyncClient.
    """
    import asyncio
    from unittest.mock import AsyncMock, MagicMock, patch

    client = OktaXAAClient(
        domain="dev-test.okta.com",
        client_id="agent-client",
        client_secret="agent-secret",
        org2_domain="dev-test.okta.com",
        resource_app_client_id="res-client",
        resource_app_client_secret="res-secret",
        weather_auth_server_id="aus",
        weather_audience="http://localhost:5001",
    )
    monkeypatch.setattr(client, "load_sarah_token", lambda: "sarah-id-token")

    captured = {}

    class _FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return None
        async def post(self, url, data=None):
            captured["url"] = url
            captured["data"] = dict(data or {})
            resp = MagicMock()
            resp.status_code = 200
            resp.json.return_value = {
                "access_token": _jwt_with({"aud": "http://localhost:5001",
                                            "act": {"sub": "openclaw"}}),
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "weather.read",
            }
            return resp

    badge_jwt = _jwt_with({"sub": "sarah"})
    with patch("identity.okta_xaa.httpx.AsyncClient", _FakeClient):
        asyncio.run(client.exchange_token(
            subject_token="ignored",
            target_audience="http://localhost:5001",
            scopes=["weather.read"],
            badge_jwt=badge_jwt,
        ))

    assert captured["data"]["actor_token"] == badge_jwt
    assert (
        captured["data"]["actor_token_type"]
        == "urn:ietf:params:oauth:token-type:jwt"
    )
