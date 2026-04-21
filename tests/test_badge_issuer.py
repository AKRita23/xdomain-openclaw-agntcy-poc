"""Tests for :class:`identity.badge_issuer.BadgeIssuer`.

Covers the real well-known fetch path: success, missing env var, empty
``vcs`` array, upstream HTTP errors, and the returned badge shape. HTTP
is mocked with respx so no live AGNTCY node is required.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from identity.badge_issuer import BadgeIssuer


WELL_KNOWN_URL = (
    "http://identity.test:4000/v1alpha1/vc/AGNTCY-abc/.well-known/vcs.json"
)
FAKE_VC_JWT = "eyJhbGciOiJFZERTQSJ9.payload.signature"


@pytest.fixture
def issuer():
    return BadgeIssuer(identity_service_url="http://identity.test:4000")


@pytest.fixture
def env_set(monkeypatch):
    monkeypatch.setenv("AGNTCY_BADGE_WELL_KNOWN", WELL_KNOWN_URL)
    monkeypatch.setenv("AGNTCY_BADGE_ID", "badge-abc-123")


@pytest.mark.asyncio
async def test_issue_badge_fetches_from_well_known(issuer, env_set):
    with respx.mock(assert_all_called=True) as mock:
        mock.get(WELL_KNOWN_URL).mock(
            return_value=httpx.Response(200, json={
                "vcs": [{
                    "envelopeType": "CREDENTIAL_ENVELOPE_TYPE_JOSE",
                    "value": FAKE_VC_JWT,
                }],
            })
        )
        badge = await issuer.issue_badge(
            agent_id="openclaw-agent-001",
            delegating_user="sarah@example.com",
            issuer_did="did:web:example.com:issuer",
            task_scopes=["weather:read"],
        )

    assert badge["jwt"] == FAKE_VC_JWT
    assert badge["badge_id"] == "badge-abc-123"
    assert badge["agent_id"] == "openclaw-agent-001"
    assert badge["delegating_user"] == "sarah@example.com"
    assert badge["issuer_did"] == "did:web:example.com:issuer"
    assert badge["task_scopes"] == ["weather:read"]
    assert badge["issued_at"].endswith("Z")


@pytest.mark.asyncio
async def test_issue_badge_has_all_required_fields(issuer, env_set):
    with respx.mock:
        respx.get(WELL_KNOWN_URL).mock(
            return_value=httpx.Response(200, json={
                "vcs": [{"value": FAKE_VC_JWT}],
            })
        )
        badge = await issuer.issue_badge(
            agent_id="agent-x",
            delegating_user="u@x.test",
            issuer_did="did:web:x",
        )

    for key in ("badge_id", "agent_id", "delegating_user",
                "issuer_did", "jwt", "issued_at", "task_scopes"):
        assert key in badge, f"badge missing {key}"
    assert badge["task_scopes"] == []


@pytest.mark.asyncio
async def test_issue_badge_falls_back_to_agent_id_when_badge_id_unset(
    issuer, monkeypatch,
):
    monkeypatch.setenv("AGNTCY_BADGE_WELL_KNOWN", WELL_KNOWN_URL)
    monkeypatch.delenv("AGNTCY_BADGE_ID", raising=False)

    with respx.mock:
        respx.get(WELL_KNOWN_URL).mock(
            return_value=httpx.Response(200, json={
                "vcs": [{"value": FAKE_VC_JWT}],
            })
        )
        badge = await issuer.issue_badge(
            agent_id="openclaw-agent-001",
            delegating_user="s@x.test",
            issuer_did="did:web:x",
        )

    assert badge["badge_id"] == "openclaw-agent-001"


@pytest.mark.asyncio
async def test_issue_badge_raises_when_well_known_env_missing(
    issuer, monkeypatch,
):
    monkeypatch.delenv("AGNTCY_BADGE_WELL_KNOWN", raising=False)
    with pytest.raises(RuntimeError, match="AGNTCY_BADGE_WELL_KNOWN"):
        await issuer.issue_badge(
            agent_id="a", delegating_user="u", issuer_did="did:web:x",
        )


@pytest.mark.asyncio
async def test_issue_badge_raises_when_vcs_empty(issuer, env_set):
    with respx.mock:
        respx.get(WELL_KNOWN_URL).mock(
            return_value=httpx.Response(200, json={"vcs": []})
        )
        with pytest.raises(RuntimeError, match="empty 'vcs'"):
            await issuer.issue_badge(
                agent_id="a", delegating_user="u", issuer_did="did:web:x",
            )


@pytest.mark.asyncio
async def test_issue_badge_raises_when_value_missing(issuer, env_set):
    with respx.mock:
        respx.get(WELL_KNOWN_URL).mock(
            return_value=httpx.Response(200, json={
                "vcs": [{"envelopeType": "CREDENTIAL_ENVELOPE_TYPE_JOSE"}],
            })
        )
        with pytest.raises(RuntimeError, match="'value' JWT"):
            await issuer.issue_badge(
                agent_id="a", delegating_user="u", issuer_did="did:web:x",
            )


@pytest.mark.asyncio
async def test_issue_badge_raises_on_500_response(issuer, env_set):
    with respx.mock:
        respx.get(WELL_KNOWN_URL).mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )
        with pytest.raises(RuntimeError, match="HTTP 500"):
            await issuer.issue_badge(
                agent_id="a", delegating_user="u", issuer_did="did:web:x",
            )


@pytest.mark.asyncio
async def test_issue_badge_raises_on_network_error(issuer, env_set):
    with respx.mock:
        respx.get(WELL_KNOWN_URL).mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        with pytest.raises(RuntimeError, match="Failed to fetch badge"):
            await issuer.issue_badge(
                agent_id="a", delegating_user="u", issuer_did="did:web:x",
            )
