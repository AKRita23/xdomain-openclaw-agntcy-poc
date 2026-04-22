"""
End-to-end XAA flow orchestrator for cross-domain agent demos.

Chains all six layers of the Version A (AGNTCY TBAC) PoC into a single
narrated async function, :func:`execute_xaa_flow` (or its class form
:class:`XAAOrchestrator`). Purely additive — imports existing modules,
does not modify them.

Flow:
    1. Badge fetch           — BadgeIssuer.issue_badge
    2. Badge verify          — BadgeVerifier.verify_badge
    3. Okta ID-JAG request   — OktaXAAClient.exchange_token
    4. Resource exchange     — resource_exchange.exchange_id_jag_for_access_token
    5. TBAC check            — IdentityServiceMCPMiddleware.enforce
    6. MCP call              — WeatherMCPClient.call

Access tokens from step 4 are cached via
:class:`identity.resource_exchange.CachedTokenStore` keyed by
``(client_id, scope, subject)`` — repeat invocations with the same tuple
skip steps 3 + 4 and log them as cache-served.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from agent.config import AgentConfig
from identity.badge_issuer import BadgeIssuer
from identity.badge_verifier import BadgeVerifier
from identity.okta_xaa import OktaXAAClient
from identity.resource_exchange import (
    CachedTokenStore,
    ResourceAccessToken,
    exchange_id_jag_for_access_token,
)
from identity.xaa_dev_client import XAADevClient, XAADevConfig, XAADevError
from mcp_servers.weather_mcp import WeatherMCPClient
from middleware.agntcy_tbac import IdentityServiceMCPMiddleware

logger = logging.getLogger(__name__)


STEP_BADGE_FETCH = 1
STEP_BADGE_VERIFY = 2
STEP_OKTA_IDJAG = 3
STEP_RESOURCE_EXCHANGE = 4
STEP_TBAC = 5
STEP_MCP_CALL = 6
TOTAL_STEPS = 6


class XAAFlowError(Exception):
    """Wraps any layer-boundary failure with the step number that failed."""

    def __init__(self, step: int, reason: str, cause: Optional[BaseException] = None):
        super().__init__(f"step {step}: {reason}")
        self.step = step
        self.reason = reason
        self.__cause__ = cause


@dataclass
class XAAFlowResult:
    """Structured result of a successful XAA flow execution."""

    task_name: str
    subject: str
    target_audience: str
    scopes: List[str]
    badge_id: str
    badge_capabilities: List[Any]
    id_jag_expires_in: int
    access_token_scope: str
    access_token_expires_in: int
    cached: bool
    mcp_result: Dict[str, Any]


@dataclass
class XAAOrchestrator:
    """Dependency-injectable orchestrator for the full XAA flow.

    All collaborators are attributes so tests can replace them. The
    module-level :func:`execute_xaa_flow` constructs the default instance
    from :class:`agent.config.AgentConfig`.

    When ``xaa_dev_client`` is set (USE_XAA_DEV=true path), Steps 3 and 4
    are dispatched through xaa.dev's protocol instead of the Okta + local
    resource auth server; the ``xaa_client`` + resource-exchange callable
    are ignored for those two steps.
    """

    config: AgentConfig
    badge_issuer: BadgeIssuer
    badge_verifier: BadgeVerifier
    xaa_client: OktaXAAClient
    middleware: IdentityServiceMCPMiddleware
    weather_client: WeatherMCPClient
    token_cache: CachedTokenStore = field(default_factory=CachedTokenStore)
    resource_client_id: Optional[str] = None
    xaa_dev_client: Optional[XAADevClient] = None

    @classmethod
    def from_config(
        cls,
        config: Optional[AgentConfig] = None,
        token_cache: Optional[CachedTokenStore] = None,
    ) -> "XAAOrchestrator":
        cfg = config or AgentConfig()
        xaa_dev_client: Optional[XAADevClient] = None
        if cfg.use_xaa_dev:
            xaa_dev_client = XAADevClient(
                XAADevConfig(
                    idp_url=cfg.xaa_idp_url,
                    auth_server_url=cfg.xaa_auth_server_url,
                    client_id=cfg.xaa_client_id,
                    client_secret=cfg.xaa_client_secret,
                    resource_client_id=cfg.xaa_resource_client_id,
                    resource_client_secret=cfg.xaa_resource_client_secret,
                    redirect_uri=cfg.xaa_redirect_uri,
                    resource_audience=cfg.xaa_resource_audience,
                    scope=cfg.xaa_scope,
                )
            )
        return cls(
            config=cfg,
            badge_issuer=BadgeIssuer(cfg.identity_service_url),
            badge_verifier=BadgeVerifier(
                cfg.identity_service_url, metadata_id=cfg.agntcy_metadata_id
            ),
            xaa_client=OktaXAAClient(
                domain=cfg.okta_domain,
                client_id=cfg.okta_client_id,
                client_secret=cfg.okta_client_secret,
                auth_server_id=cfg.okta_auth_server_id,
                audience=cfg.okta_audience,
                token_endpoint=cfg.okta_token_endpoint,
                issuer=cfg.okta_issuer,
                org2_domain=cfg.org2_domain,
                resource_app_client_id=cfg.resource_app_client_id,
                resource_app_client_secret=cfg.resource_app_client_secret,
                weather_auth_server_id=cfg.weather_auth_server_id,
                slack_auth_server_id=cfg.slack_auth_server_id,
                weather_audience=cfg.weather_audience,
                slack_audience=cfg.slack_audience,
                aws_region=cfg.aws_region,
            ),
            middleware=IdentityServiceMCPMiddleware(
                identity_service_url=cfg.identity_service_url,
                metadata_id=cfg.agntcy_metadata_id,
            ),
            weather_client=WeatherMCPClient(cfg.mcp_servers["weather"]),
            token_cache=token_cache or CachedTokenStore(),
            xaa_dev_client=xaa_dev_client,
        )

    async def execute(
        self,
        task_name: str,
        target_audience: str,
        scopes: List[str],
        subject: str,
    ) -> XAAFlowResult:
        """Run the full six-step XAA flow, narrating each step via logging."""
        scope_str = " ".join(scopes)
        client_id = self.resource_client_id or self.config.okta_client_id or "openclaw-agent"

        step = STEP_BADGE_FETCH
        try:
            # ----- Step 1: Badge fetch -----
            logger.info("[1/6] 🎫 Fetching AGNTCY badge for %s...", subject)
            badge = await self.badge_issuer.issue_badge(
                agent_id=self.config.agent_id,
                delegating_user=subject,
                issuer_did=self.config.issuer_did,
                task_scopes=scopes,
            )
            badge_id = badge.get("badge_id", "<unknown>")
            issuer = badge.get("issuer_did") or badge.get("issuer") or "<unknown>"
            logger.info(
                "[1/6] ✅ Badge received: badge_id=%s, issuer=%s",
                badge_id,
                issuer,
            )

            # ----- Step 2: Badge verify -----
            step = STEP_BADGE_VERIFY
            logger.info("[2/6] 🔐 Verifying badge signature...")
            verification = await self.badge_verifier.verify_badge(badge)
            if not verification.get("valid"):
                raise XAAFlowError(
                    step=STEP_BADGE_VERIFY,
                    reason=f"badge verification failed: {verification.get('reason', 'unknown')}",
                )
            capabilities = verification.get("capabilities") or badge.get("task_scopes", [])
            logger.info(
                "[2/6] ✅ Badge verified, capabilities: %s", capabilities
            )

            # ----- Steps 3 + 4: Token acquisition (with cache) -----
            cached = self.token_cache.get(client_id, scope_str, subject)
            if cached is not None:
                logger.info(
                    "[3/6] ♻️  Using cached access token "
                    "(skipping ID-JAG request)"
                )
                logger.info(
                    "[4/6] ♻️  Using cached access token "
                    "(skipping resource exchange)"
                )
                access_token = cached
                id_jag_expires_in = 0
                was_cached = True
            elif self.xaa_dev_client is not None:
                # xaa.dev path: use the pre-obtained ID token from env and
                # run Step 2 (token-exchange) + Step 3 (JWT-bearer grant).
                id_token = os.environ.get("XAA_ID_TOKEN", "").strip()
                if not id_token:
                    raise XAAFlowError(
                        step=STEP_OKTA_IDJAG,
                        reason=(
                            "USE_XAA_DEV=true but XAA_ID_TOKEN env var is "
                            "empty. Run `python -m scripts.get_xaa_id_token` "
                            "first to obtain an ID token, then export "
                            "XAA_ID_TOKEN=..."
                        ),
                    )

                step = STEP_OKTA_IDJAG
                logger.info(
                    "[3/6] 🏛️  Requesting ID-JAG from xaa.dev "
                    "(token-exchange for audience %s)...",
                    self.xaa_dev_client.config.auth_server_url,
                )
                try:
                    id_jag_response = (
                        await self.xaa_dev_client
                        .exchange_id_token_for_id_jag(id_token)
                    )
                except XAADevError as exc:
                    raise XAAFlowError(
                        step=STEP_OKTA_IDJAG,
                        reason=f"xaa.dev token-exchange failed: {exc}",
                        cause=exc,
                    ) from exc

                id_jag = id_jag_response.get("access_token", "")
                id_jag_expires_in = int(id_jag_response.get("expires_in", 0))
                if not id_jag:
                    raise XAAFlowError(
                        step=STEP_OKTA_IDJAG,
                        reason="xaa.dev returned no ID-JAG access_token",
                    )
                _log_jwt_claims("ID-JAG", id_jag)
                logger.info(
                    "[3/6] ✅ ID-JAG received, expires in %ds",
                    id_jag_expires_in,
                )

                step = STEP_RESOURCE_EXCHANGE
                logger.info(
                    "[4/6] 🔄 Redeeming ID-JAG at xaa.dev auth server %s...",
                    self.xaa_dev_client.config.auth_server_url,
                )
                try:
                    at_response = (
                        await self.xaa_dev_client
                        .exchange_id_jag_for_access_token(id_jag)
                    )
                except XAADevError as exc:
                    raise XAAFlowError(
                        step=STEP_RESOURCE_EXCHANGE,
                        reason=f"xaa.dev jwt-bearer grant failed: {exc}",
                        cause=exc,
                    ) from exc

                at_expires_in = int(at_response.get("expires_in", 0))
                access_token_str = at_response.get("access_token", "")
                if not access_token_str:
                    raise XAAFlowError(
                        step=STEP_RESOURCE_EXCHANGE,
                        reason="xaa.dev returned no access_token",
                    )
                _log_jwt_claims("access_token", access_token_str)
                access_token = ResourceAccessToken(
                    access_token=access_token_str,
                    token_type=at_response.get("token_type", "Bearer"),
                    expires_in=at_expires_in,
                    scope=at_response.get("scope", scope_str),
                    expires_at=int(time.time()) + at_expires_in,
                )
                self.token_cache.set(
                    client_id, scope_str, subject, access_token,
                )
                logger.info(
                    "[4/6] ✅ Access token received from xaa.dev: "
                    "scope=%s, expires in %ds",
                    access_token.scope, access_token.expires_in,
                )
                was_cached = False
            else:
                # Legacy Okta path (USE_XAA_DEV=false).
                step = STEP_OKTA_IDJAG
                logger.info(
                    "[3/6] 🏛️  Requesting ID-JAG from Okta for audience %s...",
                    target_audience,
                )
                okta_response = await self.xaa_client.exchange_token(
                    subject_token=badge.get("jwt", ""),
                    target_audience=target_audience,
                    scopes=scopes,
                    badge_jwt=badge.get("jwt", ""),
                )
                id_jag = okta_response.get("access_token", "")
                id_jag_expires_in = int(okta_response.get("expires_in", 0))
                if not id_jag:
                    raise XAAFlowError(
                        step=STEP_OKTA_IDJAG,
                        reason="Okta returned no access_token",
                    )
                logger.info(
                    "[3/6] ✅ ID-JAG received, expires in %ds", id_jag_expires_in
                )

                # Step 4: Resource exchange
                step = STEP_RESOURCE_EXCHANGE
                logger.info("[4/6] 🔄 Exchanging ID-JAG at resource auth server...")
                access_token = await asyncio.to_thread(
                    exchange_id_jag_for_access_token,
                    id_jag,
                    client_id,
                    scope_str,
                )
                self.token_cache.set(client_id, scope_str, subject, access_token)
                logger.info(
                    "[4/6] ✅ Access token received: scope=%s, expires in %ds",
                    access_token.scope,
                    access_token.expires_in,
                )
                was_cached = False

            # ----- Step 5: TBAC check -----
            step = STEP_TBAC
            logger.info(
                "[5/6] 🛡️  TBAC policy check: task=%s, scopes=%s...",
                task_name,
                scopes,
            )
            xaa_token_dict: Dict[str, Any] = {
                "access_token": access_token.access_token,
                "token_type": access_token.token_type,
                "expires_in": access_token.expires_in,
                "scope": access_token.scope,
                "task": task_name,
            }
            await self.middleware.enforce(
                badge=badge,
                target_server=target_audience,
                requested_scopes=scopes,
                xaa_token=xaa_token_dict,
            )
            logger.info("[5/6] ✅ TBAC ALLOW")

            # ----- Step 6: MCP call -----
            step = STEP_MCP_CALL
            if self.xaa_dev_client is not None:
                logger.info(
                    "[6/6] 🔑 xaa.dev access token would be sent to the "
                    "resource API (%s) in production; for the PoC the MCP "
                    "client instead uses its real backend credentials "
                    "(Open-Meteo public API / Slack bot token).",
                    self.xaa_dev_client.config.resource_audience
                    or "<unconfigured>",
                )
            logger.info(
                "[6/6] 🌤️  Calling Weather MCP at %s...",
                self.weather_client.config.url or "<stub mode>",
            )
            mcp_result = await self.weather_client.call(
                token=access_token.access_token
            )
            logger.info("[6/6] ✅ Weather data received: %s", _short_preview(mcp_result))

            logger.info("")
            logger.info("✅ XAA flow complete — end-to-end success")

            return XAAFlowResult(
                task_name=task_name,
                subject=subject,
                target_audience=target_audience,
                scopes=scopes,
                badge_id=badge_id,
                badge_capabilities=list(capabilities) if capabilities else [],
                id_jag_expires_in=id_jag_expires_in,
                access_token_scope=access_token.scope,
                access_token_expires_in=access_token.expires_in,
                cached=was_cached,
                mcp_result=mcp_result,
            )
        except XAAFlowError:
            raise
        except Exception as exc:
            raise XAAFlowError(step=step, reason=str(exc), cause=exc) from exc


def _short_preview(result: Any, limit: int = 160) -> str:
    """Collapse an MCP result to a single log-friendly line."""
    text = repr(result)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _log_jwt_claims(label: str, token: str) -> None:
    """Log selected claims from a JWT at INFO level.

    Used to make the xaa.dev handoffs visible in the demo (aud, sub,
    resource, scope, exp). No signature verification — upstream layers
    handle trust. Silently no-ops for opaque / malformed tokens so a
    logging helper never breaks the flow.
    """
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return

    selected = {
        k: claims.get(k)
        for k in ("aud", "sub", "iss", "resource", "scope", "exp")
        if k in claims
    }
    logger.info("  %s claims: %s", label, selected)


async def execute_xaa_flow(
    task_name: str,
    target_audience: str,
    scopes: List[str],
    subject: str,
    *,
    config: Optional[AgentConfig] = None,
    token_cache: Optional[CachedTokenStore] = None,
) -> XAAFlowResult:
    """Module-level convenience — build a default orchestrator and run it."""
    orchestrator = XAAOrchestrator.from_config(
        config=config, token_cache=token_cache
    )
    return await orchestrator.execute(
        task_name=task_name,
        target_audience=target_audience,
        scopes=scopes,
        subject=subject,
    )


# --------------------------------------------------------------------------- CLI


def _parse_scopes(raw: str) -> List[str]:
    """Accept space- or comma-separated scopes."""
    if "," in raw:
        parts = [s.strip() for s in raw.split(",")]
    else:
        parts = raw.split()
    return [p for p in parts if p]


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m agent.xaa_orchestrator",
        description="Run the full cross-domain XAA flow end-to-end.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run a pre-configured 'weather for Austin' demo (ignores other args).",
    )
    parser.add_argument("--task", default=None, help="Task name (e.g. weather_slack_notification)")
    parser.add_argument("--user", default=None, help="Delegating user / subject")
    parser.add_argument(
        "--target-audience",
        dest="target_audience",
        default=None,
        help="Target resource audience (e.g. http://localhost:5001/)",
    )
    parser.add_argument(
        "--scopes",
        default=None,
        help="Requested scopes, space- or comma-separated (e.g. 'weather:read')",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    return parser


def _configure_logging(level_name: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level_name),
        format="%(message)s",
        stream=sys.stdout,
    )


def _cli_main(argv: Optional[List[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    _configure_logging(args.log_level)

    if args.demo:
        task_name = "weather_slack_notification"
        subject = "sarah@example.com"
        target_audience = "http://18.233.200.161:5001/"
        scopes = ["weather:read"]
    else:
        missing = [
            name
            for name, val in [
                ("--task", args.task),
                ("--user", args.user),
                ("--target-audience", args.target_audience),
                ("--scopes", args.scopes),
            ]
            if not val
        ]
        if missing:
            parser.error(
                f"missing required arguments (or pass --demo): {', '.join(missing)}"
            )
        task_name = args.task
        subject = args.user
        target_audience = args.target_audience
        scopes = _parse_scopes(args.scopes)

    try:
        result = asyncio.run(
            execute_xaa_flow(
                task_name=task_name,
                target_audience=target_audience,
                scopes=scopes,
                subject=subject,
            )
        )
    except XAAFlowError as exc:
        logger.error("")
        logger.error(
            "❌ XAA flow FAILED at step %d/%d: %s",
            exc.step,
            TOTAL_STEPS,
            exc.reason,
        )
        return 1
    except KeyboardInterrupt:
        return 130

    logger.info("")
    logger.info("Task result summary:")
    logger.info("  task=%s subject=%s cached=%s", result.task_name, result.subject, result.cached)
    logger.info("  mcp_result=%s", _short_preview(result.mcp_result, limit=400))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli_main())
