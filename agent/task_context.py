"""Task context and delegation chain tracking."""
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class DelegationStep:
    """A single step in the delegation chain."""
    delegator: str
    delegatee: str
    auth_domain: str
    scopes: List[str]
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    token_ref: Optional[str] = None


@dataclass
class TaskContext:
    """
    Represents the full context of a delegated task.

    Tracks the delegation chain from the human user through the agent
    to each MCP server, along with the AGNTCY identity badge and
    Okta XAA tokens acquired at each hop.
    """
    task_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_description: str = ""
    delegating_user: str = ""
    agent_id: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    delegation_chain: List[DelegationStep] = field(default_factory=list)
    identity_badge: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_delegation(self, delegator: str, delegatee: str,
                       auth_domain: str, scopes: List[str],
                       token_ref: Optional[str] = None) -> DelegationStep:
        """Record a delegation step in the chain."""
        step = DelegationStep(
            delegator=delegator,
            delegatee=delegatee,
            auth_domain=auth_domain,
            scopes=scopes,
            token_ref=token_ref,
        )
        self.delegation_chain.append(step)
        return step

    def get_chain_summary(self) -> List[Dict[str, Any]]:
        """Return a summary of the delegation chain for logging/audit."""
        return [
            {
                "hop": i,
                "delegator": step.delegator,
                "delegatee": step.delegatee,
                "domain": step.auth_domain,
                "scopes": step.scopes,
                "timestamp": step.timestamp,
            }
            for i, step in enumerate(self.delegation_chain)
        ]
