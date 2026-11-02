"""May the Vector Agent run at all for this engagement? (REQ-AGENT-028, GitHub #86)

The Scope Gateway refuses every agent-phase call of an engagement without the opt-in
(`ai_testing_not_enabled`) and, for a bug-bounty engagement, of a program that forbids automation or AI testing. That
is the boundary and it does not change. This function only lets the worker ask the same question once, before it
starts the agent, so a run that is certain to be refused does not spend language-model tokens finding that out.

The rules mirror the gateway's (`gateway/authorize.py`, steps 1b and 3); a test keeps the two in step.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.gateway.authorize import _bounty_program_for
from app.models.engagement import Engagement


def agent_permission(db: Session, eng: Engagement) -> tuple[bool, str | None]:
    """(allowed, reason). `reason` is a gateway reason code when the agent may not run, else None."""
    if not eng.ai_testing_allowed:
        return False, "ai_testing_not_enabled"
    if eng.source == "bug_bounty":
        program = _bounty_program_for(db, eng.id)
        if program is None:
            return False, "bounty_program_missing"
        if not program.automation_allowed:
            return False, "automation_forbidden"
        if not program.ai_testing_allowed:
            return False, "ai_testing_forbidden"
    return True, None
