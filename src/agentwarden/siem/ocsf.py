"""Map AgentWarden audit entries to OCSF events (Open Cybersecurity Schema Framework 1.3).

The mapping (also documented in ``docs/SIEM.md``):

======================================  =================================  ======================
AgentWarden event                       OCSF class                          Activity
======================================  =================================  ======================
``token.issued``, ``token.exchanged``   Authentication (3002)               Authentication Ticket
``token.denied``                        Authentication (3002)               Authentication Ticket
``token.delegated`` / ``_denied``       Authentication (3002)               Service Ticket Request
``token.revoked``, ``subject.revoked``  Authentication (3002)               Logoff
``auth.failed``                         Authentication (3002)               Logon (failure)
``authz.decision``                      API Activity (6003)                 Other (authorize)
``agent.registered``                    Account Change (3001)               Create
``agent.enabled`` / ``agent.disabled``  Account Change (3001)               Enable / Disable
``agent.scopes_changed``                Account Change (3001)               Other
``approval.*``                          Entity Management (3004)            Create / Update / Other
``keys.rotated`` / ``keys.pruned``      Entity Management (3004)            Create / Delete
anything else                           Base Event (0)                      Other
======================================  =================================  ======================

Every event keeps the AgentWarden event name in ``metadata.event_code``, the entry's chain hash
in ``metadata.uid`` (use it to de-duplicate: delivery is at-least-once), and the full original
entry under ``unmapped.agentwarden`` so nothing is lost in translation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agentwarden import __version__
from agentwarden.models import AuditEvent

OCSF_VERSION = "1.3.0"

_CATEGORIES = {0: "Other", 3: "Identity & Access Management", 6: "Application Activity"}
_CLASSES = {
    0: "Base Event",
    3001: "Account Change",
    3002: "Authentication",
    3004: "Entity Management",
    6003: "API Activity",
}
_SEVERITY = {0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
_STATUS = {0: "Unknown", 1: "Success", 2: "Failure", 99: "Other"}
_RISK_SEVERITY = {"none": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}

SUCCESS, FAILURE, OTHER = 1, 2, 99


@dataclass(frozen=True)
class _Mapping:
    class_uid: int
    activity_id: int
    activity_name: str
    status_id: int = SUCCESS
    severity_id: int = 1


_MAPPINGS: dict[str, _Mapping] = {
    "token.issued": _Mapping(3002, 3, "Authentication Ticket"),
    "token.exchanged": _Mapping(3002, 3, "Authentication Ticket"),
    "token.denied": _Mapping(3002, 3, "Authentication Ticket", FAILURE, 3),
    "token.delegated": _Mapping(3002, 4, "Service Ticket Request"),
    "token.delegation_denied": _Mapping(3002, 4, "Service Ticket Request", FAILURE, 3),
    "token.revoked": _Mapping(3002, 2, "Logoff"),
    "subject.revoked": _Mapping(3002, 2, "Logoff", SUCCESS, 2),
    "auth.failed": _Mapping(3002, 1, "Logon", FAILURE, 3),
    "authz.decision": _Mapping(6003, 99, "Other"),
    "agent.registered": _Mapping(3001, 1, "Create"),
    "agent.enabled": _Mapping(3001, 2, "Enable", SUCCESS, 2),
    "agent.disabled": _Mapping(3001, 5, "Disable", SUCCESS, 3),
    "agent.scopes_changed": _Mapping(3001, 99, "Other", SUCCESS, 2),
    "approval.requested": _Mapping(3004, 1, "Create"),
    "approval.approved": _Mapping(3004, 3, "Update"),
    "approval.denied": _Mapping(3004, 3, "Update"),
    "approval.misuse": _Mapping(3004, 99, "Other", FAILURE, 4),
    "keys.rotated": _Mapping(3004, 1, "Create"),
    "keys.pruned": _Mapping(3004, 4, "Delete"),
}
_FALLBACK = _Mapping(0, 99, "Other", OTHER)
_DECISION_STATUS = {"allow": SUCCESS, "deny": FAILURE, "require_approval": OTHER}


def to_ocsf(event: AuditEvent) -> dict[str, Any]:
    """One OCSF event for one audit entry."""
    mapping = _MAPPINGS.get(event.event_type, _FALLBACK)
    data = event.data
    status_id, severity_id = mapping.status_id, mapping.severity_id
    if event.event_type == "authz.decision":
        status_id = _DECISION_STATUS.get(event.decision or "", OTHER)
        risk = data.get("risk")
        level = risk.get("level") if isinstance(risk, dict) else None
        severity_id = _RISK_SEVERITY.get(str(level), 1)
        if event.decision == "deny":
            severity_id = max(severity_id, 3)

    class_uid = mapping.class_uid
    record: dict[str, Any] = {
        "category_uid": class_uid // 1000,
        "category_name": _CATEGORIES[class_uid // 1000],
        "class_uid": class_uid,
        "class_name": _CLASSES[class_uid],
        "activity_id": mapping.activity_id,
        "activity_name": mapping.activity_name,
        "type_uid": class_uid * 100 + mapping.activity_id,
        "type_name": f"{_CLASSES[class_uid]}: {mapping.activity_name}",
        "time": int(event.ts.timestamp() * 1000),
        "severity_id": severity_id,
        "severity": _SEVERITY[severity_id],
        "status_id": status_id,
        "status": _STATUS[status_id],
        "message": _message(event),
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "AgentWarden",
                "vendor_name": "AgentWarden",
                "version": __version__,
                "url_string": "https://github.com/Tawhid-Mahmud/agentwarden",
            },
            "uid": event.hash,
            "event_code": event.event_type,
            "sequence": event.seq,
            "log_name": "audit",
            "original_time": event.ts.isoformat(),
        },
        "unmapped": {"agentwarden": event.model_dump(mode="json")},
    }
    reasons = data.get("reasons") if isinstance(data.get("reasons"), list) else None
    if status_id != SUCCESS and (data.get("reason") or reasons):
        record["status_detail"] = str(data.get("reason") or "; ".join(map(str, reasons or [])))
    actor = _actor(event)
    if actor:
        record["actor"] = actor
    if class_uid == 3002 and event.user_id:
        record["user"] = {"uid": event.user_id, "type": "User", "type_id": 1}
    if class_uid == 3001 and event.agent_id:
        # Agents are non-human accounts: the account that changed is the agent.
        record["user"] = {
            "uid": event.agent_id,
            "name": event.agent_id,
            "type": "Other",
            "type_id": 99,
        }
    if class_uid == 3004:
        record["entity"] = _entity(event)
    if class_uid == 6003:
        record["api"] = {
            "operation": event.tool,
            "service": {"name": "agentwarden"},
            "request": {"uid": data.get("decision_id")},
        }
        if data.get("decision_id"):
            record["metadata"]["correlation_uid"] = data["decision_id"]
        if data.get("trace_id"):
            record["metadata"]["trace_uid"] = data["trace_id"]
    return record


def _actor(event: AuditEvent) -> dict[str, Any]:
    actor: dict[str, Any] = {}
    by = event.data.get("by") or event.data.get("reviewer")
    if event.user_id and event.event_type.startswith(("authz.", "token.", "approval.")):
        actor["user"] = {"uid": event.user_id, "type": "User", "type_id": 1}
    if by:
        actor["user"] = {"uid": str(by), "type": "User", "type_id": 1}
    if event.agent_id:
        actor["app_name"] = event.agent_id
    chain = event.data.get("actor_chain")
    if isinstance(chain, list) and chain:
        actor["app_uid"] = "/".join(str(a) for a in chain)
    return actor


def _entity(event: AuditEvent) -> dict[str, Any]:
    if event.event_type.startswith("approval."):
        return {"type": "Approval", "uid": event.data.get("approval_id")}
    kid = event.data.get("new_kid") or ",".join(event.data.get("kids") or [])
    return {"type": "Signing Key", "uid": kid or None}


def _message(event: AuditEvent) -> str:
    who = f"agent {event.agent_id}" if event.agent_id else "AgentWarden"
    on_behalf = f" for user {event.user_id}" if event.user_id else ""
    if event.event_type == "authz.decision":
        return f"{who}{on_behalf} called {event.tool}: {event.decision}"
    return f"{event.event_type} ({who}{on_behalf})"
