"""M8 编排：身份核验 → 下架/恢复领域规则 → 审计视图。

handler 只做取参与 HTTP 映射，所有规则在 takedown.py / audit.py / auth.py；
身份核验失败统一写安全日志，再抛 401/403，业务表不留半成品。
"""
from __future__ import annotations

import base64
import json

from ... import config, errors
from . import audit as audit_mod
from . import auth, takedown


def authenticate(store, settings, authorization: str | None, *, endpoint: str,
                 require_audit: bool = False) -> auth.Principal:
    """从 Bearer 令牌核验身份；失败落安全日志并抛 401/403。"""
    token = auth.extract_bearer(authorization)
    try:
        principal = auth.verify_token(settings, token)
    except errors.NoticechainError as exc:
        presented = _unsafe_claims(token)
        store.insert_security_log(
            endpoint=endpoint, reason_code=exc.code,
            presented_subject=presented.get("sub", ""),
            presented_role=presented.get("role", ""), detail=exc.message)
        raise
    if require_audit and not principal.can_audit():
        store.insert_security_log(
            endpoint=endpoint, reason_code="T_AUTH_FORBIDDEN",
            presented_subject=principal.subject, presented_role=principal.role,
            detail="非审计员角色访问审计原文")
        raise errors.Forbidden(
            f"角色 {principal.role!r} 无权调取审计原文，仅审计员可访问",
            code="T_AUTH_FORBIDDEN", detail={"required": config.AUDIT_ROLE_OFFICER})
    return principal


def _unsafe_claims(token: str | None) -> dict:
    """验签失败时尽力解出 payload 仅用于安全日志，绝不用于授权。"""
    if not token or token.count(".") != 1:
        return {}
    try:
        payload_b64 = token.split(".", 1)[0]
        padding = "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
    except (ValueError, json.JSONDecodeError):
        return {}


def take_down(store, settings, payload, principal) -> dict:
    return takedown.take_down(
        store, doc_no=payload.doc_no, application_no=payload.application_no,
        reason_code=payload.reason_code, reason_text=payload.reason_text,
        basis=payload.basis, principal=principal)


def restore(store, settings, payload, principal) -> dict:
    return takedown.restore(
        store, doc_no=payload.doc_no, application_no=payload.application_no,
        reason_code=payload.reason_code, reason_text=payload.reason_text,
        basis=payload.basis, principal=principal)


def audit_replay(store, settings, doc_no: str) -> dict:
    return audit_mod.audit_replay(store, doc_no, settings)


def board(store, settings) -> dict:
    """下架工作台：当前隔离清单 + 已恢复清单 + 处置统计（不含原文，普通授权可看）。"""
    rows = store.list_takedowns()
    down = [r for r in rows if r["state"] == takedown.STATE_DOWN]
    up = [r for r in rows if r["state"] == takedown.STATE_UP]
    events = store.list_takedown_events()
    return {
        "down": [_board_row(r) for r in down],
        "restored": [_board_row(r) for r in up],
        "counts": {
            "down": len(down), "restored": len(up),
            "events": len(events),
            "take_down": sum(1 for e in events
                             if e["action"] == takedown.ACTION_TAKE_DOWN),
            "restore": sum(1 for e in events
                           if e["action"] == takedown.ACTION_RESTORE),
            "retry_noop": sum(1 for e in events
                              if e["action"] == takedown.ACTION_RETRY_NOOP),
        },
        "reasons": list(config.TAKEDOWN_REASONS),
        "roles": list(config.AUDIT_ROLES),
    }


def _board_row(row: dict) -> dict:
    return {
        "doc_no": row["doc_no"], "state": row["state"],
        "application_no": row["application_no"],
        "reason_code": row["reason_code"], "reason_text": row["reason_text"],
        "first_batch_id": row["first_batch_id"],
        "latest_batch_id": row["latest_batch_id"],
        "created_at": row["created_at"], "updated_at": row["updated_at"],
        "evidence_count": len(row.get("evidence", [])),
    }
