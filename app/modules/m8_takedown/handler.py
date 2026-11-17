"""M8 入口：下架/恢复申请、授权审计回放、下架工作台、令牌签发。

路由分两层：
- 办理层（/api/takedown/*）：需有效令牌且角色在审计角色目录内；
- 审计层（/api/audit/*）：需有效令牌且必须是 audit_officer，才能调原文证据。
令牌签发 /api/auth/token 只在服务端按密钥签发，客户端无法自造身份。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel

from ... import config
from ...web import Ctx, get_ctx, render
from . import auth, service, takedown

router = APIRouter(tags=["M8 下架与审计"])


class TakedownIn(BaseModel):
    doc_no: str
    application_no: str
    reason_code: str = "SENSITIVE_CONTENT"
    reason_text: str = ""
    basis: str = ""


class TokenIn(BaseModel):
    subject: str
    role: str
    ttl_seconds: int | None = None


@router.post("/api/auth/token")
def api_token(payload: TokenIn, ctx: Ctx = Depends(get_ctx)) -> dict:
    """服务端签发审计令牌：密钥在服务端，客户端只拿到签名后的不透明令牌。"""
    return auth.issue_token(ctx.settings, subject=payload.subject, role=payload.role,
                            ttl_seconds=payload.ttl_seconds)


@router.post("/api/takedown")
def api_take_down(payload: TakedownIn,
                  authorization: str | None = Header(default=None),
                  ctx: Ctx = Depends(get_ctx)) -> dict:
    principal = service.authenticate(ctx.store, ctx.settings, authorization,
                                     endpoint="/api/takedown")
    result = service.take_down(ctx.store, ctx.settings, payload, principal)
    result["actor"] = principal.subject
    result["actor_role"] = principal.role
    return result


@router.post("/api/takedown/restore")
def api_restore(payload: TakedownIn,
                authorization: str | None = Header(default=None),
                ctx: Ctx = Depends(get_ctx)) -> dict:
    principal = service.authenticate(ctx.store, ctx.settings, authorization,
                                     endpoint="/api/takedown/restore")
    result = service.restore(ctx.store, ctx.settings, payload, principal)
    result["actor"] = principal.subject
    result["actor_role"] = principal.role
    return result


@router.get("/api/takedown/board")
def api_board(authorization: str | None = Header(default=None),
              ctx: Ctx = Depends(get_ctx)) -> dict:
    principal = service.authenticate(ctx.store, ctx.settings, authorization,
                                     endpoint="/api/takedown/board")
    data = service.board(ctx.store, ctx.settings)
    data["principal"] = principal.as_dict()
    return data


@router.get("/api/audit/replay")
def api_audit_replay(doc_no: str,
                     authorization: str | None = Header(default=None),
                     ctx: Ctx = Depends(get_ctx)) -> dict:
    """授权审计回放：仅审计员可调，下架公告的原文证据与裁定依据在此可见。"""
    service.authenticate(ctx.store, ctx.settings, authorization,
                         endpoint="/api/audit/replay", require_audit=True)
    return service.audit_replay(ctx.store, ctx.settings, doc_no)


@router.get("/api/audit/trail")
def api_audit_trail(doc_no: str | None = None,
                    authorization: str | None = Header(default=None),
                    ctx: Ctx = Depends(get_ctx)) -> dict:
    """处置留痕：审计员可查单条或全部事件链（含恢复后仍保留的下架历史）。"""
    service.authenticate(ctx.store, ctx.settings, authorization,
                         endpoint="/api/audit/trail", require_audit=True)
    if doc_no:
        return takedown.trail(ctx.store, doc_no)
    return {"events": ctx.store.list_takedown_events(),
            "security_log": ctx.store.list_security_log()}


@router.get("/takedown")
def page_takedown(request: Request, batch_id: str | None = None,
                  ctx: Ctx = Depends(get_ctx)):
    batch = ctx.current_batch(batch_id)
    data = {"down": [], "restored": [], "counts": {"down": 0, "restored": 0,
            "events": 0, "take_down": 0, "restore": 0, "retry_noop": 0},
            "reasons": list(config.TAKEDOWN_REASONS), "roles": list(config.AUDIT_ROLES)}
    return render(request, "takedown.html", batch=batch, page="takedown",
                  data=data, page_title="下架与审计")
