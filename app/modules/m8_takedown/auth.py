"""M8 服务端身份核验：HMAC-SHA256 签名令牌，拒绝任何自报身份。

设计原则：
- 身份只由服务端签发与核验：客户端不能在请求体里写 actor/role 提权，
  写了也只记入安全日志，不参与授权；
- 令牌 = base64(payload).base64(hmac_sha256(payload, secret))，
  payload 含 subject/role/批次范围/签发与过期时间，任何字节被改都会验签失败；
- 密钥来自 settings.audit_secret（环境变量 NOTICECHAIN_AUDIT_SECRET），
  未配置时进程启动生成一次性随机密钥，重启后旧令牌全部失效；
- 角色分级：audit_officer 可调原文证据与全部留痕；takedown_operator 只能办下架/恢复。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets as _secrets
import time

from ... import config, errors

_process_fallback_secret = _secrets.token_urlsafe(48)


class Principal:
    """通过服务端核验后的调用身份；业务代码只认这个对象，不认请求里的名字。"""

    def __init__(self, subject: str, role: str, token_id: str,
                 issued_at: int, expires_at: int, scope: list[str] | None = None):
        self.subject = subject
        self.role = role
        self.token_id = token_id
        self.issued_at = issued_at
        self.expires_at = expires_at
        self.scope = tuple(scope or ())

    def has_role(self, role: str) -> bool:
        return self.role == role

    def can_audit(self) -> bool:
        return self.role == config.AUDIT_ROLE_OFFICER

    def can_operate(self) -> bool:
        return self.role in config.AUDIT_ROLES

    def as_dict(self) -> dict:
        return {"subject": self.subject, "role": self.role, "token_id": self.token_id,
                "issued_at": self.issued_at, "expires_at": self.expires_at,
                "scope": list(self.scope)}


def _secret(settings) -> bytes:
    secret = settings.audit_secret or _process_fallback_secret
    return secret.encode("utf-8")


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


def _sign(payload_b64: str, settings) -> str:
    digest = hmac.new(_secret(settings), payload_b64.encode("ascii"),
                      hashlib.sha256).digest()
    return _b64encode(digest)


def issue_token(settings, *, subject: str, role: str,
                ttl_seconds: int | None = None, scope: list[str] | None = None,
                now: int | None = None) -> dict:
    """服务端签发令牌。只在登录/授权流程里调用，不开放给普通 API。"""
    subject = (subject or "").strip()
    if not subject:
        raise errors.BadRequest("令牌主体不能为空", code="T_BAD_REQUEST")
    if role not in config.AUDIT_ROLES:
        raise errors.BadRequest(
            f"角色 {role!r} 不在审计角色目录 {config.AUDIT_ROLES} 内",
            code="T_AUTH_FORBIDDEN")
    moment = int(time.time()) if now is None else now
    ttl = config.AUDIT_TOKEN_TTL_SECONDS if ttl_seconds is None else ttl_seconds
    payload = {
        "sub": subject,
        "role": role,
        "jti": _secrets.token_hex(8),
        "iat": moment,
        "exp": moment + int(ttl),
        "scope": list(scope or ()),
    }
    payload_b64 = _b64encode(json.dumps(payload, separators=(",", ":"),
                                        ensure_ascii=False).encode("utf-8"))
    signature = _sign(payload_b64, settings)
    token = f"{payload_b64}.{signature}"
    return {"token": token, "subject": subject, "role": role,
            "issued_at": payload["iat"], "expires_at": payload["exp"],
            "token_id": payload["jti"], "scope": payload["scope"]}


def verify_token(settings, token: str | None, *, now: int | None = None) -> Principal:
    """验签 + 时效 + 角色目录；任何一项不过都抛 401/403 语义的领域异常。"""
    if not token or not isinstance(token, str) or token.count(".") != 1:
        raise errors.Unauthorized("缺少审计身份令牌", code="T_AUTH_REQUIRED")
    payload_b64, signature = token.split(".", 1)
    expected = _sign(payload_b64, settings)
    # 恒定时间比较，避免时序侧信道
    if not hmac.compare_digest(signature, expected):
        raise errors.Forbidden("令牌签名核验失败（疑似伪造）",
                               code="T_AUTH_FORBIDDEN")
    try:
        payload = json.loads(_b64decode(payload_b64))
    except (ValueError, json.JSONDecodeError):
        raise errors.Forbidden("令牌内容无法解析", code="T_AUTH_FORBIDDEN")
    moment = int(time.time()) if now is None else now
    if int(payload.get("exp", 0)) <= moment:
        raise errors.Forbidden("审计令牌已过期", code="T_AUTH_FORBIDDEN")
    role = payload.get("role")
    if role not in config.AUDIT_ROLES:
        raise errors.Forbidden(f"令牌角色 {role!r} 无权访问审计资源",
                               code="T_AUTH_FORBIDDEN")
    return Principal(subject=str(payload.get("sub", "")), role=role,
                     token_id=str(payload.get("jti", "")),
                     issued_at=int(payload.get("iat", 0)),
                     expires_at=int(payload.get("exp", 0)),
                     scope=payload.get("scope") or [])


def extract_bearer(authorization: str | None) -> str | None:
    """从 Authorization: Bearer <token> 取令牌；其他scheme一律视为无令牌。"""
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None
