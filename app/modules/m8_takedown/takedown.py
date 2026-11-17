"""M8 下架/恢复领域规则：申请校验、证据快照、幂等与状态机。

硬约束（对应门户下架函与审计要求）：
1. 原件不销毁：announcements/chain_versions/quarantine 一行不删不改正文，
   下架只在 takedown_status 上立隔离态，普通查询按公文号过滤，审计侧仍可调原文；
2. 全局生效、跨批次：状态按 doc_no 存，不绑批次；重新采集/续跑生成新批次后，
   已封禁公文号在普通接口与导出里依旧不可见（防止「只改最新批次，旧批次泄露」）；
3. 申请幂等：同一 (doc_no, application_no) 重试返回原处置，只追加 RETRY_NOOP 留痕，
   不新增处置结论、不重复隔离；
4. 留痕可回放：下架与恢复都追加事件，恢复保留完整下架历史，不覆盖、不删除；
5. 失败不放松：处理中断后重跑/复采，隔离态仍在，已封禁内容不会因失败或复采重新公开。
"""
from __future__ import annotations

import datetime as dt

from ... import config, errors

ACTION_TAKE_DOWN = "TAKE_DOWN"
ACTION_RESTORE = "RESTORE"
ACTION_RETRY_NOOP = "RETRY_NOOP"
STATE_DOWN = "DOWN"
STATE_UP = "UP"


def now_iso() -> str:
    return dt.datetime.now(config.CHINA_TZ).isoformat(timespec="seconds")


def validate_application(*, doc_no: str, application_no: str, reason_code: str,
                         reason_text: str, basis: str) -> None:
    """下架/恢复申请入参校验；不合法抛 4xx，不留任何处置记录。"""
    doc_no = (doc_no or "").strip()
    application_no = (application_no or "").strip()
    reason_text = (reason_text or "").strip()
    basis = (basis or "").strip()
    missing = []
    if not doc_no:
        missing.append("doc_no")
    if not application_no:
        missing.append("application_no")
    if not basis:
        missing.append("basis")
    if missing:
        raise errors.BadRequest(f"缺少必填字段 {missing}",
                                code="T_BAD_REQUEST", detail={"fields": missing})
    if reason_code not in config.TAKEDOWN_REASONS:
        raise errors.BadRequest(
            f"下架原因 {reason_code!r} 不在目录 {config.TAKEDOWN_REASONS} 内",
            code="T_BAD_REQUEST", detail={"field": "reason_code"})
    if len(reason_text) < config.TAKEDOWN_MIN_REASON:
        raise errors.BadRequest(
            f"原因说明至少 {config.TAKEDOWN_MIN_REASON} 个字",
            code="T_BAD_REQUEST", detail={"field": "reason_text"})
    if len(basis) < config.TAKEDOWN_MIN_BASIS:
        raise errors.BadRequest(
            f"裁定依据至少 {config.TAKEDOWN_MIN_BASIS} 个字：写清门户来函与条款",
            code="T_BAD_REQUEST", detail={"field": "basis",
                                          "min": config.TAKEDOWN_MIN_BASIS})


def find_doc_batches(store, doc_no: str) -> list[dict]:
    """该公文号出现在哪些批次（按创建时间倒序）；一个批次都没有则无法下架。"""
    hits = []
    for batch in store.list_batches(limit=1000):
        chain = store.load_chain(batch["batch_id"], doc_no)
        if chain is not None:
            hits.append(batch)
    hits.sort(key=lambda b: b["created_at"], reverse=True)
    return hits


def evidence_snapshot(store, batch_id: str, doc_no: str) -> dict:
    """冻结当时的原始证据：链版本（含证据行/来源页）+ 关联隔离行 + 原文摘录。

    审计回放就靠这份快照与批次内原始行；下架不复制大段正文、不销毁原件，
    只把「当时是哪条链、哪几版、证据行是什么」固定下来。
    """
    chain = store.load_chain(batch_id, doc_no)
    if chain is None:
        raise errors.NotFound(f"批次 {batch_id} 中没有公文号 {doc_no}",
                              code="T_NO_SUCH_DOC")
    version_refs = {v["row_ref"] for v in chain["version_rows"]}
    quarantine_rows = [q for q in store.load_quarantine(batch_id)
                       if q.get("row_ref") in version_refs]
    announcements = [a for a in store.load_announcements(batch_id)
                     if a["doc_no"] == doc_no]
    return {
        "batch_id": batch_id,
        "doc_no": doc_no,
        "title": chain.get("title"),
        "chain_status": chain.get("status"),
        "final_deadline": chain.get("final_deadline"),
        "final_amount_wan": (None if chain.get("final_amount_wan") is None
                             else str(chain["final_amount_wan"])),
        "versions": [
            {"seq": v["seq"], "kind": v["kind"], "published_at": v["published_at"],
             "portal": v.get("portal"), "row_ref": v.get("row_ref"),
             "source_url": v.get("source_url"), "note": v.get("note", "")}
            for v in chain["version_rows"]
        ],
        "quarantine": [
            {"code": q["code"], "row_ref": q.get("row_ref"),
             "source_url": q.get("source_url"), "detail": q.get("detail")}
            for q in quarantine_rows
        ],
        "raw_refs": [
            {"row_ref": a.get("row_ref"), "portal": a.get("portal"),
             "source_url": a.get("source_url"),
             "raw": a.get("raw", {})}
            for a in announcements
        ],
        "captured_at": now_iso(),
    }


def _require_doc_exists(store, doc_no: str) -> list[dict]:
    batches = find_doc_batches(store, doc_no)
    if not batches:
        raise errors.NotFound(
            f"公文号 {doc_no} 不在任何已采批次中，无法办理下架",
            code="T_NO_SUCH_DOC", detail={"doc_no": doc_no})
    return batches


def take_down(store, *, doc_no: str, application_no: str, reason_code: str,
              reason_text: str, basis: str, principal, clock=now_iso) -> dict:
    """办理下架：校验 → 幂等判定 → 立隔离态 → 冻结证据 → 追加留痕。"""
    validate_application(doc_no=doc_no, application_no=application_no,
                         reason_code=reason_code, reason_text=reason_text, basis=basis)
    doc_no = doc_no.strip()
    application_no = application_no.strip()
    basis = basis.strip()
    reason_text = reason_text.strip()
    batches = _require_doc_exists(store, doc_no)
    latest_batch = batches[0]
    existing = store.get_takedown(doc_no)

    # 幂等：同一申请号重试，无论当前是 DOWN 还是 UP，都回原处置且不新增结论
    if existing is not None and existing["application_no"] == application_no:
        return _idempotent_retry(store, existing=existing, batches=batches,
                                 principal=principal, reason_code=reason_code,
                                 reason_text=reason_text, basis=basis, clock=clock)
    if existing is not None and existing["state"] == STATE_DOWN:
        raise errors.Conflict(
            f"公文号 {doc_no} 已依申请 {existing['application_no']} 下架隔离，"
            "不能重复下架；同一申请重试走幂等，变更请先恢复",
            code="T_ALREADY_DOWN",
            detail={"application_no": existing["application_no"]})

    timestamp = clock()
    evidence = evidence_snapshot(store, latest_batch["batch_id"], doc_no)
    first_batch_id = existing["first_batch_id"] if existing else latest_batch["batch_id"]
    status_row = {
        "doc_no": doc_no, "state": STATE_DOWN,
        "first_batch_id": first_batch_id,
        "latest_batch_id": latest_batch["batch_id"],
        "application_no": application_no, "reason_code": reason_code,
        "reason_text": reason_text, "created_at": timestamp,
        "updated_at": timestamp, "evidence": [evidence],
    }
    if existing is not None:
        # 重新下架（此前恢复过）：保留首次证据链，追加本次证据
        status_row["created_at"] = existing["created_at"]
        status_row["evidence"] = existing.get("evidence", []) + [evidence]
    store.upsert_takedown_status(status_row)
    event_id = store.insert_takedown_event({
        "doc_no": doc_no, "application_no": application_no,
        "action": ACTION_TAKE_DOWN, "reason_code": reason_code,
        "reason_text": reason_text, "basis": basis,
        "actor": principal.subject, "actor_role": principal.role,
        "batch_id": latest_batch["batch_id"], "created_at": timestamp,
        "detail": {"evidence_batch_id": latest_batch["batch_id"],
                   "token_id": principal.token_id},
    })
    return _result(store, doc_no, action=ACTION_TAKE_DOWN, event_id=event_id,
                   idempotent=False, timestamp=timestamp, evidence=evidence)


def restore(store, *, doc_no: str, application_no: str, reason_code: str,
            reason_text: str, basis: str, principal, clock=now_iso) -> dict:
    """办理恢复：校验 → 必须已下架 → 解除隔离 → 追加恢复留痕（不删下架历史）。"""
    validate_application(doc_no=doc_no, application_no=application_no,
                         reason_code=reason_code, reason_text=reason_text, basis=basis)
    doc_no = doc_no.strip()
    application_no = application_no.strip()
    basis = basis.strip()
    reason_text = reason_text.strip()
    batches = _require_doc_exists(store, doc_no)
    latest_batch = batches[0]
    existing = store.get_takedown(doc_no)

    if existing is not None and existing["application_no"] == application_no \
            and existing["state"] == STATE_UP:
        return _idempotent_retry(store, existing=existing, batches=batches,
                                 principal=principal, reason_code=reason_code,
                                 reason_text=reason_text, basis=basis, clock=clock)
    if existing is None or existing["state"] != STATE_DOWN:
        raise errors.Conflict(
            f"公文号 {doc_no} 当前未处于下架状态，不能恢复",
            code="T_NOT_DOWN", detail={"doc_no": doc_no})

    timestamp = clock()
    store.upsert_takedown_status({
        "doc_no": doc_no, "state": STATE_UP,
        "first_batch_id": existing["first_batch_id"],
        "latest_batch_id": latest_batch["batch_id"],
        "application_no": application_no, "reason_code": reason_code,
        "reason_text": reason_text,
        "created_at": existing["created_at"], "updated_at": timestamp,
        "evidence": existing.get("evidence", []),
    })
    event_id = store.insert_takedown_event({
        "doc_no": doc_no, "application_no": application_no,
        "action": ACTION_RESTORE, "reason_code": reason_code,
        "reason_text": reason_text, "basis": basis,
        "actor": principal.subject, "actor_role": principal.role,
        "batch_id": latest_batch["batch_id"], "created_at": timestamp,
        "detail": {"restored_from_application": existing["application_no"],
                   "token_id": principal.token_id},
    })
    return _result(store, doc_no, action=ACTION_RESTORE, event_id=event_id,
                   idempotent=False, timestamp=timestamp,
                   evidence=(existing.get("evidence") or [None])[-1])


def _idempotent_retry(store, *, existing, batches, principal, reason_code,
                      reason_text, basis, clock) -> dict:
    """同一申请重试：不改变隔离态、不新增处置结论，只追加一条 RETRY_NOOP 留痕。"""
    timestamp = clock()
    latest_batch_id = batches[0]["batch_id"] if batches else existing["latest_batch_id"]
    event_id = store.insert_takedown_event({
        "doc_no": existing["doc_no"], "application_no": existing["application_no"],
        "action": ACTION_RETRY_NOOP, "reason_code": reason_code,
        "reason_text": reason_text, "basis": basis,
        "actor": principal.subject, "actor_role": principal.role,
        "batch_id": latest_batch_id, "created_at": timestamp,
        "detail": {"kept_state": existing["state"], "token_id": principal.token_id},
    })
    evidence = (existing.get("evidence") or [None])[-1]
    return _result(store, existing["doc_no"], action=ACTION_RETRY_NOOP,
                   event_id=event_id, idempotent=True, timestamp=timestamp,
                   evidence=evidence)


def _result(store, doc_no: str, *, action: str, event_id: int, idempotent: bool,
            timestamp: str, evidence) -> dict:
    status = store.get_takedown(doc_no)
    return {
        "doc_no": doc_no, "action": action, "state": status["state"],
        "event_id": event_id, "idempotent": idempotent,
        "application_no": status["application_no"],
        "reason_code": status["reason_code"],
        "created_at": timestamp,
        "evidence_batch_id": (evidence or {}).get("batch_id"),
        "visible_in_public": status["state"] != STATE_DOWN,
    }


def trail(store, doc_no: str) -> dict:
    """审计回放：当前态 + 完整事件链（下架/重试/恢复全在，恢复不抹掉下架）。"""
    status = store.get_takedown(doc_no)
    if status is None:
        raise errors.NotFound(f"公文号 {doc_no} 没有下架处置记录",
                              code="T_NO_SUCH_DOC")
    events = store.list_takedown_events(doc_no)
    return {"status": status, "events": events,
            "event_count": len(events),
            "evidence_count": len(status.get("evidence", []))}
