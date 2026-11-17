"""M8 授权审计回放：下架内容的原始证据与裁定依据，只对审计员开放。

与普通接口的差别：
- 普通 /api/policies、/api/export 按 takedown_status 过滤 DOWN 公文号，看不到也导不出；
- 本模块不做该过滤，按 doc_no 跨批次找回首次下架证据批次的原始链版本、原文摘录、
  隔离行与全部处置事件，证明「当时采到了什么、为什么下架、谁批的、依据是什么」；
- 只读，绝不回写 announcements/chains，原件保持入库时的样子（证据完整性）。
"""
from __future__ import annotations

import datetime as dt
import json

from ... import config
from ..m7_review import replay as m7_replay
from . import takedown


def _local(published_at: str | None) -> str | None:
    if not published_at:
        return None
    moment = dt.datetime.fromisoformat(published_at)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=config.UTC)
    return moment.astimezone(config.CHINA_TZ).isoformat(timespec="seconds")


def audit_replay(store, doc_no: str, settings) -> dict:
    """组装一份完整审计回放：处置留痕 + 当时原始链 + 逐版回放 + 原文证据。"""
    pack = takedown.trail(store, doc_no)
    status = pack["status"]
    # 证据锚点优先取首次下架批次，保证回放的是「当时」的原始证据
    anchor_batch_id = status["first_batch_id"]
    chain = store.load_chain(anchor_batch_id, doc_no)
    if chain is None:
        # 极端情况下首批次被清，则回退到最近仍含该公文号的批次
        batches = takedown.find_doc_batches(store, doc_no)
        if not batches:
            raise _not_found(doc_no)
        anchor_batch_id = batches[0]["batch_id"]
        chain = store.load_chain(anchor_batch_id, doc_no)
    if chain is None:
        raise _not_found(doc_no)

    versions = []
    for version in chain["version_rows"]:
        item = dict(version)
        spec = item.get("deadline_spec")
        if isinstance(spec, str):
            try:
                item["deadline_spec"] = json.loads(spec)
            except ValueError:
                item["deadline_spec"] = None
        item["published_local"] = _local(item.get("published_at"))
        versions.append(item)

    folded = m7_replay.fold(versions)
    long_view = m7_replay.long_view(folded)
    raw_by_ref = {a.get("row_ref"): a.get("raw")
                  for a in store.load_announcements(anchor_batch_id)
                  if a["doc_no"] == doc_no}
    version_refs = {v["row_ref"] for v in versions}
    quarantine_rows = [q for q in store.load_quarantine(anchor_batch_id)
                       if q.get("row_ref") in version_refs]

    events = []
    for event in pack["events"]:
        events.append({
            "event_id": event["event_id"], "action": event["action"],
            "action_label": ACTION_LABELS.get(event["action"], event["action"]),
            "application_no": event["application_no"],
            "reason_code": event["reason_code"], "reason_text": event["reason_text"],
            "basis": event["basis"], "actor": event["actor"],
            "actor_role": event["actor_role"], "batch_id": event["batch_id"],
            "created_at": event["created_at"],
        })

    return {
        "doc_no": doc_no,
        "title": chain.get("title"),
        "takedown_state": status["state"],
        "state_label": "已下架隔离" if status["state"] == takedown.STATE_DOWN else "已恢复公开",
        "current_application_no": status["application_no"],
        "reason_code": status["reason_code"],
        "reason_text": status["reason_text"],
        "anchor_batch_id": anchor_batch_id,
        "first_batch_id": status["first_batch_id"],
        "latest_batch_id": status["latest_batch_id"],
        "chain": {
            "status": chain.get("status"),
            "final_deadline": chain.get("final_deadline"),
            "final_amount_wan": (None if chain.get("final_amount_wan") is None
                                 else str(chain["final_amount_wan"])),
            "listed": bool(chain.get("listed")),
            "note": chain.get("note"),
            "conflicts": chain.get("conflicts") or [],
        },
        "replay_steps": long_view["steps"],
        "replay_versions": long_view["versions"],
        "replay_state": {
            "deadline": folded["state"]["deadline"].isoformat()
            if folded["state"]["deadline"] else None,
            "amount": None if folded["state"]["amount"] is None
            else str(folded["state"]["amount"].quantize(config.DECIMAL_QUANT)),
            "voided": folded["state"]["voided"],
        },
        "versions": [
            {"seq": v["seq"], "kind": v["kind"], "published_at": v.get("published_local"),
             "portal": v.get("portal"), "row_ref": v.get("row_ref"),
             "source_url": v.get("source_url"), "note": v.get("note"),
             "raw": m7_replay.raw_excerpt(raw_by_ref.get(v.get("row_ref")))}
            for v in versions
        ],
        "quarantine": [
            {"code": q["code"], "row_ref": q.get("row_ref"),
             "source_url": q.get("source_url"), "detail": q.get("detail")}
            for q in quarantine_rows
        ],
        "evidence_snapshots": status.get("evidence", []),
        "events": events,
        "event_count": pack["event_count"],
        "evidence_count": pack["evidence_count"],
    }


ACTION_LABELS = {
    takedown.ACTION_TAKE_DOWN: "下架隔离",
    takedown.ACTION_RESTORE: "恢复公开",
    takedown.ACTION_RETRY_NOOP: "同申请重试(幂等)",
}


def _not_found(doc_no: str):
    from ... import errors
    return errors.NotFound(f"找不到公文号 {doc_no} 的审计证据", code="T_NO_SUCH_DOC")
