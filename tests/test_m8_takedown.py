"""M8 下架与审计：隔离行、链回放、裁定留痕、服务端身份核验与跨批次持续生效。

覆盖需求要点：
- 普通查询接口与导出立即看不到下架内容，授权审计保留原文证据与裁定依据；
- 原件不销毁、只改最新批次也挡不住旧批次泄露（状态按公文号全局生效）；
- 审计身份服务端核验，伪造/越权拒绝并记安全日志；
- 中断续跑、复采不重新公开已封禁内容；
- 同一申请重试不新增处置记录；恢复保留完整处置历史。
"""
from __future__ import annotations

import pytest

from app import config, errors
from app.modules.m1_ingest import reader
from app.modules.m5_batches import service as batch_service
from app.modules.m8_takedown import auth, takedown

D37 = "澄工信发〔2026〕37号"
D12 = "澄科技发〔2026〕12号"
D21 = "澄科技发〔2026〕21号"
TAKE_BASIS = "门户来函澄字2026第15号附件载明该公告含敏感信息，要求立即下架"
RESTORE_BASIS = "门户二次来函确认敏感信息已删除，经法务复核准予恢复公开"


# ---------- 固定装置：带固定审计密钥的应用与两类令牌 ----------

@pytest.fixture()
def audit_settings(settings):
    return config.Settings(
        db_path=settings.db_path, eval_date=settings.eval_date,
        sample_site_dir=settings.sample_site_dir,
        sample_site_base=settings.sample_site_base,
        audit_secret="pytest-audit-secret")


@pytest.fixture()
def audit_app(audit_settings):
    from app.main import create_app
    return create_app(audit_settings)


@pytest.fixture()
def audit_client(audit_app):
    from fastapi.testclient import TestClient
    return TestClient(audit_app)


@pytest.fixture()
def client_run(audit_client):
    response = audit_client.post("/api/crawl", json={"source": "all"})
    assert response.status_code == 200
    assert response.json()["status"] == "done"
    return audit_client


@pytest.fixture()
def officer_token(audit_client):
    r = audit_client.post("/api/auth/token",
                          json={"subject": "审计员赵", "role": config.AUDIT_ROLE_OFFICER})
    assert r.status_code == 200
    return r.json()["token"]


@pytest.fixture()
def operator_token(audit_client):
    r = audit_client.post("/api/auth/token",
                          json={"subject": "经办钱", "role": config.AUDIT_ROLE_OPERATOR})
    assert r.status_code == 200
    return r.json()["token"]


def _take(client, token, *, doc_no=D37, app_no="TD-2026-0001",
          reason_code="SENSITIVE_CONTENT", reason_text="公告正文含个人敏感信息",
          basis=TAKE_BASIS):
    return client.post("/api/takedown", headers={"Authorization": f"Bearer {token}"},
                       json={"doc_no": doc_no, "application_no": app_no,
                             "reason_code": reason_code, "reason_text": reason_text,
                             "basis": basis})


# ---------- 一、服务端身份核验：拒绝伪造身份越权 ----------

class TestServerSideIdentity:
    def test_missing_token_is_401(self, client_run):
        r = client_run.post("/api/takedown", json={
            "doc_no": D37, "application_no": "TD-1", "reason_text": "含敏感信息",
            "basis": TAKE_BASIS})
        assert r.status_code == 401
        assert r.json()["error"] == "T_AUTH_REQUIRED"

    def test_forged_signature_is_403(self, client_run, officer_token):
        forged = officer_token[:-4] + ("aaaa" if officer_token[-4:] != "aaaa" else "bbbb")
        r = client_run.post("/api/takedown",
                            headers={"Authorization": f"Bearer {forged}"},
                            json={"doc_no": D37, "application_no": "TD-1",
                                  "reason_text": "含敏感信息", "basis": TAKE_BASIS})
        assert r.status_code == 403
        assert r.json()["error"] == "T_AUTH_FORBIDDEN"

    def test_tampered_payload_is_403(self, audit_settings):
        issued = auth.issue_token(audit_settings, subject="钱",
                                  role=config.AUDIT_ROLE_OPERATOR)
        payload_b64, sig = issued["token"].split(".")
        import base64
        import json
        padding = "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
        claims["role"] = config.AUDIT_ROLE_OFFICER      # 尝试提权
        raw = json.dumps(claims, separators=(",", ":")).encode()
        tampered = base64.urlsafe_b64encode(raw).decode().rstrip("=") + "." + sig
        with pytest.raises(errors.Forbidden) as caught:
            auth.verify_token(audit_settings, tampered)
        assert caught.value.code == "T_AUTH_FORBIDDEN"

    def test_expired_token_is_403(self, audit_settings):
        issued = auth.issue_token(audit_settings, subject="钱",
                                  role=config.AUDIT_ROLE_OPERATOR, ttl_seconds=10,
                                  now=1000)
        with pytest.raises(errors.Forbidden) as caught:
            auth.verify_token(audit_settings, issued["token"], now=2000)
        assert caught.value.code == "T_AUTH_FORBIDDEN"

    def test_self_declared_identity_in_body_is_ignored(self, client_run, operator_token):
        """请求体里塞 actor/role 不能提权：身份只来自签名令牌。"""
        r = client_run.post("/api/takedown",
                            headers={"Authorization": f"Bearer {operator_token}"},
                            json={"doc_no": D37, "application_no": "TD-1",
                                  "reason_text": "含敏感信息", "basis": TAKE_BASIS,
                                  "actor": "审计员赵", "role": config.AUDIT_ROLE_OFFICER})
        # 仍按 operator 身份办成下架，而不是按 body 里伪造的审计员
        assert r.status_code == 200
        trail = client_run.get("/api/audit/trail", params={"doc_no": D37},
                               headers={"Authorization": f"Bearer {_officer(client_run)}"})
        assert trail.json()["events"][0]["actor"] == "经办钱"
        assert trail.json()["events"][0]["actor_role"] == config.AUDIT_ROLE_OPERATOR

    def test_operator_cannot_access_audit_replay(self, client_run, operator_token,
                                                 officer_token):
        _take(client_run, operator_token)
        r = client_run.get("/api/audit/replay", params={"doc_no": D37},
                           headers={"Authorization": f"Bearer {operator_token}"})
        assert r.status_code == 403
        assert r.json()["error"] == "T_AUTH_FORBIDDEN"
        # 审计员可以
        ok = client_run.get("/api/audit/replay", params={"doc_no": D37},
                            headers={"Authorization": f"Bearer {officer_token}"})
        assert ok.status_code == 200

    def test_unknown_role_token_rejected_at_issue(self, client_run):
        r = client_run.post("/api/auth/token",
                            json={"subject": "x", "role": "super_admin"})
        assert r.status_code == 400
        assert r.json()["error"] == "T_AUTH_FORBIDDEN"

    def test_auth_failures_written_to_security_log(self, client_run, officer_token):
        # 带合法 body 才能穿过请求体校验、真正走到身份核验
        no_token = client_run.post("/api/takedown", json={
            "doc_no": D37, "application_no": "TD-0",
            "reason_text": "公告正文含敏感信息", "basis": TAKE_BASIS})
        assert no_token.status_code == 401
        forged = officer_token[:-3] + "aaa"
        client_run.post("/api/takedown", headers={"Authorization": f"Bearer {forged}"},
                        json={"doc_no": D37, "application_no": "TD",
                              "reason_text": "公告正文含敏感信息", "basis": TAKE_BASIS})
        store = client_run.app.state.store
        logs = store.list_security_log()
        codes = {row["reason_code"] for row in logs}
        assert "T_AUTH_REQUIRED" in codes
        assert "T_AUTH_FORBIDDEN" in codes
        # 失败尝试没有在业务表里留下任何处置记录
        assert store.list_takedown_events() == []
        required = [row for row in logs if row["reason_code"] == "T_AUTH_REQUIRED"][0]
        assert required["endpoint"] == "/api/takedown"

    def test_secret_rotation_invalidates_old_tokens(self, settings, audit_client):
        old = config.Settings(db_path=settings.db_path, eval_date=settings.eval_date,
                              sample_site_dir=settings.sample_site_dir,
                              sample_site_base=settings.sample_site_base,
                              audit_secret="secret-a")
        token = auth.issue_token(old, subject="钱",
                                 role=config.AUDIT_ROLE_OPERATOR)["token"]
        rotated = config.Settings(db_path=settings.db_path, eval_date=settings.eval_date,
                                  sample_site_dir=settings.sample_site_dir,
                                  sample_site_base=settings.sample_site_base,
                                  audit_secret="secret-b")
        with pytest.raises(errors.Forbidden):
            auth.verify_token(rotated, token)


def _officer(client):
    r = client.post("/api/auth/token",
                    json={"subject": "审计员赵", "role": config.AUDIT_ROLE_OFFICER})
    return r.json()["token"]


# ---------- 二、隔离行：普通查询与导出立即不可见 ----------

class TestPublicIsolation:
    def test_taken_down_hidden_from_policies_api(self, client_run, operator_token):
        before = client_run.get("/api/policies").json()
        assert D37 in {p["doc_no"] for p in before["policies"]}
        assert _take(client_run, operator_token).status_code == 200
        after = client_run.get("/api/policies").json()
        assert D37 not in {p["doc_no"] for p in after["policies"]}
        assert after["counts"]["taken_down"] == 1
        assert after["counts"]["total"] == before["counts"]["total"] - 1

    def test_taken_down_detail_returns_404_not_content(self, client_run, operator_token):
        _take(client_run, operator_token)
        r = client_run.get(f"/api/policies/{D37}")
        assert r.status_code == 404
        assert r.json()["error"] == "T_TAKEN_DOWN"
        page = client_run.get(f"/policies/{D37}")
        assert page.status_code == 404

    def test_taken_down_excluded_from_all_public_exports(self, client_run, operator_token):
        _take(client_run, operator_token)
        policies_csv = client_run.get("/api/export?kind=policies").text
        chains_csv = client_run.get("/api/export?kind=chains").text
        quarantine_csv = client_run.get("/api/quarantine/export.csv").text
        assert D37 not in policies_csv
        assert D37 not in chains_csv
        assert D37 not in quarantine_csv

    def test_taken_down_hidden_from_quarantine_api_and_review(self, client_run,
                                                              operator_token):
        # D21 是冲突链，其隔离行带原值；下架后普通隔离口与复核口都不能泄露
        _take(client_run, operator_token, doc_no=D21, app_no="TD-2026-0009",
              reason_text="冲突链含敏感额度", basis=TAKE_BASIS)
        quarantine = client_run.get("/api/quarantine").json()
        assert D21 not in "".join(str(r) for r in quarantine["rows"])
        review = client_run.get("/api/review").json()
        assert D21 not in {q["doc_no"] for q in review["queue"]}
        replay = client_run.get("/api/review/replay", params={"doc_no": D21})
        assert replay.status_code == 404
        assert replay.json()["error"] == "T_TAKEN_DOWN"

    def test_other_docs_unaffected(self, client_run, operator_token):
        _take(client_run, operator_token)
        data = client_run.get("/api/policies").json()
        assert D12 in {p["doc_no"] for p in data["policies"]}
        assert data["counts"]["taken_down"] == 1

    def test_keyword_filter_cannot_reveal_taken_down(self, client_run, operator_token):
        _take(client_run, operator_token)
        data = client_run.get("/api/policies", params={"keyword": "37号"}).json()
        assert all(p["doc_no"] != D37 for p in data["policies"])


# ---------- 三、原件不销毁：授权审计保留原始证据与裁定依据 ----------

class TestAuditReplayPreservesEvidence:
    def test_original_rows_remain_in_store(self, client_run, operator_token):
        batch_id = client_run.get("/api/batches").json()["batches"][0]["batch_id"]
        _take(client_run, operator_token)
        store = client_run.app.state.store
        announcements = [a for a in store.load_announcements(batch_id)
                         if a["doc_no"] == D37]
        chain = store.load_chain(batch_id, D37)
        assert len(announcements) == 3          # 原件一行没删
        assert chain is not None and len(chain["version_rows"]) == 3

    def test_audit_replay_returns_raw_evidence_and_basis(self, client_run,
                                                         operator_token, officer_token):
        _take(client_run, operator_token)
        r = client_run.get("/api/audit/replay", params={"doc_no": D37},
                           headers={"Authorization": f"Bearer {officer_token}"})
        assert r.status_code == 200
        body = r.json()
        assert body["takedown_state"] == "DOWN"
        assert len(body["versions"]) == 3
        # 原始证据行（含原文摘录）与来源页都在
        assert all(v["row_ref"] for v in body["versions"])
        assert any(v["raw"] for v in body["versions"])
        # 链回放步骤可复算
        assert body["replay_state"]["deadline"] == "2026-12-15"
        assert body["replay_state"]["amount"] == "1500.00"
        # 裁定依据在事件链里
        assert body["events"][0]["basis"] == TAKE_BASIS
        assert body["events"][0]["actor"] == "经办钱"

    def test_audit_replay_includes_conflict_quarantine_evidence(self, client_run,
                                                                operator_token,
                                                                officer_token):
        _take(client_run, operator_token, doc_no=D21, app_no="TD-2026-0021",
              reason_text="冲突链含敏感额度信息", basis=TAKE_BASIS)
        body = client_run.get("/api/audit/replay", params={"doc_no": D21},
                              headers={"Authorization": f"Bearer {officer_token}"}).json()
        codes = {q["code"] for q in body["quarantine"]}
        assert "C_DUP_SEQ_CONFLICT" in codes

    def test_audit_trail_requires_officer(self, client_run, officer_token, operator_token):
        _take(client_run, operator_token)
        r = client_run.get("/api/audit/trail",
                           headers={"Authorization": f"Bearer {operator_token}"})
        assert r.status_code == 403
        ok = client_run.get("/api/audit/trail",
                            headers={"Authorization": f"Bearer {officer_token}"})
        assert ok.status_code == 200


# ---------- 四、幂等：同一申请重试不新增处置记录 ----------

class TestIdempotentApplication:
    def test_retry_same_application_adds_no_new_disposition(self, client_run,
                                                            operator_token):
        payload = {"doc_no": D37, "application_no": "TD-2026-0001",
                   "reason_code": "SENSITIVE_CONTENT", "reason_text": "公告含敏感信息",
                   "basis": TAKE_BASIS}
        first = _take(client_run, operator_token)
        second = client_run.post("/api/takedown",
                                 headers={"Authorization": f"Bearer {operator_token}"},
                                 json=payload)
        assert first.json()["idempotent"] is False
        assert second.status_code == 200
        assert second.json()["idempotent"] is True
        assert second.json()["action"] == "RETRY_NOOP"
        store = client_run.app.state.store
        events = store.list_takedown_events(D37)
        assert [e["action"] for e in events] == ["TAKE_DOWN", "RETRY_NOOP"]
        # 隔离态没有被重复建立，状态表仍只有一行
        assert len(store.list_takedowns()) == 1
        assert store.get_takedown(D37)["state"] == "DOWN"

    def test_distinct_application_on_down_doc_conflicts(self, client_run, operator_token):
        _take(client_run, operator_token, app_no="TD-1")
        r = _take(client_run, operator_token, app_no="TD-2")
        assert r.status_code == 409
        assert r.json()["error"] == "T_ALREADY_DOWN"

    def test_restore_idempotent_for_same_application(self, client_run, operator_token):
        _take(client_run, operator_token, app_no="TD-1")
        restore_payload = {"doc_no": D37, "application_no": "TD-R-1",
                           "reason_code": "PORTAL_REQUEST", "reason_text": "复核解除",
                           "basis": RESTORE_BASIS}
        first = client_run.post("/api/takedown/restore",
                                headers={"Authorization": f"Bearer {operator_token}"},
                                json=restore_payload)
        second = client_run.post("/api/takedown/restore",
                                 headers={"Authorization": f"Bearer {operator_token}"},
                                 json=restore_payload)
        assert first.json()["state"] == "UP"
        assert second.json()["idempotent"] is True
        store = client_run.app.state.store
        assert [e["action"] for e in store.list_takedown_events(D37)] == \
            ["TAKE_DOWN", "RESTORE", "RETRY_NOOP"]


# ---------- 五、恢复保留原处置历史 ----------

class TestRestoreKeepsHistory:
    def test_restore_makes_doc_public_but_keeps_full_trail(self, client_run,
                                                            operator_token,
                                                            officer_token):
        _take(client_run, operator_token)
        r = client_run.post("/api/takedown/restore",
                            headers={"Authorization": f"Bearer {operator_token}"},
                            json={"doc_no": D37, "application_no": "TD-R-1",
                                  "reason_code": "PORTAL_REQUEST",
                                  "reason_text": "复核解除", "basis": RESTORE_BASIS})
        assert r.status_code == 200
        assert r.json()["state"] == "UP"
        # 公开接口恢复可见
        assert D37 in {p["doc_no"] for p in
                       client_run.get("/api/policies").json()["policies"]}
        # 下架历史完整保留
        trail = client_run.get("/api/audit/trail", params={"doc_no": D37},
                               headers={"Authorization": f"Bearer {officer_token}"}).json()
        actions = [e["action"] for e in trail["events"]]
        assert actions == ["TAKE_DOWN", "RESTORE"]
        status = client_run.app.state.store.get_takedown(D37)
        assert status["state"] == "UP"
        # 首次下架证据快照仍在
        assert len(status["evidence"]) >= 1

    def test_restore_without_takedown_conflicts(self, client_run, operator_token):
        r = client_run.post("/api/takedown/restore",
                            headers={"Authorization": f"Bearer {operator_token}"},
                            json={"doc_no": D12, "application_no": "TD-R-x",
                                  "reason_code": "PORTAL_REQUEST",
                                  "reason_text": "复核解除", "basis": RESTORE_BASIS})
        assert r.status_code == 409
        assert r.json()["error"] == "T_NOT_DOWN"

    def test_retakedown_after_restore_appends_evidence(self, client_run, operator_token):
        _take(client_run, operator_token, app_no="TD-1")
        client_run.post("/api/takedown/restore",
                        headers={"Authorization": f"Bearer {operator_token}"},
                        json={"doc_no": D37, "application_no": "TD-R-1",
                              "reason_code": "PORTAL_REQUEST", "reason_text": "复核后解除下架",
                              "basis": RESTORE_BASIS})
        again = _take(client_run, operator_token, app_no="TD-2",
                      basis="门户再次来函要求下架同一公告原件")
        assert again.status_code == 200
        status = client_run.app.state.store.get_takedown(D37)
        assert status["state"] == "DOWN"
        assert len(status["evidence"]) == 2     # 两次下架证据都保留
        actions = [e["action"] for e in
                   client_run.app.state.store.list_takedown_events(D37)]
        assert actions == ["TAKE_DOWN", "RESTORE", "TAKE_DOWN"]


# ---------- 六、跨批次、复采、中断续跑：封禁不重新公开 ----------

class TestSurvivesBatchesAndFailures:
    def test_takedown_applies_to_historical_batches(self, audit_settings, store):
        """旧批次仍能下载原文的泄露口：状态按公文号全局生效，每个批次都过滤。"""
        fetcher = reader.FileFetcher(audit_settings.sample_site_dir,
                                     base=audit_settings.sample_site_base)
        first = batch_service.run(settings=audit_settings, store=store,
                                  source="all", fetcher=fetcher)
        principal = auth.Principal("经办钱", config.AUDIT_ROLE_OPERATOR, "jti", 0, 9999)
        takedown.take_down(
            store, doc_no=D37, application_no="TD-1",
            reason_code="SENSITIVE_CONTENT", reason_text="公告含敏感信息",
            basis=TAKE_BASIS, principal=principal)
        # 再采一个不同来源的新批次（batch_key 不同，产生真实新批次）
        second = batch_service.run(settings=audit_settings, store=store,
                                   source="portal_a", fetcher=fetcher)
        assert second["batch"]["batch_id"] != first["batch"]["batch_id"]
        # 两个批次里 D37 都处于下架态
        assert D37 in store.down_doc_nos()
        from app.modules.m4_chain import service as m4
        for batch_id in (first["batch"]["batch_id"], second["batch"]["batch_id"]):
            data = m4.list_chains(store, batch_id, audit_settings)
            assert D37 not in {c["doc_no"] for c in data["chains"]}

    def test_failed_run_never_reopens_taken_down(self, audit_settings, store):
        """下架后跑一个注定失败的批次，失败不改变隔离态。"""
        fetcher = reader.FileFetcher(audit_settings.sample_site_dir,
                                     base=audit_settings.sample_site_base)
        batch_service.run(settings=audit_settings, store=store, source="all",
                          fetcher=fetcher)
        principal = auth.Principal("经办钱", config.AUDIT_ROLE_OPERATOR, "jti", 0, 9999)
        takedown.take_down(
            store, doc_no=D37, application_no="TD-1",
            reason_code="SENSITIVE_CONTENT", reason_text="公告含敏感信息",
            basis=TAKE_BASIS, principal=principal)

        def boom():
            raise RuntimeError("注入的链判定失败")

        failed = batch_service.run(settings=audit_settings, store=store, source="all",
                                   fetcher=fetcher, hooks={"chain": boom})
        assert failed["status"] == "failed"
        assert D37 in store.down_doc_nos()       # 失败没把公告放回来

        resumed = batch_service.run(settings=audit_settings, store=store, source="all",
                                    fetcher=fetcher,
                                    resume_of=failed["batch"]["batch_id"])
        assert resumed["status"] == "done"
        assert D37 in store.down_doc_nos()       # 续跑成功后依旧封禁
        from app.modules.m4_chain import service as m4
        data = m4.list_chains(store, resumed["batch"]["batch_id"], audit_settings)
        assert D37 not in {c["doc_no"] for c in data["chains"]}

    def test_recrawl_does_not_republish_taken_down(self, audit_settings, store):
        """复采（同输入幂等 + 新批次两条路）都不能让已封禁内容重新公开。"""
        fetcher = reader.FileFetcher(audit_settings.sample_site_dir,
                                     base=audit_settings.sample_site_base)
        batch_service.run(settings=audit_settings, store=store, source="all",
                          fetcher=fetcher)
        principal = auth.Principal("经办钱", config.AUDIT_ROLE_OPERATOR, "jti", 0, 9999)
        takedown.take_down(
            store, doc_no=D37, application_no="TD-1",
            reason_code="SENSITIVE_CONTENT", reason_text="公告含敏感信息",
            basis=TAKE_BASIS, principal=principal)
        replay = batch_service.run(settings=audit_settings, store=store, source="all",
                                   fetcher=fetcher)
        assert replay["idempotent_replay"] is True
        assert D37 in store.down_doc_nos()


# ---------- 七、入参校验与边界 ----------

class TestValidationAndBoundaries:
    def test_unknown_doc_is_404(self, client_run, operator_token):
        r = _take(client_run, operator_token, doc_no="澄工信发〔2026〕99号",
                  app_no="TD-x")
        assert r.status_code == 404
        assert r.json()["error"] == "T_NO_SUCH_DOC"

    def test_short_basis_is_400(self, client_run, operator_token):
        r = _take(client_run, operator_token, basis="短")
        assert r.status_code == 400
        assert r.json()["error"] == "T_BAD_REQUEST"
        assert r.json()["detail"]["field"] == "basis"

    def test_missing_application_no_is_400(self, client_run, operator_token):
        r = client_run.post("/api/takedown",
                            headers={"Authorization": f"Bearer {operator_token}"},
                            json={"doc_no": D37, "application_no": "",
                                  "reason_text": "公告含敏感信息", "basis": TAKE_BASIS})
        assert r.status_code == 400
        assert "application_no" in r.json()["detail"]["fields"]

    def test_unknown_reason_code_is_400(self, client_run, operator_token):
        r = _take(client_run, operator_token, reason_code="NOT_A_REASON")
        assert r.status_code == 400
        assert r.json()["detail"]["field"] == "reason_code"

    def test_audit_replay_unknown_doc_is_404(self, client_run, officer_token):
        r = client_run.get("/api/audit/replay", params={"doc_no": "不存在号"},
                           headers={"Authorization": f"Bearer {officer_token}"})
        assert r.status_code == 404


# ---------- 八、工作台与页面 ----------

class TestBoardAndPage:
    def test_board_lists_down_and_restored(self, client_run, operator_token,
                                           officer_token):
        _take(client_run, operator_token, doc_no=D37, app_no="TD-1")
        _take(client_run, operator_token, doc_no=D12, app_no="TD-2",
              basis=TAKE_BASIS)
        client_run.post("/api/takedown/restore",
                        headers={"Authorization": f"Bearer {operator_token}"},
                        json={"doc_no": D12, "application_no": "TD-R-2",
                              "reason_code": "PORTAL_REQUEST", "reason_text": "复核后解除下架",
                              "basis": RESTORE_BASIS})
        board = client_run.get("/api/takedown/board",
                               headers={"Authorization": f"Bearer {officer_token}"}).json()
        assert board["counts"]["down"] == 1
        assert board["counts"]["restored"] == 1
        assert {r["doc_no"] for r in board["down"]} == {D37}
        assert {r["doc_no"] for r in board["restored"]} == {D12}
        assert board["principal"]["role"] == config.AUDIT_ROLE_OFFICER

    def test_takedown_page_renders(self, client_run):
        r = client_run.get("/takedown")
        assert r.status_code == 200
        assert "下架与审计" in r.text

    def test_board_requires_token(self, client_run):
        assert client_run.get("/api/takedown/board").status_code == 401
