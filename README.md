# noticechain · 惠企政策公告更正链与截止时间判定

江南智造园区「企服通」政策服务组每天盯 3 个政府门户的惠企政策，原先手工抄截止日期到表格；
更正公告常被漏看，导致「以为还能报，其实已撤销」。本项目把「采信 → 解析 → 质量隔离 → 链合并
→ 清单 → 导出」做成一条可复核的流水线：同一 `doc_no` 的公告自动成链，更正/延期/撤销按序号合并，
得到当前有效状态与真实截止日；链内重复序号、时间倒挂、父公告缺失一律整链隔离并给出原因码与证据行。

## 能力

- **采信**：三门户列表页 + 详情页 + 附件 CSV；编码回退链（声明不信任）、BOM 剥离、rel=next 分页、
  断页/截断识别、逐页诊断。
- **契约**：9 个规范字段 + 三门户列名别名（同名列按精度取高分）、类型/单位/精度/可空声明。
- **质量**：转载重复合并、哨兵整行隔离、额度与日期范围校验、原因码目录与隔离导出。
- **链判定**：更正覆盖、延期顺延、撤销作废；重复序号/时间倒挂/缺父公告三类冲突整链隔离。
- **截止推算**：工作日表（法定节假日 − / 调休上班日 +），区间左闭右开。
- **批次**：阶段化、断点续跑、同源幂等重跑（命中批次键即复用结果）、运行清单（run_id + 输入 sha256）。
- **导出**：可申报清单 CSV、隔离 CSV、链版本 CSV、运行清单 JSON、对账 JSON；页面与导出规则一致。
- **复核与回放**：冲突链人工裁定（选版 + 裁定人 + 依据）、按公告号逐版回放、撤销后非法迁移拦截、
  >20 版超长链线性合并、裁定后清单与自动清单并存且逐字段留差异。
- **下架与审计（M8）**：门户来函下架的公告只立隔离态、不销毁原件；普通查询与五类导出立即屏蔽，
  授权审计员经 HMAC 令牌回放当时原文证据与裁定依据；同申请重试幂等、恢复保留完整处置历史，
  跨批次/复采/中断续跑都不会让已封禁内容重新公开。

## 模块

| 模块 | 动作 | 入口 | 页面 |
|---|---|---|---|
| M1 采信与抓取 | 触发采集、看逐页诊断 | `POST /api/crawl` | `/` |
| M2 契约与解析 | 看列契约、试跑单条解析 | `GET /api/contract`、`POST /api/parse/preview` | 契约面板在 `/export` |
| M3 质量与隔离 | 看原因码分布与隔离行、导出隔离 | `GET /api/quarantine`、`GET /api/reconcile` | `/quarantine` |
| M4 链判定与截止 | 看政策链版本时间线与当前截止 | `GET /api/policies`、`GET /api/policies/{doc_no}` | `/policies`、`/policies/{doc_no}` |
| M5 批次与续跑 | 查历史、续跑、幂等重跑 | `GET /api/batches`、`POST /api/batches/{id}/resume` | `/batches` |
| M6 复核与导出 | 四账复核与五类导出 | `GET /api/export` | `/export` |
| M7 复核与回放 | 冲突链裁定、按公告号回放、裁定后重算 | `GET /api/review`、`GET /api/review/replay`、`POST /api/review/ruling` | `/review` |
| M8 下架与审计 | 办理下架/恢复、授权审计回放、处置留痕 | `POST /api/takedown`、`POST /api/takedown/restore`、`GET /api/audit/replay`、`POST /api/auth/token` | `/takedown` |

深度登记（功能模块表、14 条 TRAP 表、反例与不变量）：`docs/DEPTH.md`；字段契约：`docs/DATA-DICTIONARY.md`。

## 启动

```bash
docker compose up --build -d
curl -sS -X POST http://localhost:18200/api/crawl -H 'content-type: application/json' -d '{"source":"all"}'
open http://localhost:18200/
```

- 主服务：<http://localhost:18200/>（容器内 8000）
- 样例站：<http://localhost:19200/>（nginx，服务 `sample_site/`）
- 应用只通过 `http://sample-site/` 访问样例站，不使用宿主机地址。

重建数据库（清空历史批次）：

```bash
docker compose down -v      # 命名卷 noticechain-data 一并删除
docker compose up -d --build
```

## 演示步骤

1. 打开 `/`，选来源「全部门户」→「触发采集」：六个阶段卡显示进/出/隔离，页面诊断表逐页给出编码、
   声明编码、字节数与原因码；日志尾可直接定位 `E_PAGE_TRUNCATED`、`E_PAGING_NO_NEXT`。
2. `/policies` 看可申报清单与合计（5890.00 万元），`/policies/澄工信发〔2026〕37号` 看
   「首次发布 → 更正 → 延期」三版时间线与工作日推算依据。
3. `/quarantine` 看 12 类原因码分布与隔离明细，点「证据」看原值；导出隔离 CSV。
4. `/batches` 看批次历史，「同源重跑」会命中批次键、只复用结果（幂等）。
5. `/export` 看四账与运行清单，下载五类文件。
6. `/review` 看 3 条冲突链，选 `澄科技发〔2026〕21号` 回放两版证据；裁定人填 2 字以上、依据填 6 字以上，
   提交后状态从「冲突隔离」变为人工结论，改判差异逐字段列出，自动值仍留在留痕里。
7. `/takedown` 演示下架与审计：先 `POST /api/auth/token` 取得服务端签发令牌，再带
   `Authorization: Bearer <token>` 调 `POST /api/takedown`；下架后 `/api/policies` 与导出立即查不到该公文号，
   审计员用 `GET /api/audit/replay?doc_no=...` 仍可调取原文证据与完整裁定留痕。

## 下架与审计（M8）规则

- **只隔离不销毁**：下架在 `takedown_status` 立 `DOWN` 态，`announcements/chain_versions/quarantine` 原件一行不删；
  普通接口（`/api/policies`、链详情、隔离区、复核回放）与五类导出按公文号全局过滤。
- **跨批次持续生效**：处置态按 `doc_no` 存、不绑批次；重新采集、来源切换产生的新批次，以及失败后续跑，
  已封禁公文号在普通接口与导出里依旧不可见，堵住「只改最新批次、旧批次仍可下载原文」的泄露口。
- **授权审计保留证据**：`GET /api/audit/replay` 仅 `audit_officer` 可调，回放首次下架批次的原始链版本、
  原文摘录、关联隔离行与全部处置事件（含裁定依据、办理人、申请号）。
- **身份服务端核验**：令牌为 HMAC-SHA256 签名（密钥取 `NOTICECHAIN_AUDIT_SECRET`，未配置则进程随机），
  验签/时效/角色任一不过即 401/403 并写安全日志；请求体里自报的 actor/role 不参与授权。
- **幂等与留痕**：同一 `(公文号, 申请号)` 重试返回原处置、只追加 `RETRY_NOOP`，不新增处置结论；
  恢复（`RESTORE`）不删除下架历史，重新下架会追加第二份证据快照。

## 规则与已知不覆盖

- 金额 Decimal（万元，2 位）；时间入库 UTC、展示 +08:00；工作日区间左闭右开。
- 中文数字截止（`三十个工作日`）不支持，按 `Q_BAD_DEADLINE_RULE` 隔离。
- 节假日表只维护 2026 年；样例站门户 B 第 2 页之后的公告未落文件（记 `E_PAGING_NO_NEXT` 断点）。
- 完整清单见 `docs/DEPTH.md` 的「已知不覆盖」。

## 目录

```text
app/                 main/config/errors/reasons/manifest/store/web + modules/m1..m8
app/templates/       base + 8 个页面（采集/清单/链详情/隔离/复核/下架审计/批次/导出）
app/static/          theme.css（令牌）layout.css（骨架）components.css（元件）+ 4 个 js
docs/                DEPTH.md（模块表 + TRAP 表）DATA-DICTIONARY.md（字段契约）
sample_site/         三门户 9 个文件（含 GB18030 页、截断页、附件 CSV、门户导航）
sample_data/         announcements_dirty.csv（同样的脏数据另存一份，便于离线核对）
tests/               conftest + 每模块 1 个（含 test_m7_review.py、test_m8_takedown.py）+ e2e + fixtures/expected.py
```

## 测试

```bash
docker compose exec -T app pytest -q
```

131 条测试（容器内 131 passed，1 条真实 HTTP 样例站用例在本地无样例站时跳过），
覆盖 8 个模块（每模块 ≥7 条）与 14 条 TRAP；含反例、不变量、端到端与下架审计的越权/幂等/跨批次场景。
