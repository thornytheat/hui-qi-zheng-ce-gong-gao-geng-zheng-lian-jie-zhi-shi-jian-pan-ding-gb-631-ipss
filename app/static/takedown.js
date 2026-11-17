// takedown.js —— M8 下架/恢复/工作台。前端只收集入参与展示，身份与判定全在服务端。

const el = (id) => document.getElementById(id);

function body() {
  return {
    doc_no: (el("td-doc")?.value || "").trim(),
    application_no: (el("td-app")?.value || "").trim(),
    reason_code: el("td-reason") ? el("td-reason").value : "SENSITIVE_CONTENT",
    reason_text: (el("td-reason-text")?.value || "").trim(),
    basis: (el("td-basis")?.value || "").trim(),
  };
}

function headers() {
  const token = (el("td-token")?.value || "").trim();
  const h = { "Content-Type": "application/json" };
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

function setHint(text, failed = false) {
  const hint = el("td-hint");
  if (!hint) return;
  hint.textContent = text;
  hint.classList.toggle("op-failed", Boolean(failed));
}

function showResult(data, failed = false) {
  const mask = el("td-result");
  const pre = el("td-result-body");
  if (pre) pre.textContent = JSON.stringify(data, null, 2);
  if (mask) mask.hidden = false;
  setHint(failed ? `被拒绝：${data.message || data.error || "见返回"}` :
    `处置完成：${data.action || ""}（${data.state || ""}）`, failed);
}

async function submit(url) {
  try {
    const response = await fetch(url, {
      method: "POST",
      headers: headers(),
      body: JSON.stringify(body()),
    });
    const data = await response.json().catch(() => ({}));
    showResult(data, !response.ok);
    if (response.ok) setTimeout(() => window.location.reload(), 900);
  } catch (error) {
    showResult({ message: error.message }, true);
  }
}

async function loadBoard() {
  try {
    const response = await fetch("/api/takedown/board", { headers: headers() });
    const data = await response.json().catch(() => ({}));
    showResult(data, !response.ok);
  } catch (error) {
    showResult({ message: error.message }, true);
  }
}

function wire() {
  el("btn-takedown")?.addEventListener("click", () => submit("/api/takedown"));
  el("btn-restore")?.addEventListener("click", () => submit("/api/takedown/restore"));
  el("btn-board")?.addEventListener("click", loadBoard);
}

wire();
