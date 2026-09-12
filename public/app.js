/* 中转 API 模型检测器 — 前端 */

const state = {
  runId: null,
  source: null,
  catalog: [],
  results: new Map(),
  summary: null,
  startedAt: 0,
  timer: null,
  finished: false,
  running: false,
  estimate: null,
  preflightNotice: null,
  authRequired: false,
  bound: false
};

const STATUS_TEXT = {
  pending: '等待中',
  running: '检测中',
  pass: '通过',
  warn: '警告',
  fail: '失败',
  aborted: '已终止',
  skipped: '已跳过'
};
const STATUS_COLOR = {
  pending: '#4a5878',
  running: '#5b8cff',
  pass: '#25c07a',
  warn: '#f0a92c',
  fail: '#ef4d5a',
  aborted: '#6b7a99',
  skipped: '#6b7a99'
};

const el = (id) => document.getElementById(id);
const grid = el('grid');
const cardTemplate = el('card-template');

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function donutBackground(score, status) {
  const pct = Math.max(0, Math.min(1, (score ?? 0) / 10));
  const color = STATUS_COLOR[status] || STATUS_COLOR.pending;
  return `conic-gradient(${color} ${pct * 360}deg, rgba(255,255,255,0.06) ${pct * 360}deg)`;
}

/* ---------------- 初始化 ---------------- */

async function boot() {
  // 注意：必须先把事件绑上，否则 401 分支提前 return 会导致登录按钮点不动
  if (!state.bound) {
    bindEvents();
    state.bound = true;
  }
  try {
    const res = await fetch('/api/catalog', { credentials: 'same-origin' });
    if (res.status === 401) {
      state.catalog = [];
      showAuth();
      return;
    }
    const data = await res.json();
    state.catalog = data.probes || [];
    state.limits = {
      defaultTokenBudget: data.defaultTokenBudget,
      minTokenBudget: data.minTokenBudget,
      maxTokenBudget: data.maxTokenBudget
    };
    state.estimate = data.estimate || null;
    state.authRequired = Boolean(data.authRequired);
    el('logout-btn').classList.toggle('hidden', !state.authRequired);
    const field = el('tokenBudget');
    if (field) {
      if (!field.value) field.value = String(data.defaultTokenBudget ?? 60000);
      field.min = String(data.minTokenBudget ?? 1000);
      field.max = String(data.maxTokenBudget ?? 5000000);
    }
    hideAuth();
  } catch {
    state.catalog = [];
    showError('无法获取探针目录：后端未响应，请确认服务已启动。');
  }
  renderPlaceholders();
  renderEstimate();
  validateBudget();
}

/* ---------------- deploy-safe 登录 ---------------- */

function showAuth(message) {
  const panel = el('auth-panel');
  panel.classList.remove('hidden');
  const err = el('auth-error');
  if (message) {
    err.textContent = message;
    err.classList.remove('hidden');
  } else {
    err.classList.add('hidden');
  }
  el('appToken').focus();
}

function hideAuth() {
  el('auth-panel').classList.add('hidden');
}

async function submitAuth(event) {
  if (event?.preventDefault) event.preventDefault();
  const token = el('appToken').value.trim();
  const err = el('auth-error');
  if (!token) {
    err.textContent = '请输入访问令牌';
    err.classList.remove('hidden');
    return;
  }
  try {
    const res = await fetch('/api/session', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token })
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      err.textContent = data.error || `登录失败（HTTP ${res.status}）`;
      err.classList.remove('hidden');
      return;
    }
    el('appToken').value = '';
    hideAuth();
    await boot();
  } catch (error) {
    err.textContent = `登录失败：${error.message}`;
    err.classList.remove('hidden');
  }
}

async function logout() {
  try {
    await fetch('/api/session', { method: 'DELETE', credentials: 'same-origin' });
  } catch {
    /* 忽略 */
  }
  window.location.reload();
}

function renderPlaceholders() {
  grid.innerHTML = '';
  if (!state.catalog.length) {
    grid.innerHTML = '<p style="color:#8b9ab8">探针目录加载失败，请刷新页面。</p>';
    return;
  }
  for (const probe of state.catalog) {
    grid.appendChild(buildCard(probe));
  }
}

function buildCard(probe) {
  const node = cardTemplate.content.firstElementChild.cloneNode(true);
  node.dataset.id = probe.id;
  node.dataset.status = 'pending';
  node.querySelector('.idx').textContent = `#${String(probe.index).padStart(2, '0')}`;
  node.querySelector('.name').textContent = probe.name;
  node.querySelector('.pill').textContent = STATUS_TEXT.pending;
  node.querySelector('.weight').textContent = `权重 ${(probe.weight * 100).toFixed(0)}% · ${probe.group}`;
  node.querySelector('.evidence').textContent = probe.summary;
  return node;
}

function bindEvents() {
  el('detect-form').addEventListener('submit', onSubmit);
  el('auth-btn').addEventListener('click', submitAuth);
  el('appToken').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') submitAuth(e);
  });
  el('logout-btn').addEventListener('click', logout);
  el('reset-btn').addEventListener('click', () => {
    stopStream();
    el('detect-form').reset();
    el('overview').classList.add('hidden');
    el('findings').classList.add('hidden');
    el('error-box').classList.add('hidden');
    state.runId = null;
    state.results.clear();
    state.summary = null;
    state.finished = false;
    state.usage = null;
    state.preflightNotice = null;
    el('budget-banner').classList.add('hidden');
    el('count-stop').textContent = '0';
    el('usage-text').textContent = `0 / ${formatTokens(Number(el('tokenBudget').value) || 60000)}`;
    el('usage-bar').style.width = '0%';
    el('usage-bar').dataset.level = 'normal';
    renderPlaceholders();
    validateBudget();
  });

  el('tokenBudget').addEventListener('input', validateBudget);
  el('allowPartialRun').addEventListener('change', validateBudget);

  el('toggle-key').addEventListener('click', (e) => {
    const input = el('apiKey');
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    e.target.textContent = show ? '隐藏' : '显示';
  });

  for (const chip of document.querySelectorAll('.chip[data-base]')) {
    chip.addEventListener('click', () => {
      el('baseUrl').value = chip.dataset.base;
      el('model').value = chip.dataset.model;
      el('apiKey').focus();
    });
  }

  el('export-json').addEventListener('click', () => {
    if (state.runId) window.location.href = `/api/detect/${state.runId}/report.json`;
  });
  el('export-html').addEventListener('click', () => {
    if (state.runId) window.location.href = `/api/detect/${state.runId}/report.html?download=1`;
  });
  el('view-html').addEventListener('click', () => {
    if (state.runId) window.open(`/api/detect/${state.runId}/report.html`, '_blank', 'noopener');
  });
}

/* ---------------- 前置预估与拦截 ---------------- */

/** 把启动时干跑出来的预估渲染到表单上 */
function renderEstimate() {
  const est = state.estimate;
  const line = el('estimate-line');
  const details = el('estimate-details');
  if (!est || !line) return;

  line.innerHTML =
    `整套检测预估 <b style="color:#cfd8ea">≈ ${formatTokens(est.projectedTokens)} token</b>` +
    `（预期 ${formatTokens(est.expectedTokens)} / 最坏 ${formatTokens(est.worstCaseTokens)}，约 ${est.calls} 次调用）`;

  const list = el('estimate-list');
  if (details && list && Array.isArray(est.perProbe)) {
    list.innerHTML = est.perProbe
      .filter((p) => p.expectedTokens > 0)
      .map(
        (p) =>
          `<li><b>${escapeHtml(p.name)}</b> ≈ ${formatTokens(p.expectedTokens)} token` +
          `（输入 ${formatTokens(p.promptTokens)} + 输出 ${formatTokens(p.completionTokens)}，${p.calls} 次调用）</li>`
      )
      .join('');
    if (est.notes?.length) {
      list.innerHTML += est.notes.map((n) => `<li>${escapeHtml(n)}</li>`).join('');
    }
    details.classList.remove('hidden');
  }
}

/**
 * 前置告警：预估消耗 vs 用户设置的上限。
 * 预估值高于上限时（且未勾选「仍运行」）直接禁用「开始检测」，与后端拒绝逻辑保持一致。
 */
function validateBudget() {
  const est = state.estimate;
  const box = el('precheck-box');
  const button = el('start-btn');
  if (!est || !box || !button) return true;
  if (state.running) return true;

  const limit = Number(el('tokenBudget').value) || 0;
  const projected = est.projectedTokens;
  const allowPartial = el('allowPartialRun').checked;
  const ratio = limit > 0 ? projected / limit : Number.POSITIVE_INFINITY;
  const percent = Number.isFinite(ratio) ? Math.round(ratio * 100) : null;

  let level;
  let html;
  if (limit < projected && !allowPartial) {
    level = 'block';
    html =
      `<b>预检拦截</b>：套装探针预估需要约 <b>${formatTokens(projected)}</b> token，` +
      `而当前上限只有 ${formatTokens(limit)}，后端会直接拒绝启动（不会发出任何请求）。` +
      `<br>请把上限提高到 <b>${formatTokens(Math.ceil(projected * 1.05))}</b> 以上，` +
      `或勾选下方「额度不足时仍运行」。`;
    button.disabled = true;
  } else if (limit < projected && allowPartial) {
    level = 'warn';
    html =
      `预估 ${formatTokens(projected)} token 高于上限 ${formatTokens(limit)}，已允许中途终止：` +
      '触顶后会跳过剩余探针，报告会标注为不完整。';
    button.disabled = false;
  } else if (percent !== null && percent >= 70) {
    level = 'warn';
    html = `预估消耗约占上限的 ${percent}%，检测过程中存在提前触顶的可能。`;
    button.disabled = false;
  } else {
    level = 'ok';
    html = `预检通过：预估约占上限的 ${percent ?? '—'}%，额度足以跑完全部探针。`;
    button.disabled = false;
  }

  box.dataset.level = level;
  box.innerHTML = html;
  box.classList.remove('hidden');
  return level !== 'block';
}

/* ---------------- 提交流程 ---------------- */

async function onSubmit(event) {
  event.preventDefault();
  const baseUrl = el('baseUrl').value.trim();
  const apiKey = el('apiKey').value.trim();
  const model = el('model').value.trim();
  const tokenBudget = Math.max(1000, Number(el('tokenBudget').value) || 60000);
  const allowPartialRun = el('allowPartialRun').checked;
  if (!baseUrl || !apiKey || !model) return;
  // 双保险：预检不过就不提交，后端也会再拦一道
  if (!validateBudget()) {
    showError('预检未通过：Token 上限低于整套检测的预估消耗，已阻止启动。请提高上限或勾选「额度不足时仍运行」。');
    return;
  }

  stopStream();
  hideError();
  state.running = true;
  state.preflightNotice = null;
  state.results.clear();
  state.summary = null;
  state.finished = false;
  renderPlaceholders();
  el('findings').classList.add('hidden');
  el('overview').classList.remove('hidden');
  el('export-json').disabled = true;
  el('export-html').disabled = true;
  el('view-html').disabled = true;
  el('total-score').textContent = '0';
  el('donut').style.background = donutBackground(0, 'pending');
  el('risk-label').textContent = '检测进行中';
  el('risk-desc').textContent = '正在并发执行 14 路探针…';
  el('progress-text').textContent = `0 / ${state.catalog.length || 14} 探针完成`;
  el('progress-bar').style.width = '0%';
  el('count-pass').textContent = '0';
  el('count-warn').textContent = '0';
  el('count-fail').textContent = '0';
  el('count-stop').textContent = '0';
  el('budget-banner').classList.add('hidden');
  renderUsage({ limit: tokenBudget, spent: 0, reserved: 0, usedPercent: 0, exhausted: false });
  el('target-line').textContent = `${baseUrl} · ${model}`;
  el('start-btn').disabled = true;
  el('start-btn').textContent = '检测中…';

  state.startedAt = Date.now();
  state.timer = setInterval(() => {
    el('progress-time').textContent = `已用时 ${((Date.now() - state.startedAt) / 1000).toFixed(1)}s`;
  }, 200);

  let runId;
  try {
    const res = await fetch('/api/detect', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ baseUrl, apiKey, model, tokenBudget, allowPartialRun })
    });
    const data = await res.json();
    if (!res.ok) {
      const error = new Error(data.error || `HTTP ${res.status}`);
      error.payload = data;
      throw error;
    }
    runId = data.runId;
    state.tokenBudget = data.tokenBudget ?? tokenBudget;
    if (data.warning) showBudgetNotice(data.warning);
  } catch (error) {
    const payload = error.payload;
    if (payload?.code === 'BUDGET_TOO_SMALL') {
      const tips = (payload.suggestions || []).map((s) => `· ${s}`).join('\n');
      showError(`预检拦截：未向端点发送任何请求。\n${payload.error}\n${tips}`);
    } else {
      showError(`无法启动检测：${error.message}`);
    }
    state.running = false;
    finishRun('启动失败');
    validateBudget();
    return;
  }

  state.runId = runId;
  // 密钥字段从内存里清掉，页面上不再保留
  el('apiKey').value = '';
  el('apiKey').type = 'password';
  el('toggle-key').textContent = '显示';

  openStream(runId);
}

function openStream(runId) {
  const source = new EventSource(`/api/detect/${runId}/events`);
  state.source = source;

  source.onmessage = (event) => {
    let payload;
    try {
      payload = JSON.parse(event.data);
    } catch {
      return;
    }
    handleEvent(payload);
  };

  source.addEventListener('end', () => {
    source.close();
    if (state.source === source) state.source = null;
  });

  source.onerror = () => {
    if (state.finished) {
      source.close();
      state.source = null;
      return;
    }
    showError('实时通道中断，正在尝试重新连接…');
  };
}

function handleEvent(payload) {
  switch (payload.type) {
    case 'snapshot':
      if (payload.catalog?.length && payload.catalog.length !== state.catalog.length) {
        state.catalog = payload.catalog;
        renderPlaceholders();
      }
      if (payload.run?.results) {
        for (const result of Object.values(payload.run.results)) updateCard(result);
      }
      if (payload.run?.summary) applySummary(payload.run.summary, payload.run.status, payload.run.durationMs, payload.run.finishedAt);
      if (payload.run?.usage) renderUsage(payload.run.usage);
      if (payload.run?.status && payload.run.status !== 'running') finishRun();
      break;
    case 'usage':
      renderUsage(payload.usage);
      break;
    case 'probe-start':
      markRunning(payload.id);
      break;
    case 'probe':
      hideError();
      updateCard(payload.result);
      updateProgress();
      break;
    case 'summary':
      applySummary(payload.summary, payload.status, payload.durationMs, payload.finishedAt);
      break;
    case 'done':
      finishRun();
      break;
    case 'closed':
      stopStream();
      showError('本次检测记录已过期并从内存中清除，如需继续请重新发起检测。');
      finishRun('记录已过期');
      break;
    default:
      break;
  }
}

/* ---------------- 渲染 ---------------- */

function cardOf(id) {
  return grid.querySelector(`.card[data-id="${id}"]`);
}

function markRunning(id) {
  const card = cardOf(id);
  if (!card || card.dataset.status !== 'pending') return;
  card.dataset.status = 'running';
  card.querySelector('.pill').textContent = STATUS_TEXT.running;
}

function updateCard(result) {
  const card = cardOf(result.id);
  if (!card) return;
  state.results.set(result.id, result);
  card.dataset.status = result.status;
  card.querySelector('.pill').textContent = STATUS_TEXT[result.status] || result.status;
  card.querySelector('.mini-donut').style.background = donutBackground(result.score, result.status);
  card.querySelector('.score-value').textContent = Number.isFinite(result.score) ? result.score : '—';
  card.querySelector('.elapsed').textContent = `耗时 ${formatMs(result.elapsedMs)}`;
  card.querySelector('.evidence').textContent = result.evidence || '—';

  const notes = card.querySelector('.notes');
  notes.innerHTML = '';
  if (result.notes?.length) {
    for (const note of result.notes) {
      const li = document.createElement('li');
      li.textContent = note;
      notes.appendChild(li);
    }
    notes.classList.remove('hidden');
  } else {
    notes.classList.add('hidden');
  }

  const raw = card.querySelector('.raw');
  if (result.raw) {
    card.querySelector('pre').textContent = JSON.stringify(result.raw, null, 2);
    raw.classList.remove('hidden');
  }
}

function updateProgress() {
  const done = state.results.size;
  const total = state.catalog.length || 14;
  el('progress-text').textContent = `${done} / ${total} 探针完成`;
  el('progress-bar').style.width = `${(done / total) * 100}%`;

  let pass = 0;
  let warn = 0;
  let fail = 0;
  let stop = 0;
  for (const res of state.results.values()) {
    if (res.status === 'pass') pass += 1;
    else if (res.status === 'warn') warn += 1;
    else if (res.status === 'fail') fail += 1;
    else if (res.status === 'aborted' || res.status === 'skipped') stop += 1;
  }
  el('count-pass').textContent = pass;
  el('count-warn').textContent = warn;
  el('count-fail').textContent = fail;
  el('count-stop').textContent = stop;
}

function applySummary(summary, status, durationMs, finishedAt) {
  if (!summary) return;
  state.summary = summary;
  el('total-score').textContent = summary.totalScore;
  el('donut').style.background = donutBackground(summary.totalScore, statusColorFor(summary.totalScore));
  el('risk-label').textContent = summary.riskLabel;
  el('risk-desc').textContent = summary.riskDesc;
  el('count-pass').textContent = summary.counts?.pass ?? 0;
  el('count-warn').textContent = summary.counts?.warn ?? 0;
  el('count-fail').textContent = summary.counts?.fail ?? 0;
  el('count-stop').textContent = (summary.counts?.aborted ?? 0) + (summary.counts?.skipped ?? 0);
  el('progress-bar').style.width = '100%';
  if (summary.usage) renderUsage(summary.usage);
  if (durationMs) el('progress-time').textContent = `总耗时 ${formatMs(durationMs)}`;

  const banner = el('budget-banner');
  if (summary.note || summary.budgetExhausted) {
    const parts = [];
    if (summary.budgetExhausted) {
      parts.push('<b>Token 预算已触顶</b>：累计用量达到上限，所有在途探针已立即中止，后续探针不再调用 API。');
    }
    if (summary.note) parts.push(escapeHtml(summary.note));
    parts.push('提高「Token 上限」后重新检测，即可跑完全部探针。');
    banner.innerHTML = parts.join('<br>');
    banner.classList.remove('hidden');
  } else if (state.preflightNotice) {
    // 没有触顶问题时保留开跑前的预检提示，不让它一闪而过
    banner.innerHTML = `<b>Token 预检提示</b>：${escapeHtml(state.preflightNotice)}`;
    banner.classList.remove('hidden');
  } else {
    banner.classList.add('hidden');
  }

  const list = el('findings-list');
  list.innerHTML = '';
  if (summary.findings?.length) {
    for (const finding of summary.findings.slice(0, 12)) {
      const li = document.createElement('li');
      const scoreText = Number.isFinite(finding.score) ? `${finding.score}/10` : STATUS_TEXT[finding.status] || '未执行';
      li.innerHTML = `<b>${escapeHtml(finding.name)}</b> <span style="color:${STATUS_COLOR[finding.status] || '#8b9ab8'}">${scoreText}</span> — ${escapeHtml(finding.evidence)}`;
      list.appendChild(li);
    }
    el('findings').classList.remove('hidden');
  } else {
    el('findings').classList.add('hidden');
  }
  el('progress-text').textContent = `${summary.probesRun ?? 0} / ${summary.probesTotal ?? 14} 探针完成`;
  if (finishedAt) state.finished = true;
}

function statusColorFor(score) {
  if (score >= 7.5) return 'pass';
  if (score >= 4) return 'warn';
  return 'fail';
}

function finishRun(label) {
  state.finished = true;
  state.running = false;
  clearInterval(state.timer);
  state.timer = null;
  stopStream();
  el('start-btn').disabled = false;
  el('start-btn').textContent = '开始检测';
  // 结束后重新按当前上限做一次预检（预检不过则保持禁用）
  validateBudget();
  if (state.runId || label) {
    el('export-json').disabled = !state.runId;
    el('export-html').disabled = !state.runId;
    el('view-html').disabled = !state.runId;
  }
  if (label) el('progress-time').textContent = label;
}

function stopStream() {
  clearInterval(state.timer);
  state.timer = null;
  if (state.source) {
    state.source.close();
    state.source = null;
  }
}

function showError(message) {
  const box = el('error-box');
  box.textContent = message;
  box.classList.remove('hidden');
}

/** 预检告警（例如「预估已占上限 83%，可能提前触顶」） */
function showBudgetNotice(text) {
  const banner = el('budget-banner');
  state.preflightNotice = text;
  banner.innerHTML = `<b>Token 预检提示</b>：${escapeHtml(text)}`;
  banner.classList.remove('hidden');
}

function hideError() {
  el('error-box').classList.add('hidden');
}

function formatMs(ms) {
  if (!Number.isFinite(ms)) return '—';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

function formatTokens(n) {
  return Number(n || 0).toLocaleString('en-US');
}

/** Token 用量条：spent=已结算，reserved=在途请求的预留额度 */
function renderUsage(usage) {
  if (!usage || !usage.limit) return;
  state.usage = usage;
  const reserved = usage.reserved || 0;
  el('usage-text').textContent =
    `${formatTokens(usage.spent)} / ${formatTokens(usage.limit)}` + (reserved > 0 ? `　（在途预留 ${formatTokens(reserved)}）` : '');
  const percent = Math.min(100, usage.usedPercent ?? ((usage.spent + reserved) / usage.limit) * 100);
  const bar = el('usage-bar');
  bar.style.width = `${percent}%`;
  bar.dataset.level = usage.exhausted ? 'full' : percent >= 80 ? 'high' : 'normal';
}

boot();
