/**
 * 报告导出：JSON 与自包含 HTML。
 * 输入必须是已白名单化的公开数据结构（不含 apiKey）。
 */

import { PROBES } from './probes/index.mjs';

const STATUS_TEXT = {
  pass: '通过',
  warn: '警告',
  fail: '失败',
  aborted: '已终止',
  skipped: '已跳过',
  running: '检测中',
  pending: '等待中'
};

export function buildJsonReport(run) {
  return {
    schema: 'relay-model-guard/report@1',
    generatedAt: new Date().toISOString(),
    target: run.target,
    status: run.status,
    startedAt: run.startedAt,
    finishedAt: run.finishedAt,
    durationMs: run.durationMs,
    summary: run.summary,
    tokenUsage: run.summary?.usage ?? run.usage ?? null,
    weightTable: PROBES.map((p) => ({ id: p.id, name: p.name, weight: p.weight, group: p.group })),
    probes: PROBES.map((probe) => {
      const res = run.results[probe.id];
      return {
        id: probe.id,
        name: probe.name,
        group: probe.group,
        weight: probe.weight,
        summary: probe.summary,
        status: res?.status ?? 'pending',
        score: res?.score ?? null,
        evidence: res?.evidence ?? null,
        elapsedMs: res?.elapsedMs ?? null,
        notes: res?.notes ?? [],
        raw: res?.raw ?? null
      };
    }),
    disclaimer:
      '本报告由自动化探针生成，仅为概率性证据，不构成质量鉴定或法律意见，请结合业务场景人工复核。' +
      '检测过程不保存 API Key，日志已脱敏，但会向目标端点发送真实请求并消耗其额度。' +
      '请仅用于你已获得授权的端点，并自行承担使用后果（详见项目根目录 DISCLAIMER.md）。'
  };
}

function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function scoreColor(score) {
  if (score === null || score === undefined) return '#64748b';
  if (score >= 7.5) return '#16a34a';
  if (score >= 4) return '#d97706';
  return '#dc2626';
}

export function buildHtmlReport(run) {
  const data = buildJsonReport(run);
  const s = data.summary || {};
  const color = scoreColor;

  const cards = data.probes
    .map((p, i) => {
      const raw = p.raw
        ? `<details><summary>原始证据</summary><pre>${esc(JSON.stringify(p.raw, null, 2))}</pre></details>`
        : '';
      const notes = p.notes?.length
        ? `<ul class="notes">${p.notes.map((n) => `<li>${esc(n)}</li>`).join('')}</ul>`
        : '';
      return [
        '<article class="card">',
        '<header>',
        `<span class="idx">#${i + 1}</span>`,
        `<h3>${esc(p.name)}</h3>`,
        `<span class="badge" style="background:${color(p.score)}">${esc(STATUS_TEXT[p.status] || p.status)}</span>`,
        `<span class="score" style="color:${color(p.score)}">${p.score === null ? '-' : p.score}<small>/10</small></span>`,
        '</header>',
        `<p class="meta">权重 ${(p.weight * 100).toFixed(0)}% · 分组 ${esc(p.group)} · 耗时 ${p.elapsedMs === null ? '-' : `${p.elapsedMs}ms`}</p>`,
        `<p class="evidence">${esc(p.evidence)}</p>`,
        notes,
        raw,
        '</article>'
      ].join('\n');
    })
    .join('\n');

  const findings = (s.findings || []).length
    ? `<ul class="findings">${s.findings
        .map(
          (f) =>
            `<li><b>${esc(f.name)}</b> <span style="color:${color(f.score)}">${f.score}/10</span> — ${esc(f.evidence)}</li>`
        )
        .join('')}</ul>`
    : '<p class="ok">全部探针通过，未发现需要整改的项。</p>';

  const groupRows = (s.groupScores || [])
    .map((g) => `<tr><td>${esc(g.group)}</td><td style="color:${color(g.score)};font-weight:600">${g.score}/10</td><td>${g.probes}</td></tr>`)
    .join('');

  const usage = data.tokenUsage;
  const usageLine = usage
    ? `Token 用量 <b>${usage.spent.toLocaleString('en-US')}</b> / 上限 ${usage.limit.toLocaleString('en-US')}（${usage.usedPercent}%，预留 ${usage.reserved.toLocaleString('en-US')}）`
    : '';
  const incompleteBanner = s.note
    ? `<p class="warn-banner">⚠️ ${esc(s.note)}</p>`
    : '';

  const css = [
    ':root{color-scheme:light}',
    '*{box-sizing:border-box}',
    'body{margin:0;padding:32px 20px 64px;font:15px/1.6 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif;background:#f1f5f9;color:#0f172a}',
    '.wrap{max-width:980px;margin:0 auto}',
    'h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 12px}',
    '.sub{color:#475569;margin:0 0 24px}',
    '.hero{background:#fff;border-radius:16px;padding:24px;display:flex;gap:28px;align-items:center;flex-wrap:wrap;box-shadow:0 1px 3px rgba(15,23,42,.08)}',
    `.total{font-size:48px;font-weight:700;line-height:1;color:${color(s.totalScore)}}`,
    '.total small{font-size:16px;color:#94a3b8;font-weight:400}',
    '.label{color:#64748b;font-size:13px}',
    '.chips{display:flex;gap:10px;flex-wrap:wrap}.chip{padding:6px 12px;border-radius:999px;font-size:13px;background:#e2e8f0}',
    'table{width:100%;border-collapse:collapse;background:#fff;border-radius:12px;overflow:hidden;margin:24px 0;box-shadow:0 1px 3px rgba(15,23,42,.08)}',
    'th,td{padding:10px 14px;text-align:left;border-bottom:1px solid #e2e8f0;font-size:14px}',
    'th{background:#f8fafc;color:#475569;font-weight:600}',
    '.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px}',
    '.card{background:#fff;border-radius:14px;padding:16px 18px;box-shadow:0 1px 3px rgba(15,23,42,.08)}',
    '.card header{display:flex;align-items:center;gap:8px;margin-bottom:6px}',
    '.card h3{font-size:15px;margin:0;flex:1}',
    '.idx{color:#94a3b8;font-size:12px}',
    '.badge{color:#fff;border-radius:999px;padding:2px 10px;font-size:12px}',
    '.score{font-weight:700;font-size:18px}.score small{color:#94a3b8;font-weight:400;font-size:11px}',
    '.meta{color:#94a3b8;font-size:12px;margin:0 0 8px}',
    '.evidence{margin:0 0 8px}',
    '.notes{margin:0 0 8px;padding-left:18px;color:#92400e;font-size:13px}',
    'details summary{cursor:pointer;color:#2563eb;font-size:13px}',
    'pre{background:#0f172a;color:#e2e8f0;padding:12px;border-radius:10px;overflow:auto;font-size:12px;max-height:340px}',
    '.findings{background:#fff;border-radius:12px;padding:16px 16px 16px 34px;box-shadow:0 1px 3px rgba(15,23,42,.08)}',
    '.ok{background:#dcfce7;color:#166534;padding:12px 16px;border-radius:12px}',
    '.warn-banner{background:#fef3c7;color:#92400e;padding:12px 16px;border-radius:12px;margin:0 0 16px}',
    '.usage{color:#475569;font-size:13px;margin:-8px 0 0}',
    'footer{margin-top:32px;color:#94a3b8;font-size:12px}'
  ].join('\n');

  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>中转 API 检测报告 · ${esc(data.target.model)}</title>
<style>
${css}
</style>
</head>
<body>
<div class="wrap">
  <h1>中转 API 模型检测报告</h1>
  <p class="sub">${esc(data.target.model)} · ${esc(data.target.baseUrl)} · 生成于 ${esc(data.generatedAt)}</p>
  <section class="hero">
    <div>
      <div class="label">综合得分</div>
      <div class="total">${s.totalScore ?? '-'}<small>/10</small></div>
    </div>
    <div>
      <div class="label">风险等级</div>
      <div style="font-size:20px;font-weight:600">${esc(s.riskLabel)}</div>
      <div class="label">${esc(s.riskDesc)}</div>
    </div>
    <div class="chips">
      <span class="chip">通过 ${s.counts?.pass ?? 0}</span>
      <span class="chip">警告 ${s.counts?.warn ?? 0}</span>
      <span class="chip">失败 ${s.counts?.fail ?? 0}</span>
      ${s.counts?.aborted || s.counts?.skipped ? `<span class="chip">终止/跳过 ${(s.counts?.aborted ?? 0) + (s.counts?.skipped ?? 0)}</span>` : ''}
      <span class="chip">耗时 ${data.durationMs ?? '-'} ms</span>
    </div>
  </section>
  <p class="usage">${usageLine}</p>
  ${incompleteBanner}
  <table>
    <tr><th>检测端点</th><th>声称模型</th><th>Key 指纹</th><th>探针完成度</th></tr>
    <tr>
      <td>${esc(data.target.baseUrl)}</td>
      <td>${esc(data.target.model)}</td>
      <td><code>${esc(data.target.keyFingerprint)}</code></td>
      <td>${s.probesRun ?? 0}/${s.probesTotal ?? PROBES.length}</td>
    </tr>
  </table>
  <table>
    <tr><th>分组</th><th>分组得分</th><th>探针数</th></tr>
    ${groupRows}
  </table>
  <h2>需要关注的问题</h2>
  ${findings}
  <h2>逐项结果</h2>
  <section class="grid">
${cards}
  </section>
  <footer>${esc(data.disclaimer)}</footer>
</div>
</body>
</html>`;
}
