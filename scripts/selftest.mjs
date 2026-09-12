/**
 * 端到端自测：起本地 mock 上游 → 跑完整检测 → 断言探针打分方向正确。
 * 用法：node scripts/selftest.mjs
 */

import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describeBlockedIp } from '../lib/target-policy.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, '..');
const APP_PORT = 8899;
const MOCK_PORT = 8898;
const SAFE_PORT = 8897;
const SAFE_OPEN_PORT = 8896;
const SAFE_TOKEN = 'selftest-token-please-rotate-0001';

function start(file, env) {
  const child = spawn(process.execPath, [path.join(root, file)], {
    env: { ...process.env, ...env },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child.stdout.on('data', (d) => process.stdout.write(`  │ ${d}`));
  child.stderr.on('data', (d) => process.stderr.write(`  │ ${d}`));
  return child;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(url, tries = 40) {
  for (let i = 0; i < tries; i += 1) {
    try {
      const res = await fetch(url);
      if (res.ok) return true;
    } catch {
      /* 重试 */
    }
    await sleep(250);
  }
  throw new Error(`等待服务失败：${url}`);
}

async function runDetect({ baseUrl, apiKey, model, tokenBudget, allowPartialRun = false }) {
  const res = await fetch(`http://127.0.0.1:${APP_PORT}/api/detect`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ baseUrl, apiKey, model, tokenBudget, allowPartialRun })
  });
  if (!res.ok) throw new Error(`启动失败：${await res.text()}`);
  const { runId } = await res.json();

  const deadline = Date.now() + 180_000;
  while (Date.now() < deadline) {
    const snap = await (await fetch(`http://127.0.0.1:${APP_PORT}/api/detect/${runId}`)).json();
    if (snap.status !== 'running') return snap;
    await sleep(1000);
  }
  throw new Error('检测超时');
}

function report(label, snap) {
  process.stdout.write(`\n=== ${label} ===\n`);
  const u = snap.summary.usage;
  process.stdout.write(
    `总分 ${snap.summary.totalScore}/10 · ${snap.summary.riskLabel}` +
      (u ? ` · Token ${u.spent}/${u.limit}${u.exhausted ? '（已触顶）' : ''}` : '') +
      ` · 有效 ${snap.summary.probesRun}/${snap.summary.probesTotal}` +
      (snap.summary.probesAborted + snap.summary.probesSkipped
        ? ` · 终止 ${snap.summary.probesAborted} / 跳过 ${snap.summary.probesSkipped}`
        : '') +
      '\n'
  );
  for (const [id, r] of Object.entries(snap.results)) {
    const mark = r.status === 'pass' ? '✓' : r.status === 'warn' ? '!' : r.status === 'fail' ? '✗' : '⏹';
    process.stdout.write(`  ${mark} ${id.padEnd(22)} ${String(r.score ?? '—').padStart(4)}  ${r.evidence.slice(0, 110)}\n`);
  }
  return snap;
}

function expect(condition, message) {
  if (!condition) {
    process.stdout.write(`\n❌ 断言失败：${message}\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write(`✓ ${message}\n`);
  }
}

// 人为延迟 250ms：让探针真的并发在途，才能验证「触顶后打断在途请求」
const mock = start('mock-upstream.mjs', { MOCK_PORT: String(MOCK_PORT), MOCK_DELAY_MS: '250' });
// 不显式设置 PROBE_CONCURRENCY：让主实例跑「默认并发」，顺便覆盖默认值这条路径
const app = start('server.mjs', { PORT: String(APP_PORT), HOST: '127.0.0.1', RUN_TTL_MS: '300000' });
// deploy-safe 实例（默认禁止私网目标）与「显式放行私网」实例
const safeApp = start('server.mjs', {
  PORT: String(SAFE_PORT),
  HOST: '127.0.0.1',
  DEPLOY_SAFE: '1',
  APP_TOKEN: SAFE_TOKEN,
  ALLOW_PRIVATE_TARGETS: '',
  RUN_TTL_MS: '300000'
});
const safeOpenApp = start('server.mjs', {
  PORT: String(SAFE_OPEN_PORT),
  HOST: '127.0.0.1',
  DEPLOY_SAFE: '1',
  APP_TOKEN: SAFE_TOKEN,
  ALLOW_PRIVATE_TARGETS: '1',
  RUN_TTL_MS: '300000'
});

try {
  await waitFor(`http://127.0.0.1:${APP_PORT}/api/health`);
  await waitFor(`http://127.0.0.1:${MOCK_PORT}/v1/models`, 20).catch(() => {});
  const base = `http://127.0.0.1:${MOCK_PORT}/v1`;

  const honest = report('诚实桩', await runDetect({ baseUrl: base, apiKey: 'demo-key-honest', model: 'gpt-4o-mini' }));
  const shady = report('黑心桩', await runDetect({ baseUrl: base, apiKey: 'shady-demo-key', model: 'gpt-4o-mini' }));

  // —— 需求 2：前置预估 + 源头拦截 ——
  const statsBefore = await (await fetch(`http://127.0.0.1:${MOCK_PORT}/__stats`)).json();
  const refusalRes = await fetch(`http://127.0.0.1:${APP_PORT}/api/detect`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ baseUrl: base, apiKey: 'demo-key-honest', model: 'gpt-4o-mini', tokenBudget: 2000 })
  });
  const refusal = await refusalRes.json();
  await sleep(1500);
  const statsAfterRefusal = await (await fetch(`http://127.0.0.1:${MOCK_PORT}/__stats`)).json();

  const catalog = await (await fetch(`http://127.0.0.1:${APP_PORT}/api/catalog`)).json();

  // —— 需求 1：运行时 Token 闸门（允许中途终止，用于验证触顶即刻收尾）——
  const budgetStart = Date.now();
  const limited = report(
    '预算受限（上限 2000 token + 允许中途终止）',
    await runDetect({ baseUrl: base, apiKey: 'demo-key-honest', model: 'gpt-4o-mini', tokenBudget: 2000, allowPartialRun: true })
  );
  const limitedMs = Date.now() - budgetStart;
  const statsAfter = await (await fetch(`http://127.0.0.1:${MOCK_PORT}/__stats`)).json();
  await sleep(2000);
  const statsLater = await (await fetch(`http://127.0.0.1:${MOCK_PORT}/__stats`)).json();

  const tiny = report(
    '预算过小（上限 1000 token + 允许中途终止）',
    await runDetect({ baseUrl: base, apiKey: 'demo-key-honest', model: 'gpt-4o-mini', tokenBudget: 1000, allowPartialRun: true })
  );

  // —— deploy-safe：鉴权 + 私网目标拦截 ——
  const safeHealth = await (await fetch(`http://127.0.0.1:${SAFE_PORT}/api/health`)).json();
  const noTokenRes = await fetch(`http://127.0.0.1:${SAFE_PORT}/api/catalog`);
  const statsBeforeSafe = await (await fetch(`http://127.0.0.1:${MOCK_PORT}/__stats`)).json();
  const noTokenDetectRes = await fetch(`http://127.0.0.1:${SAFE_PORT}/api/detect`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ baseUrl: base, apiKey: 'demo-key', model: 'gpt-4o-mini' })
  });
  const badTokenRes = await fetch(`http://127.0.0.1:${SAFE_PORT}/api/session`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: 'definitely-wrong-token' })
  });
  const goodTokenRes = await fetch(`http://127.0.0.1:${SAFE_PORT}/api/session`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ token: SAFE_TOKEN })
  });
  const setCookie = goodTokenRes.headers.get('set-cookie') || '';
  const cookie = setCookie.split(';')[0];
  const withCookieRes = await fetch(`http://127.0.0.1:${SAFE_PORT}/api/catalog`, { headers: { cookie } });
  const blockedRes = await fetch(`http://127.0.0.1:${SAFE_PORT}/api/detect`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-app-token': SAFE_TOKEN },
    body: JSON.stringify({ baseUrl: base, apiKey: 'demo-key', model: 'gpt-4o-mini' })
  });
  const blocked = await blockedRes.json();
  await sleep(1200);
  const statsAfterSafe = await (await fetch(`http://127.0.0.1:${MOCK_PORT}/__stats`)).json();
  const openHealth = await (await fetch(`http://127.0.0.1:${SAFE_OPEN_PORT}/api/health`)).json();
  process.stdout.write(
    `\n=== deploy-safe ===\n  鉴权 ${safeHealth.authRequired ? '开启' : '关闭'} / 私网目标 ${safeHealth.allowPrivateTargets ? '放行' : '拦截'}` +
      ` / 目标拦截响应 ${blockedRes.status} ${blocked.code || ''}\n`
  );

  process.stdout.write('\n--- 断言 ---\n');
  expect(Object.keys(honest.results).length === 14, '诚实桩跑满 14 个探针');
  expect(honest.summary.totalScore >= 8, `诚实桩总分应 ≥ 8，实际 ${honest.summary.totalScore}`);
  expect(shady.summary.totalScore < honest.summary.totalScore - 2, `黑心桩总分显著低于诚实桩（${shady.summary.totalScore} < ${honest.summary.totalScore}）`);
  expect(shady.results.substitution.status !== 'pass', '调包探针应命中黑心桩');
  expect(shady.results['prompt-extraction'].status === 'fail', '提示词提取应发现隐藏指令');
  expect(shady.results.jailbreak.status !== 'pass', '越狱抵抗应命中');
  expect(shady.results.wallet.status !== 'pass', '钱包安全应命中');
  expect(shady.results['error-leak'].status !== 'pass', '错误泄露应命中');
  expect(shady.results['token-injection'].status === 'fail', 'Token 注入应命中');
  expect(honest.results.connectivity.score === 10, '诚实桩连通性满分');
  expect(honest.results.stream.score >= 8, '诚实桩流完整性正常');
  expect(honest.summary.probesAborted === 0 && honest.summary.probesSkipped === 0, '默认额度下 14 个探针全部执行，无终止/跳过');

  // —— 前置预检断言 ——
  expect(catalog.estimate?.projectedTokens > 0, `目录接口带出整套检测的 token 预估（${catalog.estimate?.projectedTokens}）`);
  expect(refusalRes.status === 400 && refusal.code === 'BUDGET_TOO_SMALL', '预估超上限时前置拦截（HTTP 400 / BUDGET_TOO_SMALL）');
  expect(statsAfterRefusal.chatRequests === statsBefore.chatRequests, `被拦截时未向端点发出任何请求（新增 ${statsAfterRefusal.chatRequests - statsBefore.chatRequests} 次）`);
  expect(refusal.estimate?.projectedTokens > refusal.tokenBudget, '拦截响应说明「预估 > 上限」');
  expect(Array.isArray(refusal.suggestions) && refusal.suggestions.length >= 1, '拦截响应给出可执行的调整建议');
  expect(catalog.defaultTokenBudget >= catalog.estimate.projectedTokens, `默认上限高于预检阈值（${catalog.defaultTokenBudget} ≥ ${catalog.estimate.projectedTokens}）`);

  const lim = limited.summary;
  const limUsage = lim.usage;
  expect(lim.probesAborted + lim.probesSkipped > 0, `额度受限时应有探针被终止或跳过（终止 ${lim.probesAborted} / 跳过 ${lim.probesSkipped}）`);
  expect(lim.probesRun < 14, `额度受限时不应跑满 14 个探针（实际有效 ${lim.probesRun}）`);
  expect(limUsage.spent <= limUsage.limit * 1.02, `实际用量不得明显超出上限（${limUsage.spent} ≤ ${limUsage.limit}）`);
  expect(limUsage.exhausted === true || lim.probesSkipped > 0, '额度受限时应触发触顶或跳过保护');
  expect(limitedMs < 60_000, `额度触顶后应立即收尾，未卡在重试里（耗时 ${(limitedMs / 1000).toFixed(1)}s）`);
  expect(statsLater.chatRequests === statsAfter.chatRequests, `触顶后不再向上游发起任何请求（后续 2s 内新增 ${statsLater.chatRequests - statsAfter.chatRequests} 次）`);
  expect(Object.values(limited.results).every((r) => r.status !== 'fail' || !/超时|timeout/i.test(r.evidence)), '终止的探针不会被误记为端点超时失败');

  // —— deploy-safe 断言 ——
  expect(safeHealth.deploySafe === true && safeHealth.authRequired === true, 'deploy-safe 实例已开启鉴权');
  expect(safeHealth.allowPrivateTargets === false, 'deploy-safe 默认禁止私网/回环目标');
  expect(noTokenRes.status === 401, `无令牌访问 /api/catalog 被拒（${noTokenRes.status}）`);
  expect(noTokenDetectRes.status === 401, `无令牌启动检测被拒（${noTokenDetectRes.status}）`);
  expect(badTokenRes.status === 401, '错误令牌登录被拒');
  expect(goodTokenRes.ok, '正确令牌可换取会话');
  expect(/HttpOnly/i.test(setCookie) && /SameSite=Strict/i.test(setCookie), '会话 Cookie 带 HttpOnly + SameSite=Strict');
  expect(withCookieRes.ok, '会话 Cookie 可访问受保护接口（SSE 同源自动带 Cookie）');
  expect(blockedRes.status === 400 && blocked.code === 'TARGET_BLOCKED', `私网目标被拦截（HTTP ${blockedRes.status} / ${blocked.code}）`);
  expect(statsAfterSafe.chatRequests === statsBeforeSafe.chatRequests, `拦截期间零上游请求（新增 ${statsAfterSafe.chatRequests - statsBeforeSafe.chatRequests} 次）`);
  expect(openHealth.deploySafe === true && openHealth.allowPrivateTargets === true, 'ALLOW_PRIVATE_TARGETS=1 可显式放行私网（本地演示桩仍可用）');
  expect(
    describeBlockedIp('169.254.169.254') !== null &&
      describeBlockedIp('::ffff:10.0.0.1') !== null &&
      describeBlockedIp('fc00::1') !== null &&
      describeBlockedIp('8.8.8.8') === null,
    'IP 判定：云元数据 / IPv4 映射内网 / ULA 被拦，公网放行'
  );

  const tinyLim = tiny.summary;
  expect(
    tinyLim.usage.exhausted === true && tinyLim.probesRun < 14,
    `极小额度下必定触顶且跑不满 14 项（有效 ${tinyLim.probesRun}/14，已用 ${tinyLim.usage.spent}/${tinyLim.usage.limit}）`
  );
  expect(
    tinyLim.probesRun === 0 ? tinyLim.riskLabel === '检测未完成' : tinyLim.budgetExhausted === true,
    `额度不足时结论不会被伪装成「完全正常」（${tinyLim.riskLabel}${tinyLim.probesRun ? `，已标注预算触顶` : ''}）`
  );
  expect(tinyLim.usage.spent <= tinyLim.usage.limit * 1.02, `极小额度下用量仍不越界（${tinyLim.usage.spent} ≤ ${tinyLim.usage.limit}）`);

  const json = await (await fetch(`http://127.0.0.1:${APP_PORT}/api/detect/${honest.id}/report.json`)).text();
  expect(!json.includes('demo-key-honest'), 'JSON 报告不含明文 API Key');
  const html = await (await fetch(`http://127.0.0.1:${APP_PORT}/api/detect/${honest.id}/report.html`)).text();
  expect(html.startsWith('<!doctype html>') && !html.includes('demo-key-honest'), 'HTML 报告生成且不含明文 API Key');
} catch (error) {
  process.stdout.write(`\n❌ 自测异常：${error.stack || error}\n`);
  process.exitCode = 1;
} finally {
  for (const child of [app, mock, safeApp, safeOpenApp]) {
    child.kill('SIGTERM');
  }
  await sleep(400);
  process.exit(process.exitCode || 0);
}
