/**
 * 中转 API 模型检测器 — HTTP 服务
 *
 * 安全约定：
 *  1. apiKey 只存在于进程内存中的 run 对象里，探针跑完立即擦除，不落盘、不进日志。
 *  2. 所有对外输出（日志、SSE、报告）都会先经过 redact()。
 *  3. run 数据带 TTL 自动回收，进程退出即全部消失。
 */

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';

import { Upstream, normalizeBaseUrl } from './lib/upstream.mjs';
import { PROBES, PROBE_ORDER, probeCatalog, summarize } from './lib/probes/index.mjs';
import { buildHtmlReport, buildJsonReport } from './lib/report.mjs';
import { keyFingerprint, redact, safeLog } from './lib/redact.mjs';
import { TokenBudget, abortReasonText, isAbortError } from './lib/budget.mjs';
import { computeSuiteEstimate } from './lib/estimate.mjs';
import { TargetBlockedError, assertTargetAllowed } from './lib/target-policy.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, 'public');

const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || '127.0.0.1';
/**
 * 探针并发度。默认 3：整套检测会发出 30+ 个请求，并发过高容易撞上中转的速率限制、
 * 也容易被判定为异常流量；并发 3 仍能在 20~60 秒内跑完，需要更快可显式调高（上限 14）。
 */
const PROBE_CONCURRENCY = clampInt(process.env.PROBE_CONCURRENCY, 1, 14, 3);
const PROBE_TIMEOUT_MS = clampInt(process.env.PROBE_TIMEOUT_MS, 5_000, 180_000, 75_000);
const RUN_TTL_MS = clampInt(process.env.RUN_TTL_MS, 60_000, 6 * 3_600_000, 30 * 60_000);
const MAX_RUNS = 200;
const MAX_BODY_BYTES = 32 * 1024;
const LONG_CONTEXT_CHARS = clampInt(process.env.LONG_CONTEXT_CHARS, 4_000, 200_000, 32_000);
const MIN_TOKEN_BUDGET = 1_000;
const MAX_TOKEN_BUDGET = 5_000_000;
/** 总时长护栏：到点立刻中止所有在途探针，避免并发请求卡在重试里 */
const RUN_DEADLINE_MS = clampInt(process.env.RUN_DEADLINE_MS, 10_000, 30 * 60_000, 300_000);
/** 前置闸门的安全系数：最低可接受上限 = 预期消耗 × 系数 */
const ESTIMATE_SAFETY_FACTOR = clampFloat(process.env.TOKEN_ESTIMATE_SAFETY, 1, 3, 1.15);

/* ---------------- deploy-safe 模式 ---------------- */

/** DEPLOY_SAFE=1：开启鉴权 + 私网拦截 + 全局配额，适合放到公网/内网服务器上 */
const DEPLOY_SAFE = /^(1|true|yes)$/i.test(process.env.DEPLOY_SAFE ?? '');
/** 访问令牌（deploy-safe 下必填；也支持 Authorization: Bearer 与 x-app-token） */
const APP_TOKEN = String(process.env.APP_TOKEN ?? '').trim();
/** 是否允许把请求发往私网/回环/链路本地地址。默认：本地模式允许，deploy-safe 模式禁止 */
const ALLOW_PRIVATE_TARGETS = process.env.ALLOW_PRIVATE_TARGETS === undefined
  ? !DEPLOY_SAFE
  : /^(1|true|yes)$/i.test(process.env.ALLOW_PRIVATE_TARGETS);
/** 手动跟随重定向的最大跳数（deploy-safe 下逐跳校验目标） */
const MAX_REDIRECTS = clampInt(process.env.MAX_REDIRECTS, 0, 10, 3);
/** 全局每小时允许启动的检测数（0 = 不限；deploy-safe 默认 60） */
const GLOBAL_RUNS_PER_HOUR = clampInt(process.env.GLOBAL_RUNS_PER_HOUR, 0, 100_000, DEPLOY_SAFE ? 60 : 0);
/** 同时进行的检测数上限 */
const MAX_CONCURRENT_RUNS = clampInt(process.env.MAX_CONCURRENT_RUNS, 1, 100, DEPLOY_SAFE ? 2 : 10);
/** 登录会话有效期 */
const SESSION_TTL_MS = clampInt(process.env.SESSION_TTL_MS, 60_000, 7 * 24 * 3_600_000, 12 * 3_600_000);
/** 部署在反向代理后面时，用 X-Forwarded-For 的第一跳作为限流 key */
const TRUST_PROXY = /^(1|true|yes)$/i.test(process.env.TRUST_PROXY ?? '');
/** 出站目标策略：allowPrivate=false 时阻断 SSRF 并逐跳校验重定向 */
const TARGET_POLICY = { allowPrivate: ALLOW_PRIVATE_TARGETS, maxRedirects: MAX_REDIRECTS };
/** sessionId -> 过期时间 */
const sessions = new Map();

if (DEPLOY_SAFE && !APP_TOKEN) {
  safeLog('❌ DEPLOY_SAFE=1 但未设置 APP_TOKEN：拒绝启动。');
  safeLog('   否则这等于把一个「能读回响应的 SSRF 客户端」开放给所有能访问到它的人。');
  safeLog('   生成方式：node -e "console.log(require(\'node:crypto\').randomBytes(24).toString(\'hex\'))"');
  process.exit(1);
}
if (DEPLOY_SAFE && ALLOW_PRIVATE_TARGETS) {
  safeLog('⚠️  DEPLOY_SAFE=1 且 ALLOW_PRIVATE_TARGETS=1：私网目标拦截已按你的要求关闭，SSRF 防护不再生效。');
}

/**
 * 前置预估：启动时把 14 个探针「干跑」一遍（纯本地计算，不联网、不发任何请求），
 * 按 prompt 估算 + 输出长度汇总出整套检测的 token 预估。
 */
const SUITE_ESTIMATE = await computeSuiteEstimate({ contextChars: LONG_CONTEXT_CHARS });
/** 前置闸门阈值：低于它直接拒绝启动 */
const PROJECTED_TOKENS = Math.ceil(SUITE_ESTIMATE.total * ESTIMATE_SAFETY_FACTOR);
/** 最坏情况：每个请求都把 max_tokens 用满（仅供参考展示） */
const WORST_CASE_TOKENS = SUITE_ESTIMATE.worstTotal;
/** 默认 Token 上限：优先取 TOKEN_BUDGET，否则按预估自动留 15% 余量 */
const DEFAULT_TOKEN_BUDGET = clampInt(
  process.env.TOKEN_BUDGET,
  MIN_TOKEN_BUDGET,
  MAX_TOKEN_BUDGET,
  Math.min(MAX_TOKEN_BUDGET, Math.max(MIN_TOKEN_BUDGET, Math.ceil(PROJECTED_TOKENS * 1.15)))
);

const ESTIMATE_PAYLOAD = {
  /** 前置闸门用的预估值（= 预期 × 安全系数） */
  projectedTokens: PROJECTED_TOKENS,
  /** 预期消耗 */
  expectedTokens: SUITE_ESTIMATE.total,
  /** 最坏情况（max_tokens 全用满） */
  worstCaseTokens: WORST_CASE_TOKENS,
  safetyFactor: ESTIMATE_SAFETY_FACTOR,
  promptTokens: SUITE_ESTIMATE.promptTokens,
  completionTokens: SUITE_ESTIMATE.completionTokens,
  calls: SUITE_ESTIMATE.calls,
  perProbe: SUITE_ESTIMATE.perProbe,
  notes: SUITE_ESTIMATE.notes
};

/** runId -> run（纯内存） */
const runs = new Map();
/** ip -> 限流桶 */
const rateBuckets = new Map();
/** ip -> 登录尝试桶 */
const loginBuckets = new Map();

function clampInt(value, lo, hi, fallback) {
  const n = Number.parseInt(value ?? '', 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(lo, Math.min(hi, n));
}

function clampFloat(value, lo, hi, fallback) {
  const n = Number.parseFloat(value ?? '');
  if (!Number.isFinite(n)) return fallback;
  return Math.max(lo, Math.min(hi, n));
}

/* ------------------------------------------------------------------ */
/* 运行生命周期                                                        */
/* ------------------------------------------------------------------ */

function createRun({ baseUrl, apiKey, model, tokenBudget }) {
  const id = randomUUID();
  const run = {
    id,
    apiKey,
    tokenBudget,
    budget: null,
    createdAt: Date.now(),
    startedAt: new Date().toISOString(),
    finishedAt: null,
    durationMs: null,
    status: 'running',
    error: null,
    target: {
      baseUrl,
      model,
      keyFingerprint: keyFingerprint(apiKey),
      keyPreview: '***'
    },
    results: {},
    order: PROBE_ORDER.slice(),
    summary: null,
    eventLog: [],
    subscribers: new Set(),
    timer: null,
    lastUsageEmit: 0
  };
  runs.set(id, run);
  return run;
}

/** 预算用量上报：最多每 200ms 推一次，避免刷屏 */
function emitUsage(run, force = false) {
  if (!run.budget) return;
  const now = Date.now();
  if (!force && now - run.lastUsageEmit < 200) return;
  run.lastUsageEmit = now;
  emit(run, { type: 'usage', usage: run.budget.snapshot() });
}

function emit(run, event) {
  run.eventLog.push(event);
  for (const send of run.subscribers) {
    try {
      send(event);
    } catch (error) {
      safeLog('SSE 推送失败:', error?.message || error);
    }
  }
}

function destroyRun(runId) {
  const run = runs.get(runId);
  if (!run) return;
  run.apiKey = null;
  run.budget?.stop();
  clearTimeout(run.timer);
  for (const send of run.subscribers) {
    try {
      send({ type: 'closed', reason: 'expired' });
    } catch {
      /* 忽略 */
    }
  }
  run.subscribers.clear();
  runs.delete(runId);
}

function scheduleCleanup(run) {
  run.timer = setTimeout(() => destroyRun(run.id), RUN_TTL_MS);
  run.timer.unref?.();
}

function evictOldestIfNeeded() {
  if (runs.size <= MAX_RUNS) return;
  const oldest = [...runs.values()].sort((a, b) => a.createdAt - b.createdAt)[0];
  if (oldest) destroyRun(oldest.id);
}

/** 对外可见的运行快照（严格白名单，绝不含 apiKey） */
function publicRun(run) {
  return redact({
    id: run.id,
    status: run.status,
    error: run.error,
    startedAt: run.startedAt,
    finishedAt: run.finishedAt,
    durationMs: run.durationMs,
    target: {
      baseUrl: run.target.baseUrl,
      model: run.target.model,
      keyFingerprint: run.target.keyFingerprint,
      keyPreview: run.target.keyPreview
    },
    order: run.order,
    results: run.results,
    summary: run.summary,
    tokenBudget: run.tokenBudget,
    usage: run.budget ? run.budget.snapshot() : null
  });
}

async function executeRun(run) {
  const upstream = new Upstream({
    baseUrl: run.target.baseUrl,
    apiKey: run.apiKey,
    model: run.target.model,
    budget: run.budget,
    targetPolicy: TARGET_POLICY
  });

  const ctx = {
    upstream,
    model: run.target.model,
    baseUrl: run.target.baseUrl,
    apiKey: run.apiKey,
    options: { contextChars: LONG_CONTEXT_CHARS },
    log: (message) => safeLog(`[run ${run.id.slice(0, 8)}]`, message),
    ask: async ({ system, user, maxTokens = 200, temperature = 0, timeoutMs, extra = {} }) => {
      const messages = [];
      if (system) messages.push({ role: 'system', content: system });
      messages.push({ role: 'user', content: user });
      return upstream.chat({ messages, max_tokens: maxTokens, temperature, ...extra }, { timeoutMs });
    }
  };

  const queue = PROBES.slice();
  const startedAt = Date.now();

  const worker = async () => {
    while (queue.length) {
      const probe = queue.shift();
      const t0 = Date.now();
      let payload;
      emit(run, { type: 'probe-start', id: probe.id, name: probe.name });
      // 额度已用尽 / 总时长超限：不再向端点发任何请求，直接标记
      if (!run.budget.canContinue()) {
        const result = buildResult(probe, abortedPayload(run.budget.signal.reason), Date.now() - t0);
        run.results[probe.id] = result;
        emit(run, { type: 'probe', result });
        continue;
      }
      // 轻微抖动，避免 14 路探针同一毫秒撞上中转的速率限制
      await new Promise((resolve) => setTimeout(resolve, 40 + Math.floor(Math.random() * 160)));
      try {
        payload = await withTimeout(probe.run(ctx), PROBE_TIMEOUT_MS, probe.name);
      } catch (error) {
        payload = isAbortError(error)
          ? abortedPayload(error)
          : {
              score: 0,
              status: 'fail',
              evidence: `探针执行异常：${String(error?.message || error).slice(0, 200)}`,
              notes: ['该探针未取得有效数据，计 0 分并参与权重计算'],
              raw: { error: redact(String(error?.stack || error?.message || error)).slice(0, 2000) }
            };
      }
      const elapsedMs = Date.now() - t0;
      const result = buildResult(probe, payload, elapsedMs);
      run.results[probe.id] = result;
      emit(run, { type: 'probe', result });
      safeLog(`[run ${run.id.slice(0, 8)}] ${probe.id} → ${result.status} ${result.score}/10 (${elapsedMs}ms)`);
    }
  };

  try {
    await Promise.all(Array.from({ length: Math.min(PROBE_CONCURRENCY, PROBES.length) }, worker));
    run.status = 'done';
  } catch (error) {
    run.status = 'error';
    run.error = redact(String(error?.message || error));
  } finally {
    run.finishedAt = new Date().toISOString();
    run.durationMs = Date.now() - startedAt;
    run.budget.stop();
    run.summary = summarize(run.results, { usage: run.budget.snapshot() });
    run.apiKey = null; // 密钥在此刻离开进程内存
    emitUsage(run, true);
    emit(run, {
      type: 'summary',
      summary: run.summary,
      status: run.status,
      durationMs: run.durationMs,
      finishedAt: run.finishedAt,
      usage: run.budget.snapshot()
    });
    emit(run, { type: 'done', status: run.status });
    scheduleCleanup(run);
    safeLog(
      `[run ${run.id.slice(0, 8)}] 完成：${run.summary.totalScore}/10 ${run.summary.riskLabel}` +
        `｜Token ${run.budget.spent}/${run.budget.limit}` +
        (run.summary.probesAborted + run.summary.probesSkipped > 0
          ? `（终止 ${run.summary.probesAborted} / 跳过 ${run.summary.probesSkipped}）`
          : '') +
        '，密钥已从内存擦除'
    );
  }
}

function abortedPayload(error) {
  return {
    score: null,
    status: error?.phase === 'reserve' ? 'skipped' : 'aborted',
    evidence: abortReasonText(error),
    notes: [
      error?.phase === 'reserve'
        ? '该探针所需额度超过剩余预算，未向端点发起请求'
        : '为保证额度不被烧穿，本次检测已提前终止；未执行的探针不计入总分'
    ],
    raw: { aborted: true, code: error?.code ?? null, phase: error?.phase ?? null, meta: error?.meta ?? null }
  };
}

function buildResult(probe, payload, elapsedMs) {
  return {
    id: probe.id,
    name: probe.name,
    group: probe.group,
    weight: probe.weight,
    status: payload.status,
    score: Number.isFinite(payload.score) ? payload.score : null,
    evidence: payload.evidence,
    notes: payload.notes || [],
    elapsedMs,
    raw: redact(payload.raw ?? null)
  };
}

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} 超过 ${Math.round(ms / 1000)}s 未返回`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/* ------------------------------------------------------------------ */
/* HTTP 工具                                                          */
/* ------------------------------------------------------------------ */

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('请求体过大'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function sendJson(res, status, payload) {
  const body = JSON.stringify(redact(payload));
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  });
  res.end(body);
}

function sendText(res, status, text, headers = {}) {
  res.writeHead(status, {
    'content-type': 'text/plain; charset=utf-8',
    'cache-control': 'no-store',
    ...headers
  });
  res.end(text);
}

/* ---------------- 鉴权（deploy-safe） ---------------- */

/** 定长摘要比较，避免用 == 比较令牌 */
function tokenDigest(value) {
  return createHash('sha256').update(String(value ?? '')).digest();
}

function safeEqual(a, b) {
  if (!a || !b) return false;
  return timingSafeEqual(tokenDigest(a), tokenDigest(b));
}

function parseCookies(header) {
  const out = {};
  for (const part of String(header || '').split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function issueSession(req, res) {
  const id = `${randomUUID()}${randomBytes(8).toString('hex')}`;
  sessions.set(id, Date.now() + SESSION_TTL_MS);
  const secure = /^(https)$/i.test(String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim());
  const cookie = [
    `rg_session=${id}`,
    'HttpOnly',
    'SameSite=Strict',
    'Path=/',
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
    secure ? 'Secure' : null
  ]
    .filter(Boolean)
    .join('; ');
  res.setHeader('set-cookie', cookie);
  return id;
}

function activeSession(req) {
  const id = parseCookies(req.headers.cookie).rg_session;
  if (!id) return null;
  const expiresAt = sessions.get(id);
  if (!expiresAt) return null;
  if (Date.now() > expiresAt) {
    sessions.delete(id);
    return null;
  }
  return id;
}

/**
 * 返回 { ok, via }。非 deploy-safe 模式下一律放行（保持本地开发零摩擦）。
 * 三种凭证：Authorization: Bearer <token> / x-app-token / 登录后拿到的会话 Cookie。
 */
function requestAuth(req) {
  if (!DEPLOY_SAFE) return { ok: true, via: 'disabled' };
  const bearer = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
  const headerToken = String(req.headers['x-app-token'] || '').trim();
  if (APP_TOKEN && (safeEqual(bearer, APP_TOKEN) || safeEqual(headerToken, APP_TOKEN))) {
    return { ok: true, via: 'token' };
  }
  if (activeSession(req)) return { ok: true, via: 'session' };
  return { ok: false, via: null };
}

const sessionGc = setInterval(() => {
  const now = Date.now();
  for (const [id, expiresAt] of sessions) if (now > expiresAt) sessions.delete(id);
}, 10 * 60_000);
sessionGc.unref?.();

/* ---------------- 全局配额 ---------------- */

const runTimestamps = [];

function globalQuotaExceeded() {
  if (GLOBAL_RUNS_PER_HOUR <= 0) return false;
  const cutoff = Date.now() - 3_600_000;
  while (runTimestamps.length && runTimestamps[0] < cutoff) runTimestamps.shift();
  return runTimestamps.length >= GLOBAL_RUNS_PER_HOUR;
}

function countRunning() {
  let n = 0;
  for (const run of runs.values()) if (run.status === 'running') n += 1;
  return n;
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.json': 'application/json; charset=utf-8'
};

async function serveStatic(res, urlPath) {
  const rel = urlPath === '/' ? 'index.html' : urlPath.replace(/^\/+/, '');
  const target = path.join(PUBLIC_DIR, rel);
  if (!target.startsWith(PUBLIC_DIR)) {
    sendText(res, 403, 'Forbidden');
    return;
  }
  try {
    const data = await readFile(target);
    res.writeHead(200, {
      'content-type': MIME[path.extname(target).toLowerCase()] || 'application/octet-stream',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer'
    });
    res.end(data);
  } catch {
    sendText(res, 404, 'Not Found');
  }
}

function clientIp(req) {
  if (TRUST_PROXY) {
    const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (forwarded) return forwarded;
  }
  return req.socket.remoteAddress || 'unknown';
}

function rateLimited(ip) {
  const now = Date.now();
  const windowMs = 10 * 60_000;
  const limit = 40;
  return bumpBucket(rateBuckets, ip, limit, windowMs, now);
}

/** 登录接口单独限流，防止暴力猜令牌 */
function loginRateLimited(ip) {
  const now = Date.now();
  return bumpBucket(loginBuckets, ip, 10, 10 * 60_000, now);
}

function bumpBucket(store, key, limit, windowMs, now = Date.now()) {
  const bucket = store.get(key) ?? { count: 0, resetAt: now + windowMs };
  if (now > bucket.resetAt) {
    bucket.count = 0;
    bucket.resetAt = now + windowMs;
  }
  bucket.count += 1;
  store.set(key, bucket);
  return bucket.count > limit;
}

/* ------------------------------------------------------------------ */
/* 路由                                                               */
/* ------------------------------------------------------------------ */

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = decodeURIComponent(url.pathname);

  try {
    // —— 鉴权闸门：deploy-safe 下 /api/* 需要令牌（/api/health 与 /api/session 例外）——
    if (DEPLOY_SAFE && pathname.startsWith('/api/') && pathname !== '/api/health' && pathname !== '/api/session') {
      const auth = requestAuth(req);
      if (!auth.ok) {
        sendJson(res, 401, {
          code: 'UNAUTHORIZED',
          error: '需要访问令牌：页面右上角填入 APP_TOKEN，或用 Authorization: Bearer / x-app-token 头访问。'
        });
        return;
      }
    }

    if (req.method === 'GET' && pathname === '/api/health') {
      sendJson(res, 200, {
        ok: true,
        probes: PROBES.length,
        concurrency: PROBE_CONCURRENCY,
        activeRuns: runs.size,
        defaultTokenBudget: DEFAULT_TOKEN_BUDGET,
        runDeadlineMs: RUN_DEADLINE_MS,
        deploySafe: DEPLOY_SAFE,
        authRequired: DEPLOY_SAFE,
        allowPrivateTargets: ALLOW_PRIVATE_TARGETS,
        maxConcurrentRuns: MAX_CONCURRENT_RUNS,
        estimate: ESTIMATE_PAYLOAD
      });
      return;
    }

    if (pathname === '/api/session' && req.method === 'POST') {
      if (!DEPLOY_SAFE) {
        sendJson(res, 200, { ok: true, authRequired: false });
        return;
      }
      if (loginRateLimited(clientIp(req))) {
        sendJson(res, 429, { error: '登录尝试过于频繁，请稍后再试' });
        return;
      }
      let body;
      try {
        body = JSON.parse((await readBody(req)) || '{}');
      } catch {
        sendJson(res, 400, { error: '请求体必须是合法 JSON' });
        return;
      }
      if (!safeEqual(String(body.token || '').trim(), APP_TOKEN)) {
        safeLog(`登录失败（来源 ${clientIp(req)}）`);
        sendJson(res, 401, { code: 'BAD_TOKEN', error: '访问令牌不正确' });
        return;
      }
      issueSession(req, res);
      safeLog(`登录成功（来源 ${clientIp(req)}）`);
      sendJson(res, 200, { ok: true, authRequired: true, expiresInMs: SESSION_TTL_MS });
      return;
    }

    if (pathname === '/api/session' && req.method === 'DELETE') {
      const id = activeSession(req);
      if (id) sessions.delete(id);
      res.setHeader('set-cookie', 'rg_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
      sendJson(res, 200, { ok: true });
      return;
    }

    if (req.method === 'GET' && pathname === '/api/catalog') {
      sendJson(res, 200, {
        probes: probeCatalog(),
        concurrency: PROBE_CONCURRENCY,
        probeTimeoutMs: PROBE_TIMEOUT_MS,
        runTtlMs: RUN_TTL_MS,
        contextChars: LONG_CONTEXT_CHARS,
        defaultTokenBudget: DEFAULT_TOKEN_BUDGET,
        minTokenBudget: MIN_TOKEN_BUDGET,
        maxTokenBudget: MAX_TOKEN_BUDGET,
        runDeadlineMs: RUN_DEADLINE_MS,
        deploySafe: DEPLOY_SAFE,
        authRequired: DEPLOY_SAFE,
        allowPrivateTargets: ALLOW_PRIVATE_TARGETS,
        maxConcurrentRuns: MAX_CONCURRENT_RUNS,
        globalRunsPerHour: GLOBAL_RUNS_PER_HOUR,
        maxRedirects: MAX_REDIRECTS,
        estimate: ESTIMATE_PAYLOAD
      });
      return;
    }

    if (req.method === 'POST' && pathname === '/api/detect') {
      if (rateLimited(clientIp(req))) {
        sendJson(res, 429, { error: '请求过于频繁，请稍后再试' });
        return;
      }
      let body;
      try {
        body = JSON.parse((await readBody(req)) || '{}');
      } catch {
        sendJson(res, 400, { error: '请求体必须是合法 JSON' });
        return;
      }

      const baseUrlInput = String(body.baseUrl || '').trim();
      const apiKey = String(body.apiKey || '').trim();
      const model = String(body.model || '').trim();
      const requestedBudget = Number(body.tokenBudget);
      const tokenBudget = Number.isFinite(requestedBudget) && requestedBudget > 0
        ? Math.max(MIN_TOKEN_BUDGET, Math.min(MAX_TOKEN_BUDGET, Math.round(requestedBudget)))
        : DEFAULT_TOKEN_BUDGET;
      const allowPartialRun = body.allowPartialRun === true;

      const problems = [];
      if (!baseUrlInput) problems.push('base_url 不能为空');
      if (!apiKey) problems.push('api_key 不能为空');
      if (!model) problems.push('模型名不能为空');
      let normalized;
      try {
        normalized = normalizeBaseUrl(baseUrlInput);
        const parsed = new URL(normalized);
        if (!['http:', 'https:'].includes(parsed.protocol)) problems.push('base_url 仅支持 http/https');
      } catch (error) {
        problems.push(`base_url 无效：${error.message}`);
      }
      if (problems.length) {
        sendJson(res, 400, { error: problems.join('；') });
        return;
      }

      // —— deploy-safe：出站目标策略（阻断 SSRF）——
      try {
        await assertTargetAllowed(normalized, { allowPrivate: TARGET_POLICY.allowPrivate, label: 'base_url' });
      } catch (error) {
        if (error instanceof TargetBlockedError) {
          safeLog(`拒绝启动检测：目标被 deploy-safe 策略拦截 → ${error.message}`);
          sendJson(res, 400, { code: error.code, error: error.message, meta: error.meta });
          return;
        }
        sendJson(res, 400, { error: `base_url 无法解析：${error.message}` });
        return;
      }

      // —— deploy-safe：全局配额与并发上限（防止被当成免费算力 / SSRF 代理滥用）——
      if (globalQuotaExceeded()) {
        sendJson(res, 429, {
          code: 'GLOBAL_QUOTA',
          error: `全局配额已满：每小时最多 ${GLOBAL_RUNS_PER_HOUR} 次检测，请稍后再试。`
        });
        return;
      }
      const runningNow = countRunning();
      if (runningNow >= MAX_CONCURRENT_RUNS) {
        sendJson(res, 429, {
          code: 'TOO_MANY_RUNS',
          error: `已有 ${runningNow} 个检测在进行中（上限 ${MAX_CONCURRENT_RUNS}），请等其中一个结束后再试。`
        });
        return;
      }

      // —— 前置闸门：预估消耗超过设定上限时，从源头拒绝启动，一个请求都不发 ——
      if (!allowPartialRun && tokenBudget < PROJECTED_TOKENS) {
        const suggested = Math.min(MAX_TOKEN_BUDGET, Math.ceil(PROJECTED_TOKENS * 1.2));
        safeLog(
          `拒绝启动检测：预估 ${PROJECTED_TOKENS} token > 上限 ${tokenBudget}（未向 ${normalized} 发送任何请求）`
        );
        sendJson(res, 400, {
          code: 'BUDGET_TOO_SMALL',
          error:
            `预检拦截：整套 ${PROBES.length} 个探针预计消耗约 ${PROJECTED_TOKENS} token` +
            `（预期 ${SUITE_ESTIMATE.total}，最坏 ${WORST_CASE_TOKENS}），` +
            `高于你设置的 ${tokenBudget}，已拒绝启动，未向端点发送任何请求。`,
          tokenBudget,
          estimate: ESTIMATE_PAYLOAD,
          suggestions: [
            `把 Token 上限提高到 ${suggested} 以上再检测`,
            `调小 LONG_CONTEXT_CHARS（当前 ${LONG_CONTEXT_CHARS}）可显著降低上下文截断探针的消耗`,
            '或勾选「额度不足时仍运行」：检测会跑到触顶为止，结果会标注为不完整'
          ]
        });
        return;
      }

      evictOldestIfNeeded();
      runTimestamps.push(Date.now());
      const run = createRun({ baseUrl: normalized, apiKey, model, tokenBudget });
      run.budget = new TokenBudget({
        limit: tokenBudget,
        deadlineMs: RUN_DEADLINE_MS,
        onUpdate: (snapshot) => emitUsage(run, snapshot.exhausted)
      }).start();
      scheduleCleanup(run);
      safeLog(
        `新建检测 ${run.id.slice(0, 8)} → ${normalized} / ${model} / key指纹 ${run.target.keyFingerprint}` +
          ` / Token 上限 ${tokenBudget}（预估 ${PROJECTED_TOKENS}，${Math.round((PROJECTED_TOKENS / tokenBudget) * 100)}%）` +
          (allowPartialRun ? ' / 允许中途终止' : '')
      );
      // 立刻开始，后台并行跑探针
      executeRun(run).catch((error) => {
        safeLog('执行失败:', error?.message || error);
      });
      sendJson(res, 202, {
        runId: run.id,
        catalog: probeCatalog(),
        tokenBudget,
        runDeadlineMs: RUN_DEADLINE_MS,
        estimate: ESTIMATE_PAYLOAD,
        allowPartialRun,
        warning: allowPartialRun
          ? `已允许中途终止：若累计用量触顶，剩余探针会被跳过，结论不完整。`
          : PROJECTED_TOKENS >= tokenBudget * 0.7
            ? `预估消耗约占上限的 ${Math.round((PROJECTED_TOKENS / tokenBudget) * 100)}%，检测过程中可能提前触顶。`
            : null
      });
      return;
    }

    const detectMatch = pathname.match(/^\/api\/detect\/([0-9a-f-]{36})(\/events|\/report\.json|\/report\.html)?$/i);
    if (detectMatch) {
      const run = runs.get(detectMatch[1]);
      if (!run) {
        sendJson(res, 404, { error: '检测记录不存在或已过期（内存态记录默认保留 30 分钟）' });
        return;
      }
      const suffix = detectMatch[2];

      if (suffix === '/events' && req.method === 'GET') {
        res.writeHead(200, {
          'content-type': 'text/event-stream; charset=utf-8',
          'cache-control': 'no-cache, no-transform',
          connection: 'keep-alive',
          'x-accel-buffering': 'no'
        });
        const send = (event) => res.write(`data: ${JSON.stringify(redact(event))}\n\n`);
        send({ type: 'snapshot', run: publicRun(run), catalog: probeCatalog() });
        for (const event of run.eventLog) send(event);
        if (run.status !== 'running') {
          res.write('event: end\ndata: {}\n\n');
          res.end();
          return;
        }
        run.subscribers.add(send);
        const heartbeat = setInterval(() => res.write(': ping\n\n'), 15_000);
        heartbeat.unref?.();
        const cleanup = () => {
          clearInterval(heartbeat);
          run.subscribers.delete(send);
        };
        req.on('close', cleanup);
        req.on('error', cleanup);
        return;
      }

      if (suffix === '/report.json' && req.method === 'GET') {
        const report = JSON.stringify(redact(buildJsonReport(run)), null, 2);
        res.writeHead(200, {
          'content-type': 'application/json; charset=utf-8',
          'content-disposition': `attachment; filename="relay-report-${run.id.slice(0, 8)}.json"`,
          'cache-control': 'no-store'
        });
        res.end(report);
        return;
      }

      if (suffix === '/report.html' && req.method === 'GET') {
        const html = buildHtmlReport(run);
        const download = url.searchParams.get('download') === '1';
        res.writeHead(200, {
          'content-type': 'text/html; charset=utf-8',
          'cache-control': 'no-store',
          ...(download
            ? { 'content-disposition': `attachment; filename="relay-report-${run.id.slice(0, 8)}.html"` }
            : {})
        });
        res.end(html);
        return;
      }

      if (!suffix && req.method === 'GET') {
        sendJson(res, 200, publicRun(run));
        return;
      }
    }

    if (req.method === 'GET' || req.method === 'HEAD') {
      await serveStatic(res, pathname);
      return;
    }

    sendJson(res, 405, { error: '不支持的请求方法' });
  } catch (error) {
    safeLog('未捕获错误:', error?.stack || error);
    if (!res.headersSent) sendJson(res, 500, { error: '服务内部错误' });
    else res.end();
  }
});

server.listen(PORT, HOST, () => {
  safeLog(`中转 API 模型检测器已启动：http://${HOST}:${PORT}`);
  safeLog(`探针 ${PROBES.length} 个 / 并发 ${PROBE_CONCURRENCY} / 单探针超时 ${PROBE_TIMEOUT_MS}ms / 记录保留 ${Math.round(RUN_TTL_MS / 60000)} 分钟`);
  safeLog(
    `Token 预检：整套检测预估 ${PROJECTED_TOKENS} token（预期 ${SUITE_ESTIMATE.total} / 最坏 ${WORST_CASE_TOKENS}，${SUITE_ESTIMATE.calls} 次调用）` +
      `，默认上限 ${DEFAULT_TOKEN_BUDGET}；预估低于上限才会启动检测。`
  );
  for (const note of SUITE_ESTIMATE.notes) safeLog(`  · ${note}`);
  if (DEPLOY_SAFE) {
    safeLog(
      `部署安全模式已开启：需要访问令牌 / 私网目标${ALLOW_PRIVATE_TARGETS ? '已显式放行（SSRF 防护关闭）' : '已拦截'} / ` +
        `并发上限 ${MAX_CONCURRENT_RUNS} / 全局 ${GLOBAL_RUNS_PER_HOUR > 0 ? `${GLOBAL_RUNS_PER_HOUR} 次每小时` : '不限'} / ` +
        `重定向逐跳校验（最多 ${MAX_REDIRECTS} 跳）`
    );
    if (!/^(127\.0\.0\.1|::1|localhost)$/.test(HOST)) {
      safeLog(`⚠️  监听地址为 ${HOST}，已带令牌鉴权；仍建议只把反向代理暴露到公网，并开启 HTTPS。`);
    }
  } else {
    safeLog('当前为本地模式（无鉴权、允许私网目标）。若要放到服务器上，请用 DEPLOY_SAFE=1 + APP_TOKEN 启动。');
  }
  safeLog('运行记录仅存于内存，API Key 在探针结束后立即擦除，不写磁盘。');
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => {
    safeLog(`收到 ${signal}，清空内存中的运行记录并退出。`);
    for (const run of runs.values()) run.apiKey = null;
    runs.clear();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 1500).unref?.();
  });
}
