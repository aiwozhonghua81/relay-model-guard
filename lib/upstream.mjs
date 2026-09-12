/**
 * 上游（中转）端点调用层。
 * 只负责：拼 URL、发请求、计时、把响应原文抓回来（交给探针判定）。
 * 不在任何地方持久化 apiKey。
 */

import { redact } from './redact.mjs';
import { estimatePayloadTokens, estimateReservation, isAbortError } from './budget.mjs';
import { assertTargetAllowed } from './target-policy.mjs';

const DEFAULT_TIMEOUT = 45_000;

/** 归一化 base_url：用户可能填 https://x/v1、https://x/v1/、https://x/v1/chat/completions */
export function normalizeBaseUrl(raw) {
  let url = String(raw || '').trim();
  if (!url) throw new Error('base_url 不能为空');
  if (!/^https?:\/\//i.test(url)) url = `https://${url}`;
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error('base_url 不是合法 URL');
  }
  let pathname = parsed.pathname.replace(/\/+$/, '');
  pathname = pathname.replace(/\/chat\/completions$/i, '');
  pathname = pathname.replace(/\/completions$/i, '');
  pathname = pathname.replace(/\/models$/i, '');
  if (pathname === '/') pathname = '';
  parsed.pathname = pathname;
  parsed.search = '';
  parsed.hash = '';
  return parsed.toString().replace(/\/+$/, '');
}

function joinUrl(base, suffix) {
  return `${base}${suffix.startsWith('/') ? suffix : `/${suffix}`}`;
}

const RETRYABLE_STATUS = new Set([429, 500, 502, 503, 504]);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export class Upstream {
  constructor({ baseUrl, apiKey, model, budget = null, targetPolicy = null }) {
    this.baseUrl = normalizeBaseUrl(baseUrl);
    this.apiKey = apiKey;
    this.model = model;
    /** @type {import('./budget.mjs').TokenBudget | null} */
    this.budget = budget;
    /** deploy-safe 目标策略：allowPrivate=false 时逐个校验目标 IP，并逐跳校验重定向 */
    this.targetPolicy = targetPolicy ?? { allowPrivate: true, maxRedirects: 3 };
  }

  /**
   * 统一的出站请求入口：先过目标策略（阻断 SSRF），再决定是否手动跟随重定向。
   * allowPrivate 为 true 时行为与改造前完全一致（redirect: follow，不做 DNS 查询）。
   */
  async #fetchWithPolicy(url, { method, headers, body, signal }) {
    const allowPrivate = this.targetPolicy?.allowPrivate !== false;
    const maxRedirects = Number.isFinite(this.targetPolicy?.maxRedirects) ? this.targetPolicy.maxRedirects : 3;
    const redirectChain = [];

    if (allowPrivate) {
      const res = await fetch(url, { method, headers, body, signal, redirect: 'follow' });
      return { res, finalUrl: url, redirectChain };
    }

    // deploy-safe：手动逐跳跟随，每一跳都重新做目标校验，防止「先跳到自己域名再 302 进内网」
    await assertTargetAllowed(url, { allowPrivate: false, label: '目标地址' });
    let currentUrl = url;
    let res;
    for (let hop = 0; ; hop += 1) {
      res = await fetch(currentUrl, { method, headers, body, signal, redirect: 'manual' });
      const location = [301, 302, 303, 307, 308].includes(res.status) ? res.headers.get('location') : null;
      if (!location) break;
      if (hop >= maxRedirects) throw new Error(`重定向次数超过上限（${maxRedirects}），已停止跟随`);
      let nextUrl;
      try {
        nextUrl = new URL(location, currentUrl).toString();
      } catch {
        throw new Error(`上游返回了非法重定向地址：${String(location).slice(0, 120)}`);
      }
      await assertTargetAllowed(nextUrl, { allowPrivate: false, label: `重定向第 ${hop + 1} 跳` });
      redirectChain.push(redact(nextUrl));
      currentUrl = nextUrl;
    }
    return { res, finalUrl: currentUrl, redirectChain };
  }

  headers(extra = {}) {
    return {
      'content-type': 'application/json',
      accept: 'application/json',
      authorization: `Bearer ${this.apiKey}`,
      'user-agent': 'RelayModelGuard/1.0',
      ...extra
    };
  }

  /**
   * 非流式调用。
   * 网络/超时/HTTP 错误都作为结果返回，方便探针统一打分；
   * 唯一会抛出的异常是 TokenBudget / 总时长触发的终止（调用方据此标记「已终止」）。
   * 对 429/5xx 做有限重试，避免中转限流把探针误判为不可用。
   */
  async request(pathOrSuffix, { method = 'POST', body, timeoutMs = DEFAULT_TIMEOUT, headers, retries = 2 } = {}) {
    const url = pathOrSuffix.startsWith('/') ? joinUrl(this.baseUrl, pathOrSuffix) : pathOrSuffix;
    const startedAt = Date.now();
    let result;
    for (let attempt = 0; attempt <= retries; attempt += 1) {
      // 每次尝试（含重试）都要重新申请额度：额度不足时连请求都不会发出
      const reservation = this.#reserve(body ?? url, body?.max_tokens);
      try {
        result = await this.#once(url, { method, body, timeoutMs, headers });
      } catch (error) {
        this.#settle(reservation, reservation); // 被中断：按预留量保守记账
        throw error;
      }
      this.#settle(reservation, this.#actualFor(result, body, reservation));
      if (!RETRYABLE_STATUS.has(result.status) || attempt === retries) break;
      const waitMs = (result.headers['retry-after'] ? 1500 : 800) * (attempt + 1);
      await sleep(Math.min(waitMs, 4000));
    }
    result.elapsedMs = Date.now() - startedAt;
    return result;
  }

  async #once(url, { method, body, timeoutMs, headers }) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error('timeout')), timeoutMs);
    const result = {
      url: redact(url),
      method,
      requestBody: body === undefined ? null : redact(body),
      status: 0,
      ok: false,
      headers: {},
      text: '',
      json: null,
      jsonParsed: false,
      elapsedMs: 0,
      error: null,
      timedOut: false,
      redirectChain: []
    };
    const t0 = Date.now();
    try {
      const { res, redirectChain } = await this.#fetchWithPolicy(url, {
        method,
        headers: this.headers(headers),
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: this.#signal(controller.signal)
      });
      if (redirectChain.length) result.redirectChain = redirectChain;
      result.status = res.status;
      result.ok = res.ok;
      result.headers = pickHeaders(res.headers);
      result.text = clamp(await res.text(), 120_000);
      try {
        result.json = JSON.parse(result.text);
        result.jsonParsed = true;
      } catch {
        result.json = null;
      }
    } catch (error) {
      this.#rethrowIfAborted(error);
      result.error = redact(error?.message || String(error));
      result.timedOut = controller.signal.aborted;
    } finally {
      clearTimeout(timer);
      result.elapsedMs = Date.now() - t0;
    }
    return result;
  }

  /** 便捷封装：chat/completions 非流式 */
  async chat(body, options = {}) {
    return this.request('/chat/completions', {
      method: 'POST',
      body: { model: this.model, ...body },
      ...options
    });
  }

  /** GET /models */
  async listModels(options = {}) {
    return this.request('/models', { method: 'GET', retries: 1, ...options });
  }

  /**
   * 流式调用：抓 SSE 原始行、首字延迟、分块结构，用于「流完整性」与「延迟信号」。
   */
  async streamChat(body, { timeoutMs = DEFAULT_TIMEOUT, rawLimit = 400 } = {}) {
    const url = joinUrl(this.baseUrl, '/chat/completions');
    const startedAt = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error('timeout')), timeoutMs);
    const fullBody = { model: this.model, stream: true, ...body };
    const reservation = this.#reserve(fullBody, fullBody.max_tokens);
    const out = {
      url: redact(url),
      requestBody: redact(fullBody),
      status: 0,
      ok: false,
      headers: {},
      contentType: '',
      ttftMs: null,
      totalMs: 0,
      chunkCount: 0,
      reasoningChunkCount: 0,
      contentChunks: [],
      finishReasons: [],
      sawDone: false,
      roleSeen: false,
      usage: null,
      rawLines: [],
      rawLineCount: 0,
      error: null,
      timedOut: false,
      redirectChain: [],
      malformedLines: 0,
      nonDataLines: 0
    };
    let settled = false;
    const settleOnce = () => {
      if (settled) return;
      settled = true;
      this.#settle(reservation, this.#actualFor(out, fullBody, reservation));
    };
    try {
      const { res, redirectChain } = await this.#fetchWithPolicy(url, {
        method: 'POST',
        headers: this.headers({ accept: 'text/event-stream' }),
        body: JSON.stringify(fullBody),
        signal: this.#signal(controller.signal)
      });
      out.redirectChain = redirectChain;
      out.status = res.status;
      out.ok = res.ok;
      out.headers = pickHeaders(res.headers);
      out.contentType = res.headers.get('content-type') || '';

      if (!res.ok || !res.body) {
        out.error = clamp(await res.text().catch(() => ''), 4000) || `HTTP ${res.status}`;
        return out;
      }

      const decoder = new TextDecoder();
      let buffer = '';
      for await (const chunk of res.body) {
        if (out.ttftMs === null) out.ttftMs = Date.now() - startedAt;
        buffer += decoder.decode(chunk, { stream: true });
        let idx;
        while ((idx = buffer.indexOf('\n')) >= 0) {
          const line = buffer.slice(0, idx).replace(/\r$/, '');
          buffer = buffer.slice(idx + 1);
          handleLine(line);
        }
      }
      buffer += decoder.decode();
      if (buffer.trim()) handleLine(buffer.trim());
    } catch (error) {
      this.#rethrowIfAborted(error);
      out.error = redact(error?.message || String(error));
      out.timedOut = controller.signal.aborted;
    } finally {
      clearTimeout(timer);
      out.totalMs = Date.now() - startedAt;
      if (out.ttftMs === null && out.error) out.ttftMs = null;
      // 单点结算：正常结束、提前 return、被中断都在这里记账，绝不重复
      settleOnce();
    }
    return out;

    function handleLine(line) {
      out.rawLineCount += 1;
      if (out.rawLines.length < rawLimit) out.rawLines.push(clamp(line, 2000));
      if (!line.trim()) return;
      if (!line.startsWith('data:')) {
        out.nonDataLines += 1;
        return;
      }
      const payload = line.slice(5).trim();
      if (payload === '[DONE]') {
        out.sawDone = true;
        return;
      }
      let parsed;
      try {
        parsed = JSON.parse(payload);
      } catch {
        out.malformedLines += 1;
        return;
      }
      out.chunkCount += 1;
      if (parsed?.usage) out.usage = parsed.usage;
      const choice = parsed?.choices?.[0];
      if (!choice) return;
      if (choice.delta?.role) out.roleSeen = true;
      if (choice.finish_reason) out.finishReasons.push(choice.finish_reason);
      const text = choice.delta?.content;
      if (typeof text === 'string' && text.length > 0) out.contentChunks.push(text);
      if (typeof choice.delta?.reasoning_content === 'string') out.reasoningChunkCount += 1;
    }
  }

  /* ---------------- 内部：预算闸门 ---------------- */

  #reserve(payload, maxTokens) {
    if (!this.budget) return 0;
    return this.budget.reserve(estimateReservation(payload, maxTokens));
  }

  #settle(reservation, actual) {
    if (!this.budget || !reservation) return;
    this.budget.reconcile(reservation, actual);
  }

  /**
   * 本次请求实际计入多少 token：
   *  有 usage → 真实值；4xx/5xx → 视为未计费；网络中断/超时 → 按预留量保守计费；其余 → 估算。
   */
  #actualFor(result, requestBody, reservation) {
    const usage = tokensFromUsage(result?.json?.usage) ?? tokensFromUsage(result?.usage);
    if (usage !== null && usage !== undefined) return usage;
    const status = result?.status ?? 0;
    if (status >= 400) return 0;
    if (status === 0) return reservation;
    const responseText =
      typeof result?.text === 'string' && result.text
        ? result.text
        : Array.isArray(result?.contentChunks)
          ? result.contentChunks.join('')
          : '';
    return estimatePayloadTokens(requestBody ?? '') + estimatePayloadTokens(responseText);
  }

  /** 把超时信号与预算信号合成一个，任一触发都会中断在途请求 */
  #signal(timeoutSignal) {
    const budgetSignal = this.budget?.signal;
    if (!budgetSignal) return timeoutSignal;
    if (typeof AbortSignal.any === 'function') return AbortSignal.any([timeoutSignal, budgetSignal]);
    // 兼容老版本 Node
    const controller = new AbortController();
    const forward = (from) => {
      if (!controller.signal.aborted) controller.abort(from.reason);
    };
    timeoutSignal.addEventListener('abort', () => forward(timeoutSignal), { once: true });
    budgetSignal.addEventListener('abort', () => forward(budgetSignal), { once: true });
    return controller.signal;
  }

  /** 预算/超时导致的失败必须往上抛，不能被当成「端点网络错误」记 0 分 */
  #rethrowIfAborted(error) {
    const reason = this.budget?.signal.aborted ? this.budget.signal.reason : null;
    if (isAbortError(reason)) throw reason;
    if (isAbortError(error)) throw error;
    if (isAbortError(error?.cause)) throw error.cause;
  }
}

/** 直接从 usage 取实际消耗；字段缺失返回 null（由上层退化为估算） */
export function tokensFromUsage(usage) {
  if (!usage || typeof usage !== 'object') return null;
  const prompt = usage.prompt_tokens ?? usage.input_tokens;
  const completion = usage.completion_tokens ?? usage.output_tokens;
  const total = usage.total_tokens;
  if (Number.isFinite(prompt) || Number.isFinite(completion)) {
    return (Number(prompt) || 0) + (Number(completion) || 0);
  }
  return Number.isFinite(total) ? Number(total) : null;
}

const INTERESTING_HEADERS = [
  'server',
  'date',
  'content-type',
  'x-request-id',
  'request-id',
  'x-trace-id',
  'traceparent',
  'openai-organization',
  'openai-processing-ms',
  'openai-version',
  'openai-model',
  'x-ratelimit-limit-requests',
  'x-ratelimit-remaining-requests',
  'x-ratelimit-limit-tokens',
  'x-ratelimit-remaining-tokens',
  'retry-after',
  'cf-ray',
  'cf-cache-status',
  'via',
  'x-envoy-upstream-service-time',
  'apim-request-id',
  'x-ms-request-id',
  'x-ms-region',
  'azureml-model-session',
  'x-azure-ref',
  'x-tt-logid',
  'x-new-api-request-id',
  'x-oneapi-request-id',
  'x-served-by',
  'x-upstream-host',
  'x-backend-server',
  'x-cache',
  'x-powered-by',
  'x-llm-provider',
  'content-encoding'
];

export function pickHeaders(headersLike) {
  const out = {};
  for (const name of INTERESTING_HEADERS) {
    const value = headersLike.get?.(name);
    if (value) out[name] = clamp(value, 300);
  }
  return out;
}

export function clamp(text, limit) {
  const str = typeof text === 'string' ? text : String(text ?? '');
  if (str.length <= limit) return str;
  return `${str.slice(0, limit)}…[truncated ${str.length - limit} chars]`;
}

/** 从 chat 响应里取出助手正文（兼容多种形态） */
export function extractContent(result) {
  const choice = result?.json?.choices?.[0];
  if (!choice) return { content: '', finishReason: null };
  const msg = choice.message || choice.delta || {};
  let content = msg.content;
  if (Array.isArray(content)) {
    content = content.map((p) => (typeof p === 'string' ? p : p?.text || '')).join('');
  }
  if (typeof content !== 'string') content = '';
  if (!content && typeof msg.reasoning_content === 'string') content = msg.reasoning_content;
  return { content, finishReason: choice.finish_reason ?? null };
}

/** 粗略 token 估算：中英混排按字符量折算，仅用于「账目是否离谱」的粗判 */
export function estimateTokens(text) {
  const str = typeof text === 'string' ? text : '';
  let cjk = 0;
  let other = 0;
  for (const ch of str) {
    if (/[\u3000-\u9fff\uff00-\uffef]/.test(ch)) cjk += 1;
    else other += 1;
  }
  // CJK 在不同分词器下约 0.6~1 token/字，取 0.8 作为中间值，仅用于量级粗判
  return Math.ceil(cjk * 0.8 + other / 3.6) + 4;
}
