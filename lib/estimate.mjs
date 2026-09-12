/**
 * 前置预估：不联网，用「干跑」的方式完整走一遍 14 个探针，记录每条将要发出的请求
 * （prompt 估算 + max_tokens 上限），汇总成整套检测的 token 预估。
 *
 * 为什么用干跑而不是手写常量表：探针里的提示词与分支（/models 失败时的补 ping、
 * stream_options 不被支持时的重试、tool_choice 强制重试等）都会随代码变化，
 * 干跑天然与实现保持一致，不需要维护第二份数据。
 *
 * 为了不低估，每个探针对「全部成功」和「全部失败」两种响应剧本各跑一次，取较大值。
 */

import { estimateTokens } from './upstream.mjs';
import { createProbeContext } from './ctx.mjs';
import { PROBES } from './probes/index.mjs';

const DEFAULT_COMPLETION_CAP = 512;
/** 预期输出长度：探针给的 max_tokens 是上限，真实回答通常远短于它 */
const EXPECTED_COMPLETION_RATIO = 0.35;
const EXPECTED_COMPLETION_MIN = 16;
const EXPECTED_COMPLETION_MAX = 160;

function expectedCompletionFor(cap) {
  const value = Number.isFinite(cap) && cap > 0 ? cap : DEFAULT_COMPLETION_CAP;
  const scaled = Math.max(EXPECTED_COMPLETION_MIN, Math.min(EXPECTED_COMPLETION_MAX, Math.round(value * EXPECTED_COMPLETION_RATIO)));
  // 预期输出不可能超过该请求自己的 max_tokens 上限
  return Math.min(value, scaled);
}

function costOf(body) {
  const messages = Array.isArray(body?.messages) ? body.messages : [];
  if (!messages.length) return { prompt: 0, completion: 0, total: 0 };
  const prompt = messages.reduce((acc, m) => {
    const content = typeof m?.content === 'string' ? m.content : JSON.stringify(m?.content ?? '');
    return acc + estimateTokens(content);
  }, 8);
  const completion = Number.isFinite(body?.max_tokens) && body.max_tokens > 0 ? body.max_tokens : DEFAULT_COMPLETION_CAP;
  return { prompt, completion, total: prompt + completion };
}

class PlanningUpstream {
  constructor({ model, mode }) {
    this.model = model;
    this.mode = mode;
    this.baseUrl = 'https://estimate.invalid/v1';
    this.apiKey = 'plan';
    this.calls = [];
  }

  async request(pathOrSuffix, { method = 'POST', body } = {}) {
    this.record(method === 'GET' ? 'models' : 'request', pathOrSuffix, body);
    if (this.mode === 'failure') return failureResponse(pathOrSuffix, method, body);
    if (String(pathOrSuffix).includes('/models')) return this.modelsResponse();
    return this.chatResponse(body);
  }

  async chat(body) {
    this.record('chat', '/chat/completions', body);
    return this.mode === 'failure' ? failureResponse('/chat/completions', 'POST', body) : this.chatResponse(body);
  }

  async listModels() {
    this.record('models', '/models', null);
    return this.mode === 'failure' ? failureResponse('/models', 'GET', null) : this.modelsResponse();
  }

  async streamChat(body) {
    this.record('stream', '/chat/completions', body);
    if (this.mode === 'failure') {
      return {
        url: 'https://estimate.invalid/v1/chat/completions',
        requestBody: body,
        status: 500,
        ok: false,
        headers: {},
        contentType: 'application/json',
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
        malformedLines: 0,
        nonDataLines: 0,
        error: 'planned failure',
        timedOut: false
      };
    }
    const cost = costOf(body);
    return {
      url: 'https://estimate.invalid/v1/chat/completions',
      requestBody: body,
      status: 200,
      ok: true,
      headers: {},
      contentType: 'text/event-stream',
      ttftMs: 320,
      totalMs: 1500,
      chunkCount: 48,
      reasoningChunkCount: 0,
      contentChunks: ['', ''],
      finishReasons: ['stop'],
      sawDone: true,
      roleSeen: true,
      usage: { prompt_tokens: cost.prompt, completion_tokens: Math.min(16, cost.completion) },
      rawLines: [],
      rawLineCount: 50,
      malformedLines: 0,
      nonDataLines: 0,
      error: null,
      timedOut: false
    };
  }

  record(kind, path, body) {
    const cost = costOf(body);
    // 没有计费载荷的调用（如 GET /models）按 0 计，不套用默认输出长度
    const expectedCompletion = cost.total > 0 ? expectedCompletionFor(cost.completion) : 0;
    this.calls.push({
      kind,
      path: String(path),
      promptTokens: cost.prompt,
      completionCap: cost.completion,
      expectedCompletion,
      // 预期消耗：prompt 估算 + 典型输出长度
      expected: cost.prompt + expectedCompletion,
      // 最坏情况：prompt 估算 + max_tokens 全用满
      worst: cost.total
    });
  }

  modelsResponse() {
    return {
      url: 'https://estimate.invalid/v1/models',
      method: 'GET',
      requestBody: null,
      status: 200,
      ok: true,
      headers: {},
      text: '',
      json: { object: 'list', data: [{ id: this.model }] },
      jsonParsed: true,
      elapsedMs: 0,
      error: null,
      timedOut: false
    };
  }

  chatResponse(body) {
    const cost = costOf(body);
    const usage = { prompt_tokens: cost.prompt, completion_tokens: Math.min(16, cost.completion) };
    usage.total_tokens = usage.prompt_tokens + usage.completion_tokens;
    return {
      url: 'https://estimate.invalid/v1/chat/completions',
      method: 'POST',
      requestBody: body,
      status: 200,
      ok: true,
      headers: {},
      text: '',
      json: {
        id: 'plan',
        object: 'chat.completion',
        model: this.model,
        choices: [{ index: 0, message: { role: 'assistant', content: '' }, finish_reason: 'stop' }],
        usage
      },
      jsonParsed: true,
      elapsedMs: 0,
      error: null,
      timedOut: false
    };
  }
}

function failureResponse(pathOrSuffix, method, body) {
  return {
    url: `https://estimate.invalid${pathOrSuffix}`,
    method,
    requestBody: body ?? null,
    status: 500,
    ok: false,
    headers: {},
    text: '{"error":{"message":"planned failure"}}',
    json: { error: { message: 'planned failure', type: 'server_error' } },
    jsonParsed: true,
    elapsedMs: 0,
    error: 'planned failure',
    timedOut: false
  };
}

/**
 * 干跑整套探针，得到 token 预估（不产生任何网络请求）。
 * @returns {Promise<{total:number, promptTokens:number, completionTokens:number, calls:number, perProbe:Array, notes:string[]}>}
 */
export async function computeSuiteEstimate({ model = 'estimate-model', contextChars = 32_000 } = {}) {
  const perProbeMap = new Map();

  for (const mode of ['success', 'failure']) {
    for (const probe of PROBES) {
      const planner = new PlanningUpstream({ model, mode });
      const ctx = createProbeContext({
        upstream: planner,
        model,
        baseUrl: planner.baseUrl,
        options: { contextChars },
        log: () => {},
        probeId: probe.id
      });
      try {
        await probe.run(ctx);
      } catch {
        // 干跑只关心「发出了哪些请求」，探针内部的判定逻辑是否走得通不影响预估
      }
      const expected = planner.calls.reduce((acc, c) => acc + c.expected, 0);
      const worst = planner.calls.reduce((acc, c) => acc + c.worst, 0);
      const prompt = planner.calls.reduce((acc, c) => acc + c.promptTokens, 0);
      const current = perProbeMap.get(probe.id) || {
        id: probe.id,
        name: probe.name,
        expected: 0,
        worst: 0,
        promptTokens: 0,
        calls: 0
      };
      // 取两种剧本里更保守的一次
      if (worst > current.worst) {
        current.expected = expected;
        current.worst = worst;
        current.promptTokens = prompt;
        current.calls = planner.calls.length;
      }
      perProbeMap.set(probe.id, current);
    }
  }

  const perProbe = [...perProbeMap.values()]
    .map((p) => ({
      id: p.id,
      name: p.name,
      calls: p.calls,
      promptTokens: p.promptTokens,
      expectedTokens: p.expected,
      completionTokens: Math.max(0, p.expected - p.promptTokens),
      worstTokens: p.worst
    }))
    .sort((a, b) => b.expectedTokens - a.expectedTokens);

  const total = perProbe.reduce((acc, p) => acc + p.expectedTokens, 0);
  const worstTotal = perProbe.reduce((acc, p) => acc + p.worstTokens, 0);
  const promptTokens = perProbe.reduce((acc, p) => acc + p.promptTokens, 0);
  const completionTokens = Math.max(0, total - promptTokens);
  const calls = perProbe.reduce((acc, p) => acc + p.calls, 0);
  const dominant = perProbe[0];

  const notes = [];
  if (dominant && total > 0 && dominant.expectedTokens / total > 0.5) {
    notes.push(
      `预估消耗主要来自「${dominant.name}」探针（约占 ${Math.round((dominant.expectedTokens / total) * 100)}%），调小 LONG_CONTEXT_CHARS 可显著降低`
    );
  }

  return {
    // 预期消耗：用于「前置告警 / 是否拒绝启动」
    total,
    promptTokens,
    completionTokens,
    // 最坏情况：每个请求都把 max_tokens 用满
    worstTotal,
    calls,
    perProbe,
    notes
  };
}
