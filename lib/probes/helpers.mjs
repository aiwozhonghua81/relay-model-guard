/**
 * 探针共享工具：模型家族识别、计分、证据裁剪。
 */

export const STATUS_PASS = 'pass';
export const STATUS_WARN = 'warn';
export const STATUS_FAIL = 'fail';

export const clamp = (n, lo = 0, hi = 10) => Math.max(lo, Math.min(hi, n));
export const round1 = (n) => Math.round(n * 10) / 10;

/** 分数 → 状态（探针也可自己指定 status 覆盖） */
export function statusFor(score) {
  if (score >= 7.5) return STATUS_PASS;
  if (score >= 4) return STATUS_WARN;
  return STATUS_FAIL;
}

/** 统一结果封装 */
export function result({ score, evidence, raw = null, status, notes = [] }) {
  const s = clamp(round1(score));
  return {
    score: s,
    status: status || statusFor(s),
    evidence: String(evidence || '').slice(0, 600),
    notes: notes.slice(0, 6),
    raw
  };
}

export const FAMILIES = [
  { key: 'openai', label: 'OpenAI', re: [/gpt-?[0-9o]/i, /\bo[134]{1}(-|$|\b)/i, /\bchatgpt\b/i, /\bdavinci\b/i, /\btext-embedding/i, /\bgpt\b/i] },
  { key: 'anthropic', label: 'Anthropic', re: [/claude/i, /anthropic/i, /sonnet|opus|haiku/i] },
  { key: 'google', label: 'Google', re: [/gemini/i, /\bgoogle\b/i, /\bpalm\b/i, /\bbard\b/i] },
  { key: 'deepseek', label: 'DeepSeek', re: [/deepseek/i, /深度求索/i] },
  { key: 'qwen', label: '阿里通义', re: [/\bqwen/i, /tongyi/i, /通义/i, /dashscope/i] },
  { key: 'meta', label: 'Meta', re: [/llama/i, /\bmeta\b/i] },
  { key: 'mistral', label: 'Mistral', re: [/mistral|mixtral|codestral|ministral|pixtral/i] },
  { key: 'zhipu', label: '智谱', re: [/\bglm\b/i, /chatglm/i, /智谱/i, /zhipu/i] },
  { key: 'xai', label: 'xAI', re: [/\bgrok\b/i, /\bxai\b/i] },
  { key: 'moonshot', label: '月之暗面', re: [/kimi|moonshot|月之暗面/i] },
  { key: 'bytedance', label: '字节豆包', re: [/doubao|豆包|skylark|seed-?\d|volcengine|火山/i] },
  { key: 'baidu', label: '百度文心', re: [/ernie|wenxin|文心|百度/i] },
  { key: 'tencent', label: '腾讯混元', re: [/hunyuan|混元|tencent/i] },
  { key: 'iflytek', label: '讯飞星火', re: [/spark|星火|讯飞/i] },
  { key: 'minimax', label: 'MiniMax', re: [/minimax|abab/i] },
  { key: '01ai', label: '零一万物', re: [/\byi-(large|medium|lightning|vision)/i, /01\.ai|零一万物/i] },
  { key: 'microsoft', label: 'Microsoft', re: [/\bphi-\d/i, /azure/i, /microsoft/i] },
  { key: 'cohere', label: 'Cohere', re: [/command-[ar]|cohere/i] },
  { key: 'perplexity', label: 'Perplexity', re: [/pplx|sonar/i, /perplexity/i] },
  { key: 'nvidia', label: 'NVIDIA', re: [/nemotron|nvidia/i] },
  { key: 'openrouter', label: 'OpenRouter', re: [/openrouter/i] },
  { key: 'local', label: '本地/自部署', re: [/ollama|vllm|lmstudio|llama\.cpp|text-generation-webui|local/i] }
];

/** 从自由文本里识别「提到了哪些家族」 */
export function detectFamilies(text) {
  const str = String(text || '');
  const hits = new Set();
  for (const family of FAMILIES) {
    if (family.re.some((re) => re.test(str))) hits.add(family.key);
  }
  return hits;
}

/** 从模型名识别家族（只按名字，不猜） */
export function familyOfModel(modelName) {
  const name = String(modelName || '');
  // 排除掉「local」「openrouter」这类泛化标签，避免误判
  for (const family of FAMILIES) {
    if (family.key === 'local' || family.key === 'openrouter') continue;
    if (family.re.some((re) => re.test(name))) return family.key;
  }
  return null;
}

export function familyLabel(key) {
  return FAMILIES.find((f) => f.key === key)?.label || key || '未知';
}

/** 宽松判定：两个模型名是否指向同一家族/同一模型 */
export function sameModelFamily(a, b) {
  const fa = familyOfModel(a);
  const fb = familyOfModel(b);
  if (fa && fb) return fa === fb;
  return String(a || '').toLowerCase() === String(b || '').toLowerCase();
}

export function excerpt(text, limit = 400) {
  const str = typeof text === 'string' ? text : JSON.stringify(text ?? null);
  if (!str) return '(空)';
  const flat = str.replace(/\s+/g, ' ').trim();
  return flat.length > limit ? `${flat.slice(0, limit)}…` : flat;
}

export function count(text, re) {
  const m = String(text || '').match(re);
  return m ? m.length : 0;
}

/** 从任意文本里抠出数字（含千分位） */
export function findNumber(text, expected) {
  const flat = String(text || '').replace(/[,\s_]/g, '');
  return flat.includes(String(expected));
}

export function median(nums) {
  const arr = nums.filter((n) => Number.isFinite(n)).sort((a, b) => a - b);
  if (!arr.length) return null;
  const mid = Math.floor(arr.length / 2);
  return arr.length % 2 ? arr[mid] : (arr[mid - 1] + arr[mid]) / 2;
}

export function ms(n) {
  if (!Number.isFinite(n)) return 'n/a';
  if (n < 1000) return `${Math.round(n)}ms`;
  return `${(n / 1000).toFixed(2)}s`;
}

/** 探针把上游调用结果压缩成可展示的原始证据 */
export function trace(result, { bodyLimit = 2000 } = {}) {
  if (!result) return null;
  return {
    url: result.url,
    method: result.method || 'POST',
    status: result.status,
    ok: result.ok,
    elapsedMs: result.elapsedMs,
    ...(result.redirectChain?.length ? { redirectChain: result.redirectChain } : {}),
    request: result.requestBody ?? null,
    headers: result.headers || {},
    response: result.error
      ? { error: result.error, timedOut: Boolean(result.timedOut) }
      : result.rawText !== undefined
        ? result.rawText
        : result.jsonParsed
          ? result.json
          : String(result.text || '').slice(0, bodyLimit)
  };
}

export function traceStream(s) {
  if (!s) return null;
  return {
    url: s.url,
    status: s.status,
    ok: s.ok,
    contentType: s.contentType,
    ttftMs: s.ttftMs,
    totalMs: s.totalMs,
    chunkCount: s.chunkCount,
    rawLineCount: s.rawLineCount,
    sawDone: s.sawDone,
    roleSeen: s.roleSeen,
    finishReasons: s.finishReasons,
    usage: s.usage,
    malformedLines: s.malformedLines,
    nonDataLines: s.nonDataLines,
    request: s.requestBody,
    headers: s.headers,
    text: s.contentChunks.join('').slice(0, 1200),
    sampleLines: s.rawLines.slice(0, 24)
  };
}
