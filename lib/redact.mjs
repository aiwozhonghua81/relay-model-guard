/**
 * 统一脱敏工具：任何要写日志 / 回传前端 / 落盘的内容都必须先过这里。
 * 目标：API Key 及其片段、Bearer 头、疑似密钥样式的字符串永不出现在输出中。
 */

const KEY_PATTERNS = [
  // 常见真实密钥形态
  /\bsk-[A-Za-z0-9_\-]{6,}\b/g,
  /\bsk-proj-[A-Za-z0-9_\-]{6,}\b/g,
  /\bsk-ant-[A-Za-z0-9_\-]{6,}\b/g,
  /\b(?:ghp|gho|github_pat)_[A-Za-z0-9_]{6,}\b/g,
  /\bAIza[0-9A-Za-z_\-]{10,}\b/g,
  /\bAKIA[0-9A-Z]{12,}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{6,}\b/g,
  /\bBearer\s+[A-Za-z0-9._\-]{8,}/gi,
  // 通用长随机串（保守：仅在看起来像密钥时）
  /\b(?:api[_-]?key|apikey|token|secret|password)["'\s:=]+["']?([A-Za-z0-9._\-]{12,})/gi
];

export function maskSecret(value) {
  if (typeof value !== 'string' || value.length === 0) return '';
  if (value.length <= 8) return '*'.repeat(value.length);
  return `${value.slice(0, 4)}${'*'.repeat(Math.min(12, value.length - 8))}${value.slice(-4)}`;
}

/** 指纹：用于报告里标明「本次用的是哪把 key」，不可逆且不泄露原文。 */
export function keyFingerprint(apiKey) {
  if (typeof apiKey !== 'string' || apiKey.length === 0) return 'n/a';
  // 简单的非加密散列，仅为展示区分度
  let h1 = 0x811c9dc5;
  let h2 = 0x1000193;
  for (let i = 0; i < apiKey.length; i += 1) {
    const c = apiKey.charCodeAt(i);
    h1 = (h1 ^ c) >>> 0;
    h1 = Math.imul(h1, 0x01000193) >>> 0;
    h2 = (h2 + Math.imul(c, 31 + i)) >>> 0;
  }
  return `${h1.toString(16).padStart(8, '0')}${h2.toString(16).padStart(8, '0')}`;
}

/** 深度脱敏：字符串走正则，对象返回新对象，永不修改入参。 */
export function redact(value, extraSecrets = []) {
  const secrets = extraSecrets.filter((s) => typeof s === 'string' && s.length >= 6);
  const seen = new WeakSet();

  const walk = (input, depth) => {
    if (depth > 12) return '[depth-limit]';
    if (typeof input === 'string') return scrubString(input, secrets);
    if (input === null || typeof input !== 'object') return input;
    if (seen.has(input)) return '[circular]';
    seen.add(input);
    if (Array.isArray(input)) {
      const out = input.slice(0, 200).map((item) => walk(item, depth + 1));
      if (input.length > 200) out.push(`…(${input.length - 200} more)`);
      return out;
    }
    const out = {};
    for (const [k, v] of Object.entries(input)) {
      if (/^(authorization|api[-_]?key|x-api-key|proxy-authorization)$/i.test(k)) {
        out[k] = '***REDACTED***';
        continue;
      }
      out[k] = walk(v, depth + 1);
    }
    return out;
  };

  return walk(value, 0);
}

function scrubString(str, secrets) {
  let out = str;
  for (const secret of secrets) {
    if (!secret) continue;
    out = out.split(secret).join(maskSecret(secret));
    // 也处理 URL 编码 / 去引号等变形
    const encoded = encodeURIComponent(secret);
    if (encoded !== secret) out = out.split(encoded).join(maskSecret(secret));
  }
  for (const pattern of KEY_PATTERNS) {
    out = out.replace(pattern, (match, group1) => {
      if (typeof group1 === 'string' && group1.length >= 12) {
        return match.replace(group1, maskSecret(group1));
      }
      return maskSecret(match);
    });
  }
  return out;
}

/** 安全日志：所有控制台输出统一走这里，杜绝 key 泄漏。 */
export function safeLog(...parts) {
  const line = parts
    .map((p) => (typeof p === 'string' ? p : JSON.stringify(redact(p))))
    .join(' ');
  process.stdout.write(`[relay-guard] ${redact(line)}\n`);
}
