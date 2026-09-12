/**
 * 探针运行上下文工厂。
 * 真实执行与「预估干跑」共用同一份实现，保证预估出的请求与真实发出的请求一致。
 */

export function createProbeContext({ upstream, model, baseUrl, options = {}, log = () => {}, probeId = null }) {
  return {
    upstream,
    model,
    baseUrl,
    options,
    log,
    probeId,
    ask: ({ system, user, maxTokens = 200, temperature = 0, timeoutMs, extra = {} }) => {
      const messages = [];
      if (system) messages.push({ role: 'system', content: system });
      messages.push({ role: 'user', content: user });
      return upstream.chat({ messages, max_tokens: maxTokens, temperature, ...extra }, { timeoutMs });
    }
  };
}
