/**
 * 单次检测的 Token 预算闸门 + token 估算工具。
 *
 * 语义（对应「防止一次性跑爆额度」）：
 *  1. reserve()：每个请求在**发送前**先按「prompt 估算 + max_tokens 上限」预占额度。
 *     若预占后会超过上限 → 立即把预算标记为耗尽、abort 在途请求、并抛错，**请求不会发出**。
 *  2. reconcile()：请求返回后用真实 usage 结算（拿不到 usage 就按预占值保守记账）。
 *  3. 一旦耗尽：signal 被 abort → Upstream 里所有在途 fetch / 流式读取立刻中断；
 *     reserve() 之后一律抛错，重试循环也不会再发新请求。
 *  4. deadlineMs：总时长护栏，到点同样中止（避免并发探针卡在重试里拖时间）。
 *
 * 抛出的终止错误带 phase 字段，供上层区分展示：
 *   phase='reserve'  → 该探针额度不足，未发出任何请求 → 记为「已跳过」
 *   phase='budget'   → 累计用量到顶，在途请求被打断 → 记为「已终止」
 *   phase='deadline' → 总时长到顶 → 记为「已终止」
 */

/** 请求没有显式 max_tokens 时，按这个值预留下限 */
const DEFAULT_COMPLETION_RESERVE = 512;

export class BudgetExceededError extends Error {
  constructor(message, { phase = 'reserve', code = 'TOKEN_BUDGET_RESERVE', meta = null } = {}) {
    super(message);
    this.name = 'BudgetExceededError';
    this.isGuardAbort = true;
    this.phase = phase;
    this.code = code;
    this.meta = meta;
  }
}

/** 预算 / 总时长触发的终止，统一用它表示（Upstream 会原样向上抛） */
function guardAbort(message, { phase, code, meta = null }) {
  return new BudgetExceededError(message, { phase, code, meta });
}

/** 只有本模块产生的终止错误才算「预算/时长终止」，普通网络错误不在此列 */
export function isAbortError(value) {
  return Boolean(value && value.isGuardAbort === true);
}

/** 给用户看的一句话说明（作为证据文案） */
export function abortReasonText(reason) {
  if (!reason) return '本次检测已提前终止：额度或时长护栏触发';
  if (typeof reason === 'string') return reason;
  if (reason.message) return reason.message;
  return '本次检测已提前终止：额度或时长护栏触发';
}

/**
 * 轻量 token 估算（中英混排）：CJK ≈ 0.8 token/字，其他 ≈ 1/3.6 token/字符。
 * 仅用于预占与量级判断，不追求与具体分词器一致。
 */
export function estimatePayloadTokens(payload) {
  const text = typeof payload === 'string' ? payload : JSON.stringify(payload ?? '');
  let cjk = 0;
  let other = 0;
  for (const ch of text) {
    if (/[\u3000-\u9fff\uff00-\uffef]/.test(ch)) cjk += 1;
    else other += 1;
  }
  return Math.ceil(cjk * 0.8 + other / 3.6) + 4;
}

/** 单次请求的预占额度：输入估算 + 输出上限（取不到 max_tokens 时用保守缺省值） */
export function estimateReservation(payload, maxTokens) {
  const prompt = estimatePayloadTokens(payload);
  const cap = Number.isFinite(maxTokens) && maxTokens > 0 ? maxTokens : DEFAULT_COMPLETION_RESERVE;
  return prompt + cap;
}

export class TokenBudget {
  constructor({ limit, deadlineMs = 0, onUpdate = null } = {}) {
    const parsed = Number(limit);
    if (!Number.isFinite(parsed) || parsed <= 0) throw new Error('Token 上限必须是正数');
    this.limit = Math.floor(parsed);
    this.spent = 0;
    this.reserved = 0;
    this.calls = 0;
    this.settled = 0;
    this.refused = 0;
    this.exhausted = false;
    this.stopped = false;
    this.reason = null;
    this.exhaustedAt = null;
    this.deadlineMs = Math.max(0, Number(deadlineMs) || 0);
    this.deadlineAt = null;
    this.startedAt = null;
    this.onUpdate = typeof onUpdate === 'function' ? onUpdate : null;
    this._timer = null;
    this._controller = new AbortController();
  }

  /** 供 fetch 使用的信号：预算耗尽 / 总时长到顶时 abort，reason 即终止错误 */
  get signal() {
    return this._controller.signal;
  }

  start() {
    if (this.startedAt) return this;
    this.startedAt = Date.now();
    if (this.deadlineMs > 0) {
      this.deadlineAt = this.startedAt + this.deadlineMs;
      this._timer = setTimeout(() => {
        this.exhaust(
          guardAbort(`本次检测已超过总时长上限 ${Math.round(this.deadlineMs / 1000)}s，已中止全部在途请求`, {
            phase: 'deadline',
            code: 'TOKEN_BUDGET_DEADLINE'
          })
        );
      }, this.deadlineMs);
      this._timer.unref?.();
    }
    return this;
  }

  /** 清理定时器（检测结束时调用；不改变用量与终止状态） */
  stop() {
    this.stopped = true;
    if (this._timer) {
      clearTimeout(this._timer);
      this._timer = null;
    }
    return this;
  }

  get remaining() {
    return Math.max(0, this.limit - this.spent - this.reserved);
  }

  /** 是否还能继续跑下一个探针 */
  canContinue() {
    if (this.exhausted) return false;
    if (this.deadlineAt && Date.now() >= this.deadlineAt) {
      this.exhaust(
        guardAbort(`本次检测已超过总时长上限 ${Math.round(this.deadlineMs / 1000)}s，已中止全部在途请求`, {
          phase: 'deadline',
          code: 'TOKEN_BUDGET_DEADLINE'
        })
      );
      return false;
    }
    return this.spent < this.limit;
  }

  /**
   * 发送前预占额度。返回预占量；额度不足时抛 phase='reserve' 的终止错误（请求不会发出）。
   */
  reserve(cost, meta = null) {
    const amount = Number.isFinite(cost) && cost > 0 ? Math.ceil(cost) : 0;
    if (this.exhausted) {
      this.refused += 1;
      throw guardAbort(`本次检测的 Token 额度已用尽（${this.spent}/${this.limit}），该请求未发送`, {
        phase: 'reserve',
        code: 'TOKEN_BUDGET_RESERVE',
        meta
      });
    }
    if (this.spent + this.reserved + amount > this.limit) {
      this.refused += 1;
      const error = guardAbort(
        `剩余额度不足以再发一次请求（需要 ${amount}，剩余 ${this.remaining}，上限 ${this.limit}），该请求未发送并终止本次检测`,
        { phase: 'reserve', code: 'TOKEN_BUDGET_RESERVE', meta }
      );
      // 先终止（打断在途请求、通知上层），再把「未发出请求」的错误抛给当前探针
      this.exhaust(
        guardAbort(
          `本次检测累计 Token 已达上限（${this.spent + this.reserved}/${this.limit}），已中止全部在途探针并停止调用 API`,
          { phase: 'budget', code: 'TOKEN_BUDGET_EXHAUSTED', meta }
        )
      );
      throw error;
    }
    this.reserved += amount;
    this.calls += 1;
    this._notify();
    return amount;
  }

  /** 请求结束后结算：有真实 usage 用真实值，否则按预占值保守记账 */
  reconcile(reservation, actual) {
    const reservedAmount = Number.isFinite(reservation) ? Math.max(0, reservation) : 0;
    this.reserved = Math.max(0, this.reserved - reservedAmount);
    this.settled += 1;
    const measured = Number.isFinite(actual) ? Math.max(0, Math.ceil(actual)) : null;
    const spent = measured === null ? reservedAmount : measured;
    this.spent += spent;
    if (!this.exhausted && this.spent >= this.limit) {
      this.exhaust(
        guardAbort(
          `本次检测累计 Token 已达上限（${this.spent}/${this.limit}），已中止全部在途探针并停止调用 API`,
          { phase: 'budget', code: 'TOKEN_BUDGET_EXHAUSTED' }
        )
      );
    } else {
      this._notify();
    }
    return { spent, measured: measured !== null };
  }

  /** 触发终止：abort 信号（打断在途请求）并通知上层 */
  exhaust(reason) {
    if (this.exhausted) return this;
    this.exhausted = true;
    this.reason =
      reason instanceof Error
        ? reason
        : guardAbort(abortReasonText(reason), { phase: 'budget', code: 'TOKEN_BUDGET_EXHAUSTED' });
    this.exhaustedAt = Date.now();
    // 在途 fetch / 流式读取会从这里被中断
    if (!this._controller.signal.aborted) this._controller.abort(this.reason);
    this._notify(true);
    return this;
  }

  snapshot() {
    const committed = this.spent + this.reserved;
    const usedPercent = this.limit > 0 ? Math.round(Math.min(100, (committed / this.limit) * 100) * 10) / 10 : 0;
    return {
      limit: this.limit,
      spent: this.spent,
      reserved: this.reserved,
      remaining: this.remaining,
      committed,
      usedPercent,
      calls: this.calls,
      settled: this.settled,
      refused: this.refused,
      exhausted: this.exhausted,
      reason: this.exhausted ? abortReasonText(this.reason) : null,
      phase: this.reason?.phase ?? null,
      code: this.reason?.code ?? null,
      overshoot: Math.max(0, this.spent - this.limit),
      deadlineMs: this.deadlineMs,
      elapsedMs: this.startedAt ? Date.now() - this.startedAt : 0,
      stopped: this.stopped
    };
  }

  _notify(force = false) {
    if (!this.onUpdate) return;
    try {
      this.onUpdate(this.snapshot(), force);
    } catch {
      /* 上报异常不能影响检测主流程 */
    }
  }
}
