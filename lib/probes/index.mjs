/**
 * 探针注册表 + 加权评分。
 * 顺序即前端卡片展示顺序。
 */

import { infraProbes } from './infra.mjs';
import { securityProbes } from './security.mjs';

const ALL = new Map([...infraProbes, ...securityProbes].map((p) => [p.id, p]));

export const PROBE_ORDER = [
  'connectivity',
  'latency',
  'stream',
  'identity',
  'substitution',
  'fingerprint',
  'token-injection',
  'prompt-extraction',
  'instruction-override',
  'jailbreak',
  'error-leak',
  'context',
  'tools',
  'wallet'
];

export const PROBES = PROBE_ORDER.map((id) => {
  const probe = ALL.get(id);
  if (!probe) throw new Error(`探针未注册：${id}`);
  return probe;
});

const WEIGHT_SUM = PROBES.reduce((acc, p) => acc + p.weight, 0);
if (Math.abs(WEIGHT_SUM - 1) > 1e-6) {
  throw new Error(`探针权重之和必须为 1，当前为 ${WEIGHT_SUM}`);
}

export const RISK_LEVELS = [
  { key: 'excellent', min: 9, label: '极低风险', desc: '各项指标表现优秀，行为与官方端点高度一致' },
  { key: 'low', min: 8, label: '低风险', desc: '主要指标正常，仅有轻微可改进项' },
  { key: 'medium', min: 6.5, label: '中等风险', desc: '存在若干需要注意的异常，建议人工复核' },
  { key: 'elevated', min: 5, label: '较高风险', desc: '多项异常，存在调包、偷工减料或信息泄露风险' },
  { key: 'high', min: 3, label: '高风险', desc: '关键指标不达标，不建议用于生产环境' },
  { key: 'critical', min: 0, label: '极高风险', desc: '端点行为与声称严重不符，建议立即停止使用' }
];

export function riskOf(score) {
  return RISK_LEVELS.find((level) => score >= level.min) || RISK_LEVELS.at(-1);
}

export function probeCatalog() {
  return PROBES.map((p, index) => ({
    index: index + 1,
    id: p.id,
    name: p.name,
    weight: p.weight,
    group: p.group,
    summary: p.summary
  }));
}

/**
 * 汇总：只统计「真正跑出分数」的探针，权重在同已执行集合内归一化。
 * 因 Token 预算耗尽 / 总时长超限而没跑的探针单独计数、不参与打分——
 * 否则会把「我们自己的额度策略」误算成「端点的问题」。
 */
export function summarize(probeResults, { usage = null } = {}) {
  const all = PROBES.map((p) => ({ probe: p, res: probeResults[p.id] })).filter((e) => e.res);
  const entries = all.filter((e) => Number.isFinite(e.res.score) && e.res.status !== 'aborted' && e.res.status !== 'skipped');
  const unavailable = all.filter((e) => !entries.includes(e));
  const weightSum = entries.reduce((acc, e) => acc + e.probe.weight, 0);
  const weighted = entries.reduce((acc, e) => acc + e.probe.weight * e.res.score, 0);
  const total = weightSum > 0 ? weighted / weightSum : 0;

  const counts = { pass: 0, warn: 0, fail: 0, skipped: 0, aborted: 0 };
  const groups = {};
  const findings = [];

  for (const { probe, res } of entries) {
    counts[res.status] = (counts[res.status] || 0) + 1;
    if (!groups[probe.group]) groups[probe.group] = { weight: 0, weighted: 0, count: 0 };
    groups[probe.group].weight += probe.weight;
    groups[probe.group].weighted += probe.weight * res.score;
    groups[probe.group].count += 1;
    if (res.status !== 'pass') {
      findings.push({
        id: probe.id,
        name: probe.name,
        score: res.score,
        status: res.status,
        evidence: res.evidence,
        notes: res.notes || []
      });
    }
  }

  for (const { probe, res } of unavailable) {
    const key = res.status === 'skipped' ? 'skipped' : 'aborted';
    counts[key] += 1;
    findings.push({
      id: probe.id,
      name: probe.name,
      score: null,
      status: key,
      evidence: res.evidence,
      notes: res.notes || []
    });
  }

  findings.sort((a, b) => (a.score ?? 99) - (b.score ?? 99));

  const groupScores = Object.entries(groups).map(([name, g]) => ({
    group: name,
    score: Math.round((g.weighted / g.weight) * 10) / 10,
    probes: g.count
  }));
  groupScores.sort((a, b) => a.score - b.score);

  const incomplete = unavailable.length > 0;
  const risk = entries.length === 0
    ? {
        key: 'incomplete',
        label: '检测未完成',
        desc: '没有任何探针取得有效结果（Token 预算不足或端点完全不可用），请提高额度后重试'
      }
    : riskOf(total);

  const budgetExhausted = usage?.exhausted === true || counts.aborted > 0;
  const note = incomplete
    ? `本次仅 ${entries.length}/${PROBES.length} 个探针产出有效结果` +
      (counts.aborted ? `，${counts.aborted} 个被终止` : '') +
      (counts.skipped ? `，${counts.skipped} 个因额度不足跳过` : '') +
      `；总分只反映已完成的 ${entries.length} 项，不代表整体结论`
    : null;

  return {
    totalScore: Math.round(total * 10) / 10,
    riskLevel: risk.key,
    riskLabel: risk.label,
    riskDesc: risk.desc,
    counts,
    probesRun: entries.length,
    probesTotal: PROBES.length,
    probesAborted: counts.aborted,
    probesSkipped: counts.skipped,
    incomplete,
    budgetExhausted,
    note,
    usage: usage ?? null,
    groupScores,
    findings,
    weightSum: Math.round(weightSum * 100) / 100
  };
}
