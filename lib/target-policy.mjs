/**
 * 出站目标策略：deploy-safe 模式下用来阻断 SSRF。
 *
 * 拦什么：
 *  - 协议不是 http/https 的
 *  - 主机名是 localhost / *.localhost / *.local / *.internal / 云元数据域名
 *  - 解析出来的**任意一个** IP 落在私有 / 回环 / 链路本地 / 组播 / 保留段
 *    （IPv4 与 IPv6 都覆盖，含 ::ffff: 映射地址）
 *
 * 已知边界（诚实说明）：本模块在**发起请求前**解析并校验，DNS rebinding 理论上存在
 * TOCTOU 竞态窗口；deploy-safe 模式下还有「鉴权 + 全局限流 + 逐跳校验重定向」三层兜底，
 * 但如果你要把这个服务开放给不受信任的用户，请额外配置出站防火墙策略。
 */

import { lookup } from 'node:dns/promises';
import net from 'node:net';

export class TargetBlockedError extends Error {
  constructor(message, meta = {}) {
    super(message);
    this.name = 'TargetBlockedError';
    this.code = 'TARGET_BLOCKED';
    this.isTargetBlocked = true;
    this.meta = meta;
  }
}

/** [网络地址, 前缀长度] —— 覆盖 RFC1918 / 回环 / 链路本地 / CGNAT / 组播 / 保留段 */
const V4_BLOCKS = [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16], // 含云元数据 169.254.169.254
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.88.99.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
  ['255.255.255.255', 32]
];

const V6_BLOCKS = [
  ['::', 128],
  ['::1', 128],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
  ['2001:db8::', 32],
  ['64:ff9b::', 96],
  ['100::', 64]
];

const BLOCKED_HOSTNAMES = /^(localhost|.*\.localhost|.*\.local|.*\.internal|metadata\.google\.internal|metadata\.goog)$/i;

function v4ToBytes(ip) {
  const parts = ip.split('.').map((p) => Number(p));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return parts;
}

function v6ToBytes(ip) {
  let text = ip.trim().toLowerCase();
  // 处理 ::ffff:1.2.3.4 这类映射地址
  const mapped = text.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) {
    const v4 = v4ToBytes(mapped[1]);
    return v4 ? [...Array(10).fill(0), 0xff, 0xff, ...v4] : null;
  }
  const [headRaw, tailRaw] = text.split('::');
  const head = headRaw ? headRaw.split(':').filter(Boolean) : [];
  const tail = tailRaw ? tailRaw.split(':').filter(Boolean) : [];
  if (text.includes('::')) {
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    return [...head, ...Array(missing).fill('0'), ...tail].flatMap((g) => {
      const value = Number.parseInt(g, 16);
      if (!Number.isInteger(value) || value < 0 || value > 0xffff) return [];
      return [value >> 8, value & 0xff];
    });
  }
  const groups = head;
  if (groups.length !== 8) return null;
  return groups.flatMap((g) => {
    const value = Number.parseInt(g, 16);
    if (!Number.isInteger(value) || value < 0 || value > 0xffff) return [];
    return [value >> 8, value & 0xff];
  });
}

function toBytes(ip) {
  const family = net.isIP(ip);
  if (family === 4) return v4ToBytes(ip);
  if (family === 6) return v6ToBytes(ip);
  return null;
}

function matchPrefix(bytes, network, prefix) {
  const netBytes = toBytes(network);
  if (!netBytes || !bytes || netBytes.length !== bytes.length) return false;
  const fullBytes = Math.floor(prefix / 8);
  const restBits = prefix % 8;
  for (let i = 0; i < fullBytes; i += 1) if (bytes[i] !== netBytes[i]) return false;
  if (restBits === 0) return true;
  const mask = 0xff << (8 - restBits) & 0xff;
  return (bytes[fullBytes] & mask) === (netBytes[fullBytes] & mask);
}

/** 判断单个 IP 是否属于禁止访问的网段 */
export function describeBlockedIp(ip) {
  const bytes = toBytes(ip);
  if (!bytes) return null;
  const family = net.isIP(ip);
  const table = family === 4 ? V4_BLOCKS : V6_BLOCKS;
  for (const [network, prefix] of table) {
    if (matchPrefix(bytes, network, prefix)) return `${network}/${prefix}`;
  }
  // IPv4-mapped IPv6：按 IPv4 再判一次
  if (family === 6 && bytes.slice(0, 10).every((b) => b === 0) && bytes[10] === 0xff && bytes[11] === 0xff) {
    const v4 = bytes.slice(12).join('.');
    return describeBlockedIp(v4);
  }
  return null;
}

export function isBlockedIp(ip) {
  return describeBlockedIp(ip) !== null;
}

/**
 * 校验一个 URL 能否作为出站目标。
 * allowPrivate=true 时直接放行（本地开发/自建演示桩场景，不产生 DNS 查询）。
 * @returns {Promise<{url:string, host:string, addresses:string[]}>}
 */
export async function assertTargetAllowed(rawUrl, { allowPrivate = false, label = '目标' } = {}) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new TargetBlockedError(`${label}不是合法 URL：${String(rawUrl).slice(0, 120)}`, { rawUrl: String(rawUrl).slice(0, 200) });
  }

  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new TargetBlockedError(`${label}协议不被允许：${url.protocol}（仅支持 http/https）`, { host: url.hostname });
  }
  if (allowPrivate) return { url: url.toString(), host: url.hostname, addresses: [] };

  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (BLOCKED_HOSTNAMES.test(host)) {
    throw new TargetBlockedError(
      `${label}指向本机/内网保留域名 ${host}，已按 deploy-safe 策略拦截（如确需访问，设置 ALLOW_PRIVATE_TARGETS=1）`,
      { host }
    );
  }

  const literalFamily = net.isIP(host);
  let addresses;
  if (literalFamily) {
    addresses = [{ address: host, family: literalFamily }];
  } else {
    try {
      addresses = await lookup(host, { all: true, verbatim: true });
    } catch (error) {
      throw new Error(`域名解析失败：${host}（${error?.code || error?.message}）`);
    }
  }
  if (!addresses.length) throw new Error(`域名无法解析：${host}`);

  for (const entry of addresses) {
    const blockedRange = describeBlockedIp(entry.address);
    if (blockedRange) {
      throw new TargetBlockedError(
        `${label}解析到内网/保留地址 ${entry.address}（网段 ${blockedRange}），已按 deploy-safe 策略拦截，未发出任何请求`,
        { host, address: entry.address, range: blockedRange, addresses: addresses.map((a) => a.address) }
      );
    }
  }

  return { url: url.toString(), host, addresses: addresses.map((a) => a.address) };
}
