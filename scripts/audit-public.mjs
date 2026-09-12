/**
 * 开源前的「脱敏体检」：扫描即将发布的内容，找出不该出现在公开仓库里的东西。
 *
 * 用法：
 *   node scripts/audit-public.mjs          # 有 git 仓库时只扫「将被提交的文件」（git ls-files）
 *   node scripts/audit-public.mjs --all    # 无视 .gitignore，扫描工作目录下所有文件
 *
 * 退出码：发现问题 = 1，干净 = 0（方便挂到 pre-commit / CI 上）
 *
 * 注意：本脚本自身的检测规则用字符串拼接写成，避免自我误报。
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SCAN_ALL = process.argv.includes('--all');
/** 永远不扫的目录 */
const ALWAYS_SKIP = new Set(['.git', 'node_modules']);
/** 被 .gitignore 覆盖、默认不扫（--all 时会扫） */
const IGNORED_DIRS = new Set(['outputs', 'work']);
const TEXT_EXT = new Set([
  '.mjs', '.js', '.cjs', '.json', '.md', '.html', '.css', '.txt', '.yml', '.yaml', '.toml', '.sh', '.ps1', '.example'
]);
const MAX_BYTES = 2 * 1024 * 1024;

/** 用片段拼接，避免规则字符串本身被扫描命中 */
const U = 'C:' + '\\\\Users\\\\';
const U2 = 'C:' + '/Users/';
const HOME_POSIX = new RegExp(`(?:/Users/|/home/)[A-Za-z0-9._-]{2,}/`);

const RULES = [
  {
    id: 'secret-openai',
    label: '疑似真实 API Key（OpenAI 风格）',
    re: new RegExp('\\b' + 'sk' + '-[A-Za-z0-9_-]{20,}', 'g')
  },
  {
    id: 'secret-other',
    label: '疑似其它服务密钥',
    re: new RegExp(`\\b(?:${'AIza'}[0-9A-Za-z_-]{20,}|${'AKIA'}[0-9A-Z]{12,}|${'ghp'}_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})`, 'g')
  },
  {
    id: 'private-key',
    label: '私钥文件内容',
    re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g
  },
  {
    id: 'long-bearer',
    label: '硬编码的 Bearer 令牌',
    re: /Bearer\s+[A-Za-z0-9._-]{24,}/g
  },
  {
    id: 'win-home-path',
    label: 'Windows 用户目录绝对路径（会暴露本机用户名）',
    re: new RegExp(U.replace(/\\\\/g, '\\\\') + '[^\\s"\']+', 'gi')
  },
  {
    id: 'win-home-path-fwd',
    label: 'Windows 用户目录绝对路径（正斜杠写法）',
    re: new RegExp(U2 + '[^\\s"\']+', 'gi')
  },
  {
    id: 'posix-home-path',
    label: 'macOS / Linux 用户目录绝对路径',
    re: new RegExp(HOME_POSIX.source, 'g')
  },
  {
    id: 'email',
    label: '邮箱地址',
    // 负向后顾用于排除 URL 里的 user:pass@host 这种「凭据」写法，避免误报
    re: /(?<![:\w.@/-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g,
    allow: [/noreply\.github\.com$/i, /@example\.(com|invalid)$/i, /@github\.com$/i, /@users\.noreply\.github\.com$/i, /@img\.shields\.io$/i]
  }
];

function listFilesFromGit() {
  try {
    const out = execFileSync('git', ['ls-files', '-z'], { cwd: ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    return out.split('\0').filter(Boolean).map((p) => path.join(ROOT, p));
  } catch {
    return null;
  }
}

function walk(dir, acc = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith('.') && entry.name !== '.gitignore') {
      if (entry.isDirectory()) continue;
    }
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (ALWAYS_SKIP.has(entry.name)) continue;
      if (!SCAN_ALL && IGNORED_DIRS.has(entry.name)) continue;
      walk(full, acc);
      continue;
    }
    acc.push(full);
  }
  return acc;
}

function isTextFile(file) {
  const ext = path.extname(file).toLowerCase();
  try {
    if (statSync(file).size > MAX_BYTES) return false;
  } catch {
    return false;
  }
  // 已知文本扩展名直接放行；无扩展名的文件（Dockerfile、.env 等）用「是否含 NUL 字节」判断
  if (TEXT_EXT.has(ext)) return true;
  if (ext !== '') return false;
  try {
    return !readFileSync(file).subarray(0, 4096).includes(0);
  } catch {
    return false;
  }
}

const gitFiles = SCAN_ALL ? null : listFilesFromGit();
const files = (gitFiles && gitFiles.length ? gitFiles : walk(ROOT)).filter(isTextFile);
const source = gitFiles && gitFiles.length ? 'git ls-files（将被提交的文件）' : '文件系统遍历（尚未 git add 或不是 git 仓库）';

// 本机用户名动态检测：最容易被忽略、也最直接的隐私泄漏
const localUser = (() => {
  const fromProfile = String(process.env.USERPROFILE || process.env.HOME || '').split(/[\\/]/).filter(Boolean).pop();
  const fromInfo = (() => {
    try {
      return os.userInfo().username;
    } catch {
      return null;
    }
  })();
  return [...new Set([fromProfile, fromInfo])].filter(
    (v) => v && v.length >= 3 && !/^(users?|home|root|admin|runner)$/i.test(v)
  );
})();

const findings = [];
for (const file of files) {
  let content;
  try {
    content = readFileSync(file, 'utf8');
  } catch {
    continue;
  }
  const rel = path.relative(ROOT, file).split(path.sep).join('/');

  for (const name of localUser) {
    const re = new RegExp(name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi');
    for (const match of content.matchAll(re)) {
      const line = content.slice(0, match.index).split('\n').length;
      findings.push({ rel, line, label: `出现本机用户名「${name}」`, snippet: snippetAt(content, match.index, match[0].length) });
    }
  }

  for (const rule of RULES) {
    const re = rule.re.global ? rule.re : new RegExp(rule.re.source, `${rule.re.flags}g`);
    re.lastIndex = 0;
    for (const match of content.matchAll(re)) {
      const value = match[0];
      if (rule.allow?.some((a) => a.test(value))) continue;
      if (rule.id.startsWith('secret') || rule.id === 'long-bearer') {
        // 明显是示例/占位的值不算泄漏
        if (/demo|sample|example|placeholder|test|dummy|your-key|xxx/i.test(value)) continue;
      }
      const line = content.slice(0, match.index).split('\n').length;
      findings.push({ rel, line, label: rule.label, snippet: mask(value) });
    }
  }
}

function snippetAt(content, index, length) {
  const start = Math.max(0, index - 24);
  const raw = content.slice(start, index + length + 24).replace(/\s+/g, ' ');
  return raw.replace(content.slice(index, index + length), mask(content.slice(index, index + length)));
}

function mask(value) {
  const text = String(value);
  if (text.length <= 8) return text;
  return `${text.slice(0, 4)}***${text.slice(-2)}（${text.length} 字符）`;
}

process.stdout.write(`\n扫描来源：${source}\n文件数：${files.length}\n`);
if (localUser.length) process.stdout.write(`动态检测的本机用户名：${localUser.join(', ')}\n`);

if (!findings.length) {
  process.stdout.write('\n✅ 未发现密钥、私钥、绝对路径、邮箱或本机用户名。可以推送。\n\n');
  process.exit(0);
}

process.stdout.write(`\n⚠️  发现 ${findings.length} 处需要处理的内容：\n\n`);
for (const f of findings) {
  process.stdout.write(`  ${f.rel}:${f.line}  ${f.label}\n      ${f.snippet}\n`);
}
process.stdout.write(
  '\n处理建议：删除或改成占位符（example / your-key / <YOUR_NAME>）；' +
    '已被 .gitignore 排除的目录（outputs/、work/）不会进仓库，可不处理。\n\n'
);
process.exit(1);
