/**
 * 一键发布到 GitHub。需要本机已安装并登录 gh CLI（https://cli.github.com）。
 *
 *   npm run publish:github                    # 交互确认后创建公开仓库并推送
 *   npm run publish:github -- --yes           # 跳过确认（适合已经想清楚的情况）
 *   npm run publish:github -- --private       # 建私有仓库
 *   npm run publish:github -- --name my-repo  # 自定义仓库名
 *
 * 做四件事：
 *   1. 校验 gh 已登录（拿不到就明确提示，不会去碰你的账号）
 *   2. 把提交身份设成 GitHub 的 noreply 邮箱（不写真实邮箱，身份安全）
 *   3. 跑一遍脱敏体检，不干净就拒绝发布
 *   4. 建仓库（附标题/简介/Topics）并推送
 */

import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterface } from 'node:readline/promises';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const argv = process.argv.slice(2);
const has = (flag) => argv.includes(flag);
const valueOf = (flag, fallback) => {
  const i = argv.indexOf(flag);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback;
};

const REPO_NAME = valueOf('--name', 'relay-model-guard');
const VISIBILITY = has('--private') ? '--private' : '--public';
const SKIP_CONFIRM = has('--yes');
const COMMIT_MESSAGE = 'feat: 中转 API 模型检测器（14 路探针 + Token 预算保护 + deploy-safe）';
const DESCRIPTION =
  '给 LLM 中转 API 做体检的 14 路探针检测器：识别模型调包、隐藏提示词、Token 注入、越狱绕过、上下文截断与计费异常；内置 Token 预算保护与 deploy-safe 部署模式。零依赖 Node。';
const TOPICS = ['llm', 'openai', 'api-testing', 'llm-security', 'prompt-injection', 'relay', 'nodejs', 'zero-dependencies'];

const isWin = process.platform === 'win32';

/**
 * 解析可执行文件路径。注意一律**不用 shell**：
 * Windows 下经 cmd.exe 传参会把中文参数拆坏（实测 `git commit -m "feat: 中转 …"`
 * 会被解析成 pathspec 错误），所以这里直接传 argv。
 */
function which(bin) {
  const finder = isWin ? 'where.exe' : 'which';
  const res = spawnSync(finder, [bin], { encoding: 'utf8', shell: false });
  if (res.status === 0) {
    const first = (res.stdout || '').split(/\r?\n/).map((s) => s.trim()).filter(Boolean)[0];
    if (first) return first;
  }
  return bin;
}

const GIT = which('git');
const GH = which('gh');

const run = (cmd, args, { quiet = false, input } = {}) =>
  spawnSync(cmd, args, {
    cwd: ROOT,
    encoding: 'utf8',
    shell: false,
    input,
    maxBuffer: 64 * 1024 * 1024,
    stdio: input === undefined ? (quiet ? ['ignore', 'pipe', 'pipe'] : ['inherit', 'pipe', 'pipe']) : ['pipe', 'pipe', 'pipe']
  });

/** 读取二进制输出（把 git 对象原样取出来） */
const runBuffer = (cmd, args) => spawnSync(cmd, args, { cwd: ROOT, shell: false, maxBuffer: 64 * 1024 * 1024 });

/** 取出本地 HEAD 提交的作者/提交者/信息，用于在 API 侧复刻同一个提交 */
function readLocalCommitMeta() {
  const res = run(GIT, ['log', '-1', '--format=%an%n%ae%n%aI%n%cn%n%ce%n%cI%n%B'], { quiet: true });
  if (res.status !== 0) fail('读取提交信息失败。');
  const lines = res.stdout.split('\n');
  const [an, ae, aI, cn, ce, cI] = lines;
  return {
    message: lines.slice(6).join('\n').replace(/\n+$/, ''),
    author: { name: an, email: ae, date: aI },
    committer: { name: cn, email: ce, date: cI }
  };
}

/**
 * 兜底通道：当 github.com:443 连不通（国内网络很常见）时，改走 api.github.com 的
 * Git Data API 上传：blob → tree → commit → ref，完全绕开 github.com。
 * 文件字节与提交元信息都取自本地对象，因此远端会得到与本地相同的 SHA，不会分叉。
 */
function pushViaApi(fullName, meta) {
  const repoInfo = JSON.parse(run(GH, ['api', `/repos/${fullName}`], { quiet: true }).stdout || '{}');
  const branch = repoInfo.default_branch || 'main';
  // 空仓库不能直接建 blob（GitHub 返回 409 Git Repository is empty），
  // 先用 Contents API 造一个种子提交把仓库激活，最后再用孤儿提交覆盖掉它。
  if (run(GH, ['api', `/repos/${fullName}/git/ref/heads/${branch}`], { quiet: true }).status !== 0) {
    const seedPath = `.publish-seed-${Date.now()}`;
    const seed = run(GH, ['api', '--method', 'PUT', `/repos/${fullName}/contents/${seedPath}`, '--input', '-'], {
      quiet: true,
      input: JSON.stringify({ message: 'chore: initialize repository', content: Buffer.from('seed\n').toString('base64') })
    });
    if (seed.status !== 0) fail('创建种子提交失败。', (seed.stderr || '').trim().split('\n')[0]);
    process.stdout.write('   已创建种子提交（稍后会被覆盖，不会留在历史里）\n');
  }

  const list = run(GIT, ['ls-tree', '-r', '-z', 'HEAD']);
  if (list.status !== 0) fail('读取本地 git 对象失败。');
  const entries = list.stdout
    .split('\0')
    .filter(Boolean)
    .map((line) => {
      const [info, ...rest] = line.split('\t');
      const [mode, type, sha] = info.split(' ');
      return { mode, type, sha, path: rest.join('\t') };
    });

  process.stdout.write(`   共 ${entries.length} 个文件，逐个上传（走 api.github.com）…\n`);
  const tree = [];
  entries.forEach((entry, i) => {
    const blob = runBuffer(GIT, ['cat-file', 'blob', entry.sha]);
    const payload = JSON.stringify({ content: Buffer.from(blob.stdout).toString('base64'), encoding: 'base64' });
    const res = run(GH, ['api', '--method', 'POST', `/repos/${fullName}/git/blobs`, '--input', '-'], { quiet: true, input: payload });
    if (res.status !== 0) fail(`上传 ${entry.path} 失败。`, (res.stderr || '').trim().split('\n')[0]);
    tree.push({ path: entry.path, mode: entry.mode, type: 'blob', sha: JSON.parse(res.stdout).sha });
    process.stdout.write(`   [${String(i + 1).padStart(2)}/${entries.length}] ${entry.path}\n`);
  });

  const apiJson = (endpoint, body, label) => {
    const res = run(GH, ['api', '--method', 'POST', endpoint, '--input', '-'], { quiet: true, input: JSON.stringify(body) });
    if (res.status !== 0) fail(`${label}失败。`, (res.stderr || '').trim().split('\n')[0]);
    return JSON.parse(res.stdout);
  };

  const treeSha = apiJson(`/repos/${fullName}/git/trees`, { tree }, '创建 tree ').sha;
  const commitSha = apiJson(
    `/repos/${fullName}/git/commits`,
    { message: meta.message, tree: treeSha, parents: [], author: meta.author, committer: meta.committer },
    '创建 commit '
  ).sha;
  // 强制把默认分支指向这个「无父提交」，历史里就只剩这一个提交
  const refRes = run(GH, ['api', '--method', 'PATCH', `/repos/${fullName}/git/refs/heads/${branch}`, '--input', '-'], {
    quiet: true,
    input: JSON.stringify({ sha: commitSha, force: true })
  });
  if (refRes.status !== 0) fail('更新分支失败。', (refRes.stderr || '').trim().split('\n')[0]);

  const local = (run(GIT, ['rev-parse', 'HEAD'], { quiet: true }).stdout || '').trim();
  process.stdout.write(
    commitSha === local
      ? `   ✓ 已通过 API 上传，远端提交与本地完全一致（${commitSha.slice(0, 8)}）\n`
      : `   ✓ 已通过 API 上传（远端 ${commitSha.slice(0, 8)} / 本地 ${local.slice(0, 8)}，内容一致、SHA 不同）\n`
  );
}

function fail(message, hint) {
  process.stdout.write(`\n❌ ${message}\n`);
  if (hint) process.stdout.write(`   ${hint}\n`);
  process.exit(1);
}

process.stdout.write(`\n=== 发布到 GitHub ===\n仓库名：${REPO_NAME}\n可见性：${VISIBILITY === '--public' ? '公开' : '私有'}\n`);

// 1) gh 可用且已登录
const ghVersion = run(GH, ['--version'], { quiet: true });
if (ghVersion.status !== 0) {
  fail('没有找到 gh CLI。', '安装：https://cli.github.com —— 装好后运行 `gh auth login` 登录，再执行本脚本。');
}
const ghAuth = run(GH, ['auth', 'status'], { quiet: true });
if (ghAuth.status !== 0) {
  fail('gh CLI 尚未登录。', '先运行 `gh auth login`（推荐用浏览器授权），然后重新执行本脚本。');
}
const userJson = run(GH, ['api', 'user'], { quiet: true });
if (userJson.status !== 0) fail('无法读取 GitHub 账号信息。', '确认网络与 gh 登录状态。');
let login;
let id;
try {
  // 只取 login 与 id，其余字段（如邮箱）一律忽略、不打印
  ({ login, id } = JSON.parse(userJson.stdout));
} catch {
  fail('解析 GitHub 账号信息失败。', '可尝试手动执行 `gh api user` 看看返回。');
}
process.stdout.write(`GitHub 账号：${login}\n`);

// 2) 提交身份：默认用 noreply 邮箱，绝不使用真实邮箱
const currentEmail = (run(GIT, ['config', 'user.email'], { quiet: true }).stdout || '').trim();
const currentName = (run(GIT, ['config', 'user.name'], { quiet: true }).stdout || '').trim();
const looksLikePlaceholder = !currentEmail || /your-github-id|example\.(com|invalid)|noreply@example/i.test(currentEmail);
if (looksLikePlaceholder) {
  const noreply = `${id}+${login}@users.noreply.github.com`;
  run(GIT, ['config', '--local', 'user.name', login]);
  run(GIT, ['config', '--local', 'user.email', noreply]);
  process.stdout.write(`提交身份已设为：${login} <${noreply}>（GitHub noreply，不暴露真实邮箱）\n`);
} else {
  process.stdout.write(`沿用现有提交身份：${currentName} <${currentEmail}>\n`);
}

// 3) 脱敏体检
process.stdout.write('\n运行发布前脱敏体检…\n');
const audit = run(process.execPath, [path.join(ROOT, 'scripts', 'audit-public.mjs')], { quiet: true });
process.stdout.write(audit.stdout || '');
if (audit.status !== 0) {
  fail('脱敏体检未通过，已中止发布。', '先按上面的提示清理，再重新执行本脚本。');
}

// 4) 确认
if (!SKIP_CONFIRM) {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = (await rl.question(`\n将在你的账号 ${login} 下创建${VISIBILITY === '--public' ? '公开' : '私有'}仓库「${REPO_NAME}」并把代码推上去。确认？(y/N) `))
    .trim()
    .toLowerCase();
  rl.close();
  if (answer !== 'y' && answer !== 'yes') fail('已取消，未做任何改动。');
}

// 5) 提交（如果还有未提交内容）
run(GIT, ['add', '-A']);
const staged = run(GIT, ['diff', '--cached', '--quiet'], { quiet: true });
if (staged.status !== 0) {
  const commit = run(GIT, ['commit', '-m', COMMIT_MESSAGE], { quiet: true });
  if (commit.status !== 0) fail('提交失败。', (commit.stderr || '').trim().split('\n')[0]);
  process.stdout.write(`\n已提交：${COMMIT_MESSAGE}\n`);
} else {
  process.stdout.write('\n没有需要提交的改动。\n');
}
run(GIT, ['branch', '-M', 'main']);

// 6) 建仓库 + 推送（github.com 连不通时自动改走 API）
const fullName = `${login}/${REPO_NAME}`;
const repoExists = run(GH, ['api', `/repos/${fullName}`], { quiet: true }).status === 0;
if (!repoExists) {
  process.stdout.write('\n创建仓库…\n');
  const create = run(GH, ['repo', 'create', REPO_NAME, VISIBILITY, '--description', DESCRIPTION], { quiet: true });
  process.stdout.write(create.stdout || '');
  if (create.status !== 0) {
    fail(
      '创建仓库失败。',
      `${(create.stderr || '').trim().split('\n')[0]}\n   换个名字：npm run publish:github -- --name 另一个名字`
    );
  }
}

if (run(GIT, ['remote', 'get-url', 'origin'], { quiet: true }).status !== 0) {
  run(GIT, ['remote', 'add', 'origin', `https://github.com/${fullName}.git`]);
}

process.stdout.write('\n推送…\n');
const push = run(GIT, ['push', '-u', 'origin', 'HEAD'], { quiet: true });
if (push.status === 0) {
  process.stdout.write(push.stdout || '');
} else {
  const reason = (push.stderr || '').trim().split('\n').slice(-1)[0];
  process.stdout.write(`   git push 不通（${reason}）\n   改用 GitHub API 通道上传…\n`);
  pushViaApi(fullName, readLocalCommitMeta());
}

// 7) 补上 Topics 并回显地址
run(GH, ['repo', 'edit', '--add-topic', TOPICS.join(',')], { quiet: true });
const urlResult = run(GH, ['repo', 'view', '--json', 'url', '--jq', '.url'], { quiet: true });
const url = (urlResult.stdout || '').trim() || `https://github.com/${login}/${REPO_NAME}`;

process.stdout.write(
  `\n✅ 发布完成：${url}\n` +
    `   标题（About）：${DESCRIPTION}\n` +
    `   Topics：${TOPICS.join(', ')}\n` +
    `   建议随后在仓库 Settings 里确认描述与议题，并检查 README 渲染效果。\n\n`
);
