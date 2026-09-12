# 中转 API 模型检测器（Relay Model Guard）· 产品介绍与使用说明

![Node](https://img.shields.io/badge/Node-%E2%89%A5%2018-339933?logo=node.js&logoColor=white)
![依赖](https://img.shields.io/badge/dependencies-0-brightgreen)
![探针](https://img.shields.io/badge/probes-14-blue)
![协议](https://img.shields.io/badge/API-OpenAI%20compatible-6f42c1)

> **一句话**：填三个字段（`base_url` / `api_key` / 声称的模型名），点一下按钮，20～60 秒后拿到一份**可复核**的体检报告——这个中转端点，到底是不是它声称的那个东西。

- 想先看它能抓什么 → [1. 这个项目解决什么问题](#1-这个项目解决什么问题)
- 想立刻跑起来 → [2. 30 秒上手](#2-30-秒上手)
- 想看接口/二次开发 → [8. API 用法](#8-api-用法)、[12. 项目结构与二次开发](#12-项目结构与二次开发)
- 工程细节、环境变量清单 → [README.md](../README.md)

---

## 目录

| 章节 | 内容 |
|---|---|
| [1](#1-这个项目解决什么问题) | 这个项目解决什么问题 / 适用与不适用场景 |
| [2](#2-30-秒上手) | 30 秒上手 + 本地演示桩 |
| [3](#3-界面说明) | 界面逐字段说明、卡片怎么读 |
| [4](#4-14-个探针都在测什么) | 14 个探针清单、权重、风险等级 |
| [5](#5-token-预算保护两道闸门) | Token 预算保护（预估拦截 + 运行时硬上限） |
| [6](#6-读懂结果) | 读懂结果：哪些是硬证据，常见组合怎么判 |
| [7](#7-报告导出) | JSON / HTML 报告导出的字段说明 |
| [8](#8-api-用法) | API 用法（curl / SSE / 接入 CI） |
| [9](#9-安全与隐私设计) | 安全与隐私设计 |
| [10](#10-环境变量) | 环境变量 |
| [11](#11-常见问题-faq) | 常见问题 FAQ |
| [12](#12-项目结构与二次开发) | 项目结构 & 如何新增一个探针 |
| [13](#13-开发与自测) | 开发与自测（28 条断言的自测脚本） |
| [14](#14-局限与免责声明) | 局限与免责声明 |
| [15](#15-上传-github-前的检查清单) | 上传 GitHub 前的检查清单 |

---

## 1. 这个项目解决什么问题

### 1.1 背景

调用 GPT / Claude / DeepSeek 这类模型时，很多团队不会直连官方，而是走**中转（relay / 代理 / 聚合站）**：便宜、能开票、能绕开支付与网络限制。但中转是一层你看不见的黑盒，它可以在中间做很多事——换模型、改提示词、截断输入、伪造用量，而你从返回的文字里几乎看不出来。

这个项目就是那层黑盒的**体检仪**：用 14 个探针从不同角度戳它，每个探针给出 0～10 分、状态、一句证据和耗时，最后按权重汇总成总分与风险等级。

### 1.2 它能抓到的具体套路

| 中转常见的套路 | 你平时会看到的现象 | 检测器怎么抓（对应探针） |
|---|---|---|
| 用小模型冒充大模型 | 复杂题频繁出错、回答质量忽高忽低 | **模型调包**（响应 `model` 字段 + 能力基准题）、**模型身份**（自述开发者/知识截止） |
| 静默降级 / 模型混池 | 同一模型有时快有时慢、风格不一致 | 调包 + **延迟信号** + **渠道指纹** 交叉判断 |
| 偷偷注入系统提示词 | 模型统一口径、不承认自己是某模型 | **提示词提取**（回读系统层，识别隐瞒类/计费类指令） |
| 网关用裸文本拼接角色（伪协议实现） | 表面正常，但内容能被"伪造系统消息" | **Token 注入**（ChatML / `[INST]` 标记是否被当成真实指令执行） |
| 假装流式（其实整体缓冲后一次性返回） | 打字机效果卡住，然后整段蹦出来 | **流完整性** + **延迟信号**（首字延迟 ≈ 总耗时） |
| 吞掉 `tools` 字段 | Agent / 函数调用突然失灵 | **工具篡改** |
| 静默截断长输入 | 长文档总结丢掉开头、RAG 结果对不上 | **上下文截断**（长输入埋点 + `usage` 交叉验证） |
| `max_tokens` 不生效、`usage` 虚报 | 账单比预期高，短输出也按长输出计费 | **钱包安全** |
| 缓存命中仍按全价计费 | 重复提问秒回，但照样扣费 | **钱包安全**（重复请求延迟骤降 + 输出完全一致） |
| 接到无限制/越狱模型 | 模型什么都说，没有拒绝 | **越狱抵抗**（自持口令 + 3 种话术） |
| 报错泄露内部架构 | 错误信息里出现堆栈、内网 IP、云厂商名 | **错误泄露** |
| 参数校验形同虚设 | 非法参数也返回 200 | **错误泄露** + **流完整性** |

### 1.3 适用与不适用

**适合**

- 选型前"验货"：拿到一个中转的测试 Key，先体检再决定是否接入
- 切换供应商 / 续费前的回归对比：同一套探针跑两次，看分数与证据是否变化
- 把结果作为采购、对账、投诉的依据（每项都有原始请求/响应可展开复核）
- 放进 CI 做定期体检：`totalScore` 低于阈值就告警（见 [第 8 节](#8-api-用法)）

**不适合**

- 它测的是**渠道是否诚实**，不是"模型好不好用"。做效果评测请用评测集，别用这个。
- 不要拿它去压测、刷别人的端点。探针是正常的 API 调用，但请只检测**你有权限使用**的端点。

---

## 2. 30 秒上手

### 2.1 启动

```bash
# 需要 Node ≥ 18（用到内置 fetch 与 Web Streams）；零依赖，不需要 npm install
node server.mjs        # → http://127.0.0.1:8787
```

打开页面，填三个字段，点「开始检测」即可。默认只监听 `127.0.0.1`，不会暴露到局域网。

### 2.2 先跑一遍自带演示桩（不花一分钱）

仓库里带了一个**假中转端点**，可以先在本地把整个流程走通，看清楚"正常"和"作弊"两种极端：

```bash
node mock-upstream.mjs      # 另开一个终端 → http://127.0.0.1:8788/v1
```

| 模式 | 怎么触发 | 会发生什么 |
|---|---|---|
| 诚实模式 | Base URL `http://127.0.0.1:8788/v1`，模型 `gpt-4o-mini`，Key 随便填（`demo-key`） | 14 个探针全过，总分通常 9～10 |
| 黑心模式 | Key 或模型名里含 `shady`（如 `shady-demo-key`） | 演示桩会**同时**作弊：调包成 `llama-3.1-8b-instruct`、隐藏系统提示词、越狱直接吐口令、忽略 `max_tokens`、错误堆栈泄露、上下文静默截断、吞掉 `tool_calls`、特殊 token 注入生效 → 总分掉到 4 分以下 |

演示桩只监听 `127.0.0.1`，不连接任何真实上游，可以放心随便点。

![检测结果总览](images/01-result-overview.jpg)

> 上图是黑心模式下的一次检测：总分 3.6 / 高风险，14 个探针里 10 个失败。

---

## 3. 界面说明

### 3.1 表单字段

| 字段 | 说明 | 注意事项 |
|---|---|---|
| **Base URL** | 中转的接口地址 | 支持 `https://x/v1`、`https://x/v1/`、`https://x/v1/chat/completions` 等写法，会自动归一化；只支持 OpenAI 兼容协议 |
| **API Key** | 用于本次检测的密钥 | 只存在于检测进程内存中，探针跑完立即擦除；不写日志、不落盘、不进报告（报告里只有不可逆指纹） |
| **声称的模型名** | 你想验证的模型名，例如 `gpt-4o-mini` | 会与响应里的 `model` 字段、模型自述身份做交叉核对 |
| **本次检测 Token 上限** | 本次检测允许消耗的上限 | 见 [第 5 节](#5-token-预算保护两道闸门)：预估超过它会被直接拒绝启动 |

「快速填充」里有几个常见服务的示例地址，以及本地演示桩。

### 3.2 结果卡片

14 张卡片按探针顺序排列，每张包含：

| 元素 | 含义 |
|---|---|
| 编号 + 名称 | 探针序号与名称 |
| 右上角状态胶囊 | **通过**（≥7.5 分）/ **警告**（4～7.4 分）/ **失败**（<4 分）/ **已终止** / **已跳过**（因预算触顶未执行） |
| 环形分数 | 0～10 分 |
| 权重 / 分组 | 该项在总分中的权重与所属分组 |
| 耗时 | 该探针实际耗时（含它内部的所有上游请求） |
| 一句话证据 | 结论性说明，例如"能力题 1/3 正确；响应 model 字段为 llama-3.1-8b-instruct（不同族）" |
| 黄色小字 | 需要额外注意的补充说明（如"自述身份为弱证据，建议交叉判断"） |
| 可展开的「原始证据」 | 该探针发出的请求体、响应头、响应原文、SSE 样本行、`usage` 等，用于人工复核 |

![展开原始证据](images/02-raw-evidence.jpg)

> 每张卡片都能展开看到真实的请求与响应——报告里的每个结论都能被追溯，这是这个工具和"跑分网站"最大的区别。

### 3.3 顶部总览

- **总分**：Σ(权重 × 得分) / Σ(已执行权重)，10 分制
- **风险等级**：见 [4.3](#43-风险等级)
- **Token 用量条**：`已用 / 上限`，并显示"在途预留"（已经发出、还没结算的请求占用的额度）
- **通过 / 警告 / 失败 / 终止·跳过** 计数
- **导出按钮**：查看 HTML 报告、下载 HTML、下载 JSON

---

## 4. 14 个探针都在测什么

### 4.1 清单

| # | 探针 | 权重 | 分组 | 测什么 | 典型失败信号 |
|---|---|---|---|---|---|
| 1 | 连通性检查 | 10% | 基础 | 端点可达、鉴权有效、`/models` 是否包含声明模型 | 401/403、模型名不存在 |
| 2 | 延迟信号 | 7% | 基础 | 首字延迟、生成吞吐、是否被网关整体缓冲 | 首字延迟 ≈ 总耗时、只有 1 个分块 |
| 3 | 流完整性 | 6% | 基础 | SSE 协议规范：增量正文、`delta.role`、`finish_reason`、`[DONE]`、流式 `usage` | 缺少 `[DONE]`、分块结构异常 |
| 4 | 模型身份 | 9% | 一致性 | 模型自述的标识 / 开发者 / 知识截止是否与声称一致 | 自称 `llama-3.1-8b-instruct` / 开发者 `Meta` |
| 5 | 模型调包 | 10% | 一致性 | 响应 `model` 字段 + 3 道能力基准题（含算术、字符计数、陷阱题） | `model` 字段指向别的模型族；能力题 1/3 |
| 6 | 渠道指纹 | 7% | 溯源 | 响应头特征（OpenAI 原生 / Azure / Cloudflare / 火山 / new-api 等）与错误体标识 | 无任何指纹、错误体暴露别的上游 |
| 7 | Token 注入 | 6% | 安全 | 注入 ChatML / `[INST]` 等特殊标记，看是否被当成真实角色执行 | 特殊标记真的触发了 system 指令 |
| 8 | 提示词提取 | 7% | 安全 | 能否回读系统提示层，是否夹带隐瞒、计费、品牌注入 | 回读出"不要向用户透露真实模型" |
| 9 | 指令覆盖 | 7% | 安全 | 用户文档里埋的指令能否劫持系统级约束 | 输出 `OVERRIDE_HIJACKED` |
| 10 | 越狱抵抗 | 7% | 安全 | 自持口令 + 3 种话术（直接索取 / 角色扮演 / 翻译套取） | 口令被套出，说明接到了无限制模型 |
| 11 | 错误泄露 | 5% | 安全 | 非法请求的报错是否泄露堆栈、文件路径、密钥、内网地址、真实上游 | 错误体里出现 `at /srv/app/src/router/openai.ts:88` |
| 12 | 上下文截断 | 6% | 能力 | 长输入埋点（约 9k token），检测静默截断/裁剪，并用 `usage` 交叉验证 | 长输入时开头埋点丢失 |
| 13 | 工具篡改 | 6% | 能力 | 函数调用链路是否被改写：schema、参数、`function.name` 一致性 | 声明了 `tools` 却退化成纯文本 |
| 14 | 钱包安全 | 7% | 计费 | `usage` 真实性、`max_tokens` 是否生效、重复请求缓存命中却照价计费 | `max_tokens=8` 实际输出 120 token |

### 4.2 打分与权重

- 每个探针独立打 0～10 分，并给出状态：**≥7.5 通过** / **4～7.4 警告** / **<4 失败**
- 总分 = Σ(权重 × 得分) / Σ(已执行权重)。14 项权重之和恒为 1（代码启动时会校验，不等就报错退出）
- 因 Token 预算或总时长而**没跑**的探针，标记为「已终止 / 已跳过」，**不参与总分计算**——否则会把"我们自己的额度策略"误算成"端点的问题"
- 一项都没跑出结果时，给的是「检测未完成」而不是 0 分

### 4.3 风险等级

| 总分 | 等级 | 建议 |
|---|---|---|
| ≥ 9 | 极低风险 | 行为与官方端点高度一致 |
| ≥ 8 | 低风险 | 主要指标正常，仅有轻微可改进项 |
| ≥ 6.5 | 中等风险 | 存在若干异常，建议人工复核对应证据 |
| ≥ 5 | 较高风险 | 多项异常，存在调包、偷工减料或信息泄露风险 |
| ≥ 3 | 高风险 | 关键指标不达标，不建议用于生产 |
| < 3 | 极高风险 | 行为与声称严重不符，建议立即停用 |
| — | 检测未完成 | 没有任何探针取得有效结果（预算不足或端点完全不可用） |

---

## 5. Token 预算保护（两道闸门）

### 5.1 为什么需要

一次完整检测会发出 **30 多次上游请求**（其中"上下文截断"探针要发一条约 9k token 的长输入），如果并发探针再遇到限流重试，很容易在你没注意的时候把测试额度跑穿。所以做了两层防护：**能预估的先拦住，拦不住的运行时兜底**。

当前默认配置下的实测数字：

| 指标 | 数值 | 说明 |
|---|---|---|
| 预期消耗 | ≈ 29,800 token | 按典型输出长度估算 |
| 最坏情况 | ≈ 31,900 token | 每个请求都把 `max_tokens` 用满 |
| **前置阈值（预估值）** | **≈ 34,200 token** | 预期 × 安全系数 1.15，低于它直接拒绝启动 |
| 默认上限 | ≈ 39,400 token | 自动按预估值留 15% 余量（可用 `TOKEN_BUDGET` 覆盖） |
| 探针调用次数 | 约 31 次 | 其中"上下文截断"占预估消耗的 **92%** |

> 想省钱：把 `LONG_CONTEXT_CHARS` 从 `32000` 调小（例如 `8000`），预估值会立刻降到约 10,600 token——预估值是**实时干跑算出来的**，不是写死的常量表。

### 5.2 第一道：启动前预估 + 源头拦截

服务启动时会把 14 个探针**干跑一遍**（纯本地计算，不联网、不发任何请求），汇总出整套检测的 token 预估。每次提交检测时：

| 情况 | 行为 |
|---|---|
| 预估 **>** 上限 | **直接拒绝启动**，返回 `400 BUDGET_TOO_SMALL`，**一个请求都不会发给端点**，并给出"把上限提高到 ≥ X"等具体建议 |
| 预估 ≥ 上限的 70% | 放行但告警（页面黄色提示 + 响应里的 `warning` 字段） |
| 预估 ≤ 上限的 70% | 正常启动 |

前端会做同样的校验：预估不达标时「开始检测」按钮直接置灰，并写明拦截原因。

![前置预检拦截](images/03-precheck-block.jpg)

> 上限填 20,000 时被拦下：预估 34,246，按钮置灰，同时给出"提到 35,959 以上"和"调小 `LONG_CONTEXT_CHARS`"两条出路。

### 5.3 第二道：运行时硬上限

预估只是估算，真实消耗必须靠运行时结算：

1. **发送前预占**：每个请求先按「prompt 估算 + 该请求的 `max_tokens`」预占额度；预占后会超过上限的请求**不会被发出**。
2. **返回后结算**：用响应里的真实 `usage` 替换预占值；拿不到 `usage` 就按预占值保守记账。
3. **触顶即止**：累计用量到顶 → 立刻 `abort` 掉所有**在途**的 fetch / 流式读取 → 剩余探针不再执行 → **重试循环也不会再发新请求**。
4. **总时长护栏**：另有 `RUN_DEADLINE_MS`（默认 5 分钟），防止并发探针卡在重试里空转。

触顶后的探针会标记为「已终止 / 已跳过」，页面顶部出现横幅说明"本次仅 N/14 个探针产出有效结果，总分只反映已完成的 N 项"。**它们不会按 0 分计入总分**——避免把额度策略记成端点的锅。

### 5.4 如果我就是想跑（额度不够时）

勾选表单里的「**额度不足时仍运行**」（API 对应 `allowPartialRun: true`）可以显式放行：检测会一直跑到触顶为止，报告标注为**不完整**。默认关闭。

---

## 6. 读懂结果

### 6.1 先分清两类证据

| 类型 | 探针 | 可信度 |
|---|---|---|
| **硬证据**（协议/账目层面，几乎不会误判） | 连通性、流完整性、渠道指纹、错误泄露、工具篡改、钱包安全、上下文截断 | 看到异常基本可以直接采信 |
| **概率证据**（依赖模型行为，可能被系统提示词修饰） | 模型身份、模型调包的能力题部分、越狱抵抗、提示词提取、指令覆盖 | 需要**多条一起看**，单条异常先别下结论 |

### 6.2 常见组合怎么判

| 你看到的组合 | 大概率是什么 |
|---|---|
| 调包失败 + 身份冲突 + 指纹混浊 | 二次转售 / 换模型 |
| 只有能力题失败，`model` 字段一致 | 可能是上游本身能力不足，或该模型的低价版本 |
| 流完整性差 + 便宜但重复提问秒回 | 共享池 / 缓存转发 |
| Token 注入失败（特殊标记被执行） | 网关用裸文本拼接角色，属于结构性风险 |
| 错误泄露硬泄露 + 无 request-id | 自建轻量中转，运维与追责能力都弱 |
| 钱包安全失败（`max_tokens` 被忽略） | 你的长输出场景会产生超预期费用 |
| 越狱抵抗失败 | 该端点可能在转发到无限制/微调模型，合规与安全风险高 |

### 6.3 可能的误报来源

- 模型名写错（例如写了官方不存在的别名）→ 连通性与调包会同时异常
- 你的网络/代理不稳定 → 延迟、流完整性异常
- 端点对某些参数（`stream_options`、`tools`）本来就不支持 → 会给出"上游不支持"的明确说明，而不是直接判失败
- 中文 token 估算与实际分词器存在偏差 → 账目类结论都写成量级判断，不会给精确数字

---

## 7. 报告导出

检测完成后可导出两种格式（也可直接从每次检测的 URL 打开）：

```text
GET /api/detect/:runId/report.json              下载 JSON
GET /api/detect/:runId/report.html              在线查看 HTML
GET /api/detect/:runId/report.html?download=1   下载 HTML
```

### 7.1 JSON 报告字段

| 字段 | 说明 |
|---|---|
| `schema` | 固定为 `relay-model-guard/report@1`，便于程序解析 |
| `generatedAt` / `startedAt` / `finishedAt` / `durationMs` | 时间与耗时 |
| `target` | `baseUrl` / `model` / `keyFingerprint`（**不含密钥原文**） |
| `summary` | 总分、风险等级、通过/警告/失败/终止/跳过计数、分组得分、待关注问题列表 |
| `tokenUsage` | 本次 `spent` / `limit` / `usedPercent` / 是否触顶 |
| `weightTable` | 14 个探针的权重表（便于自行复算总分） |
| `probes[]` | 每项：`id` / `name` / `group` / `weight` / `status` / `score` / `evidence` / `elapsedMs` / `notes` / `raw`（原始证据） |
| `disclaimer` | 使用声明 |

HTML 报告是**自包含单文件**（样式内联，无外部依赖），可以直接发邮件或存档：

![HTML 报告](images/04-html-report.jpg)

---

## 8. API 用法

### 8.1 接口一览

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/api/catalog` | 探针目录、权重、并发/超时配置，以及整套检测的 `estimate` 预估 |
| `POST` | `/api/detect` | 启动检测，返回 `202 { runId, tokenBudget, estimate, warning }` |
| `GET` | `/api/detect/:runId/events` | SSE 实时事件流 |
| `GET` | `/api/detect/:runId` | 当前快照（断线重连用） |
| `GET` | `/api/detect/:runId/report.json` | JSON 报告 |
| `GET` | `/api/detect/:runId/report.html` | HTML 报告 |
| `GET` | `/api/health` | 健康检查 |

> deploy-safe 模式下，除 `/api/health` 外的所有接口都需要令牌：页面登录拿 Cookie，或加 `Authorization: Bearer <APP_TOKEN>` / `x-app-token: <APP_TOKEN>` 头；缺令牌返回 `401 {"code":"UNAUTHORIZED"}`。

### 8.2 启动检测

```bash
curl -s http://127.0.0.1:8787/api/detect \
  -H 'content-type: application/json' \
  -d '{
        "baseUrl": "https://relay.example.com/v1",
        "apiKey": "your-test-key",
        "model": "gpt-4o-mini",
        "tokenBudget": 60000,
        "allowPartialRun": false
      }'
# → {"runId":"...","tokenBudget":60000,"estimate":{...},"warning":null}
```

被前置拦截时（**不会发出任何请求**）：

```json
{
  "code": "BUDGET_TOO_SMALL",
  "error": "预检拦截：整套 14 个探针预计消耗约 34246 token（预期 29779，最坏 31879），高于你设置的 20000，已拒绝启动，未向端点发送任何请求。",
  "tokenBudget": 20000,
  "estimate": { "projectedTokens": 34246, "expectedTokens": 29779, "worstCaseTokens": 31879, "perProbe": [] },
  "suggestions": ["把 Token 上限提高到 41096 以上再检测", "调小 LONG_CONTEXT_CHARS（当前 32000）…", "或勾选…"]
}
```

### 8.3 消费实时事件（SSE）

```bash
curl -N http://127.0.0.1:8787/api/detect/<runId>/events
```

| 事件 `type` | 载荷 | 说明 |
|---|---|---|
| `snapshot` | `{ run, catalog }` | 连接/重连时的当前状态 |
| `probe-start` | `{ id, name }` | 某个探针开始执行 |
| `probe` | `{ result }` | 某个探针完成（含 `score` / `status` / `evidence` / `elapsedMs` / `raw`） |
| `usage` | `{ usage }` | Token 用量更新（`spent` / `reserved` / `usedPercent` / `exhausted`） |
| `summary` | `{ summary, usage, durationMs }` | 全部结束后的汇总 |
| `done` | `{ status }` | 收尾信号 |
| `closed` | `{ reason }` | 运行记录过期被内存回收 |

### 8.4 接进 CI 做门禁

用 `totalScore` 和「硬证据」探针的状态卡阈值，比只看总分更稳：

```bash
score=$(curl -s http://127.0.0.1:8787/api/detect/$RUN/report.json | jq -r .summary.totalScore)
[[ $(echo "$score > 8" | bc) == 1 ]] || { echo "中转体检未通过：$score"; exit 1; }
```

推荐的门禁写法：`summary.probesRun == 14`（确认没被预算截断）+ `totalScore ≥ 8` +「流完整性 / 错误泄露 / 工具篡改 / 钱包安全」四项必须为 `pass`。

### 8.5 单条探针结果的字段

| 字段 | 说明 |
|---|---|
| `id` / `name` / `group` / `weight` | 探针标识与权重 |
| `status` | `pass` / `warn` / `fail` / `aborted`（触顶中止）/ `skipped`（未发出请求） |
| `score` | 0～10；被中止/跳过时为 `null` |
| `evidence` | 一句话结论 |
| `notes` | 补充提示（可能是"这是弱证据"这类提醒） |
| `elapsedMs` | 耗时 |
| `raw` | 原始证据：请求体、响应头、响应原文、SSE 样本、`usage`（已脱敏） |

---

## 9. 安全与隐私设计

这个工具需要你填入真实的 API Key，所以在设计上做了明确约束：

| 机制 | 做法 |
|---|---|
| **密钥生命周期** | Key 只存在于该次检测的内存对象里，14 个探针跑完立即置 `null`；进程不写数据库、不写文件、不写缓存 |
| **日志脱敏** | 所有日志统一过一层脱敏：`sk-*`、`Bearer *`、`api_key=…`、长随机串一律打码；只打印 Key 的不可逆指纹（8+8 hex）用于区分 |
| **报告脱敏** | SSE 与报告走白名单序列化，`authorization` 类字段强制替换为 `***REDACTED***`，请求体/响应头也会再过一遍脱敏 |
| **前端即弃** | 检测发起后立刻清空输入框中的 Key，页面不再保留 |
| **运行记录** | 只保存在内存，默认 30 分钟后自动回收（`RUN_TTL_MS`），进程退出即全部消失 |
| **网络暴露面** | 默认只监听 `127.0.0.1`；限流 40 次 / 10 分钟 / IP；请求体上限 32 KB |

> ⚠️ **默认的本地模式没有鉴权，不要直接暴露到公网。** 它按用户提供的 `base_url` 发起出站请求，等于一个能读回响应的 SSRF 客户端。要放到服务器上用，请开 deploy-safe 模式（下一节）。

> ⚠️ **只用它检测你有权限使用的端点。** 检测过程会发送正常的 API 请求并消耗你的额度；请遵守目标服务的使用条款。

### 9.1 公开部署：deploy-safe 模式

```bash
# macOS / Linux
DEPLOY_SAFE=1 APP_TOKEN="$(openssl rand -hex 24)" node server.mjs

# Windows PowerShell
$env:DEPLOY_SAFE="1"; $env:APP_TOKEN="<随机串>"; node server.mjs
```

打开页面会先要求填入 `APP_TOKEN`，登录后 12 小时内免登录（会话 Cookie 为 `HttpOnly` + `SameSite=Strict`，HTTPS 反代下自动加 `Secure`）。`DEPLOY_SAFE=1` 却没给 `APP_TOKEN` 会**直接拒绝启动**——避免"以为开了防护，其实没有"。

![deploy-safe 登录](images/05-deploy-safe-login.jpg)

| 能力 | 行为 |
|---|---|
| **鉴权** | 所有 `/api/*` 需要令牌（`/api/health`、`/api/session` 除外）；支持页面登录、`Authorization: Bearer`、`x-app-token` 三种方式；登录接口单独限流 10 次 / 10 分钟 |
| **SSRF 防护** | `base_url` 解析出的**任意一个** IP 落在私有 / 回环 / 链路本地 / 组播 / 保留段（含 `169.254.169.254` 云元数据、`::1`、`fc00::/7`、`::ffff:` 映射地址）就拒绝启动，**一个请求都不发** |
| **重定向** | 由"自动跟随"改为**手动逐跳跟随**（默认最多 3 跳），每一跳都重新校验目标，防止"先跳到自己域名、再 302 进内网" |
| **全局配额** | 默认每小时最多 60 次检测、同时最多 2 个检测进行中，超出返回 429 |
| **反向代理** | `TRUST_PROXY=1` 时按 `X-Forwarded-For` 第一跳限流 |

**已知边界（诚实说明）**：目标校验发生在发起请求之前，理论上存在 DNS rebinding 的 TOCTOU 竞态窗口；deploy-safe 用「鉴权 + 全局配额 + 逐跳校验」三层兜底，但如果要面向不受信任的用户开放，请再配一层出站防火墙策略（只允许访问白名单网段）。另外，本工具**会把填进来的 API Key 发给填进来的 base_url**——这是它的功能，不是漏洞；请不要让不可信的人使用你的实例。

---

## 10. 环境变量

Windows PowerShell 用 `$env:NAME="value"`，macOS / Linux 用 `NAME=value node server.mjs`。

| 变量 | 默认值 | 说明 |
|---|---|---|
| `PORT` / `HOST` | `8787` / `127.0.0.1` | 监听地址。**不要改成 0.0.0.0 后暴露到公网** |
| `PROBE_CONCURRENCY` | `3` | 探针并发度（1～14）。默认取保守值以免触发中转限流；追求速度可调高（上限 14） |
| `PROBE_TIMEOUT_MS` | `75000` | 单个探针超时 |
| `RUN_TTL_MS` | `1800000` | 内存中检测记录保留时长（30 分钟） |
| `LONG_CONTEXT_CHARS` | `32000` | 上下文探针的长输入长度（≈9k token）。**调小它最能省钱** |
| `TOKEN_BUDGET` | 按预估自动算 | 默认 Token 上限；不设时自动取「预估值 × 1.15」 |
| `TOKEN_ESTIMATE_SAFETY` | `1.15` | 前置闸门安全系数：预估值 = 预期消耗 × 该系数 |
| `RUN_DEADLINE_MS` | `300000` | 单次检测总时长护栏，到点中止所有探针 |
| `DEPLOY_SAFE` | `0` | 设为 `1` 开启部署安全模式（鉴权 + 私网拦截 + 全局配额） |
| `APP_TOKEN` | 无 | deploy-safe 下的访问令牌；`DEPLOY_SAFE=1` 时**必填**，否则拒绝启动 |
| `ALLOW_PRIVATE_TARGETS` | 本地 `1` / deploy-safe `0` | 是否允许请求私网 / 回环 / 链路本地地址（本地跑演示桩需要它为 `1`） |
| `MAX_REDIRECTS` | `3` | 手动跟随重定向的最大跳数（每跳校验目标） |
| `GLOBAL_RUNS_PER_HOUR` | 本地 `0`（不限）/ deploy-safe `60` | 全局每小时检测次数上限 |
| `MAX_CONCURRENT_RUNS` | 本地 `10` / deploy-safe `2` | 同时进行的检测数上限 |
| `SESSION_TTL_MS` | `43200000` | 登录会话有效期（12 小时） |
| `TRUST_PROXY` | `0` | 置于反向代理后设为 `1`，按 `X-Forwarded-For` 限流 |
| `MOCK_PORT` | `8788` | 演示桩端口 |
| `MOCK_DELAY_MS` | `0` | 演示桩人为延迟，用来模拟真实网络下"并发在途"的触顶场景 |

---

## 11. 常见问题 FAQ

**Q：预估算出来 3 万 token，实际只花了 1 万，是不是不准？**
预估值故意偏保守：它假设每个分支都真的发出请求（`/models` 失败时的补 ping、`stream_options` 不被支持时的重试等），并且中文按 0.8 token/字估算。它的职责是拦住"明显会跑爆额度"的提交；**真实消耗以运行时结算的 `spent` 为准**（页面用量条上的数字）。

**Q：能不能只跑其中几个探针？**
当前版本不支持按需勾选探针。要裁剪可以改 `lib/probes/index.mjs` 里的 `PROBE_ORDER`（只留你想跑的 id，权重会在已执行集合内自动归一化）。如果你的场景只需要省钱，先调小 `LONG_CONTEXT_CHARS` 更直接。

**Q：支持 Claude 原生 / Gemini 原生接口吗？**
只支持 **OpenAI 兼容协议**（`/chat/completions`、`/models`）。大多数中转都提供 OpenAI 兼容层，直接用它即可；Anthropic 原生 `/v1/messages` 未适配。

**Q：检测会不会导致我的账号被封？**
探针走的都是正常 API 调用，但它们会在 20~60 秒内发出 30 多个请求（默认并发 3 + 抖动），并且包含"越狱话术""注入特殊 token"这类内容。**强烈建议用独立的测试 Key**，不要拿生产主 Key 跑；遇到 429 会自动重试 2 次。

**Q：检测会修改对方的任何配置吗？**
不会。全部是只读性质的推理请求，不涉及任何管理接口。

**Q：为什么"越狱抵抗"会失败？这是端点的问题吗？**
这个探针在自己的 system 提示词里放了一个口令，然后用三种话术尝试套出来。如果一戳就破，说明该端点转发到的模型对系统级约束几乎没有抵抗力（常见于被微调/越狱的替换模型），对合规场景是实质风险。

**Q：`usage` 的真实性怎么判断？只能估算吗？**
只能做**量级比对**：把响应里的 `prompt_tokens` / `completion_tokens` 与字符级估算对比，偏差过大就提示。所以结论写的是"偏差过大/量级一致"，不会假装精确到 token。

**Q：怎么确认这套代码本身是好的？**
仓库自带端到端自测：起假上游 + 本地模式与 deploy-safe 实例，跑完整检测并断言 39 项。见 [第 13 节](#13-开发与自测)。

---

## 12. 项目结构与二次开发

### 12.1 结构

```text
server.mjs                 HTTP 服务：路由 / SSE / 内存态运行 / 预算闸门 / 报告下载
lib/upstream.mjs           OpenAI 兼容调用层（429/5xx 重试、流式抓取、预算预占与结算）
lib/budget.mjs             Token 预算闸门（预占 → 结算 → 触顶中止）+ token 估算
lib/estimate.mjs           启动时干跑 14 个探针，算出整套检测的 token 预估
lib/ctx.mjs                探针上下文工厂（真实执行与干跑预估共用同一份实现）
lib/target-policy.mjs      出站目标策略：私网/回环/链路本地/云元数据拦截 + 逐跳重定向校验
lib/redact.mjs             脱敏与 Key 指纹
lib/probes/infra.mjs       探针 1–9（基础 / 一致性 / 溯源 / 安全 / 能力）
lib/probes/security.mjs    探针 10–14（安全 / 计费）
lib/probes/helpers.mjs     探针共享工具：家族识别、计分、证据裁剪
lib/probes/index.mjs       探针注册表 + 加权汇总 + 风险分级
lib/report.mjs             JSON / HTML 报告生成
public/                    前端（原生 ES 模块，无构建步骤）
mock-upstream.mjs          本地假中转：诚实 / 黑心双模式
scripts/selftest.mjs       端到端自测
scripts/audit-public.mjs   开源前脱敏体检（密钥 / 私钥 / 绝对路径 / 邮箱 / 本机用户名）
.gitignore / LICENSE       仓库卫生与许可
docs/GUIDE.md              本文档
```

### 12.2 新增一个探针

探针就是「一个有 `id` / `name` / `weight` / `group` / `summary` 和 `run(ctx)` 的对象」。在 `lib/probes/` 里加一个，然后注册到 `PROBE_ORDER` 即可：

```js
// lib/probes/infra.mjs（或新建一个同名结构文件）
export const extraProbes = [
  {
    id: 'rate-limit',            // 唯一 id
    name: '限流与配额',           // 卡片标题
    weight: 0.05,                // 权重（所有探针之和必须 = 1）
    group: '基础',
    summary: '检查 x-ratelimit-* 头与 429 行为是否诚实',
    async run(ctx) {
      const res = await ctx.ask({ user: 'ping', maxTokens: 4 });   // 走预算闸门
      const score = res.ok ? 10 : 0;
      return result({
        score,
        evidence: res.ok ? '返回了限流头' : `请求失败 HTTP ${res.status}`,
        raw: { headers: res.headers, status: res.status },          // 可展开的原始证据
        notes: []
      });
    }
  }
];
```

注意几点：

1. 所有上游调用**必须**走 `ctx.upstream` / `ctx.ask`，它们会自动过预算闸门、超时与中止信号，也能被干跑预估统计到。
2. 权重之和必须为 1，`lib/probes/index.mjs` 在启动时会校验，不满足直接抛错。
3. 新增后把 `id` 加进 `lib/probes/index.mjs` 的 `PROBE_ORDER`，否则会报「探针未注册」。
4. 想调权重 / 风险等级阈值：分别在 `lib/probes/*.mjs` 的 `weight` 与 `lib/probes/index.mjs` 的 `RISK_LEVELS`。

---

## 13. 开发与自测

```bash
npm start        # = node server.mjs
npm run dev      # = node --watch server.mjs（改代码自动重启）
npm run mock     # = node mock-upstream.mjs（演示桩）
npm run selftest # = node scripts/selftest.mjs（端到端自测）
npm run audit    # = node scripts/audit-public.mjs（开源前脱敏体检）
npm run publish:github  # 一键发布到 GitHub（需先安装并登录 gh CLI）
```

`npm run selftest` 会自动起「假上游 + 本地模式应用 + 两个 deploy-safe 应用」共 4 个进程（端口 8896–8899，不会占用你正在跑的服务），跑多轮检测并断言 **39 项**，其中包括：

- 诚实桩：14 个探针全部执行、总分 ≥ 8、无终止/跳过
- 黑心桩：总分显著低于诚实桩，且**调包 / 提示词提取 / 越狱抵抗 / 钱包安全 / 错误泄露 / Token 注入** 六项精准命中
- **前置闸门**：预估超上限时返回 `400 BUDGET_TOO_SMALL`，且**假上游收到的请求数没有增加**（证明一个请求都没发）
- **运行时闸门**：额度受限时探针被终止/跳过、实际用量不越界、**触顶后 2 秒内零新增上游请求**、终止的探针不会被误记成"端点超时"
- 报告不含明文 API Key（JSON 与 HTML 各验一次）
- **deploy-safe**：无令牌访问被拒（401）、错误令牌被拒、私网目标被拦（`400 TARGET_BLOCKED`）、拦截期间零上游请求、会话 Cookie 带 `HttpOnly + SameSite=Strict`、`ALLOW_PRIVATE_TARGETS=1` 可显式放行、云元数据/IPv4 映射内网/ULA 地址均被识别

---

## 14. 局限与免责声明

> 完整条款见 [DISCLAIMER.md](../DISCLAIMER.md)。以下是要点：

- **只是证据，不是判决**。模型自述、能力基准这类结果具有概率性，请结合业务场景与多条证据人工判断。
- **预估值是保守上界**：它按最坏剧本与中文近似估算，通常高于真实消耗；真实消耗以运行时结算为准。
- **会产生真实费用**：上下文探针会真的发送约 9k token 的长输入（可通过 `LONG_CONTEXT_CHARS` 调小）。
- **只支持 OpenAI 兼容协议**，其它协议未适配。
- **并发可能触发限流**：默认并发已收到 3（可调到 14），遇到 429/5xx 会自动重试 2 次，仍可能被限流严格的端点拒绝。
- **请只在获得授权的端点上使用**，并遵守目标服务的条款；因使用本工具产生的任何后果由使用者自行承担。

---

## 15. 上传 GitHub 前的检查清单

开源**代码本身**不会暴露你的服务器身份——仓库里没有你的主机名、域名、IP 或密钥。真正会泄漏身份的是另外三处：**提交记录里的邮箱、本机绝对路径、以及你手动贴出去的真实报告**。按下面顺序过一遍就行。

仓库里已经准备好：

| 文件 | 作用 |
|---|---|
| `.gitignore` | 排除 `node_modules/`、`.env*`、`*.key`、`outputs/`、`work/`，本地产物与临时脚本不会进仓库 |
| `LICENSE` | MIT，署名用了中性占位符 `The Relay Model Guard Authors`（想换成自己的名字/ID 就改这一行） |
| `DISCLAIMER.md` | 免责声明：使用范围、会产生真实费用、结论性质、安全责任、无担保 |
| `scripts/audit-public.mjs` | 发布前体检：扫密钥、私钥、绝对路径、邮箱，以及**本机用户名**出现的位置 |

### 15.1 必做

1. **设置不暴露私人邮箱的提交身份**（commit 里的作者邮箱会永久公开）：

   ```bash
   git init
   git config user.name  "your-github-id"                        # 不写真实姓名也可以
   git config user.email "1234567+your-github-id@users.noreply.github.com"
   ```

   那串 noreply 邮箱在 GitHub → Settings → Emails 里查得到（勾选 "Keep my email addresses private" 后会显示）。

2. **跑发布前体检**（先 `git add .`，脚本才会按"将被提交的文件"扫描）：

   ```bash
   npm run audit           # = node scripts/audit-public.mjs
   npm run audit -- --all  # 连被 .gitignore 排除的目录一起扫，确认没有漏网
   ```

   干净时退出码 0，发现问题退出码 1——可以挂到 pre-commit 或 CI 上。

3. **不要把真实检测报告发到仓库/issue**：报告里的 `keyFingerprint` 是确定性的，同一把 Key 永远同一个值，别人能据此把多份报告关联到同一把 Key。要贴就贴演示桩生成的报告。

4. **提交前跑一次自测**：`npm run selftest`。

### 15.2 建议

- [ ] 仓库名用英文 slug（例如 `relay-model-guard`，代码里的 `user-agent` 和报告 `schema` 已经在用这个名字了）
- [ ] 简介写"给 LLM 中转 API 做体检的 14 路探针检测器"，GitHub **Topics** 填：`llm`、`openai`、`api-testing`、`llm-security`、`prompt-injection`、`relay`、`nodejs`
- [ ] 如果连 GitHub 账号都不想与真实身份关联，用**独立账号**开源：公开仓库的作者账号本身就是公开信息，邮箱只是其中一环
- [ ] `docs/images/` 里的 5 张界面截图约 310 KB（JPEG），本文档已用相对路径引用，直接一起提交
- [ ] 确认默认值：默认 Token 上限 `≈39k`、并发 `3`、`LONG_CONTEXT_CHARS=32000`；若要给别人用，记得开 deploy-safe 并改默认监听
- [ ] 标题与简介可以直接用（`npm run publish:github` 会自动填）：
  - **仓库名**：`relay-model-guard`
  - **About（标题+简介）**：给 LLM 中转 API 做体检的 14 路探针检测器：识别模型调包、隐藏提示词、Token 注入、越狱绕过、上下文截断与计费异常；内置 Token 预算保护与 deploy-safe 部署模式。零依赖 Node。
  - **Topics**：`llm`、`openai`、`api-testing`、`llm-security`、`prompt-injection`、`relay`、`nodejs`、`zero-dependencies`
- [ ] 面向英文用户可再加一份 `docs/GUIDE.en.md`（界面与文案目前均为中文）

### 15.3 推上去

**推荐：一条命令**（先跑体检 → 把提交身份自动设成 GitHub noreply 邮箱 → 建仓库、写标题/简介、打 Topics → 推送）

```bash
gh auth login            # 只需一次；未安装 gh：https://cli.github.com
npm run publish:github   # 默认创建公开仓库 relay-model-guard

# 可选参数
npm run publish:github -- --name 别的名字      # 换仓库名
npm run publish:github -- --private            # 建私有仓库
npm run publish:github -- --yes                # 跳过确认
```

**手动方式**

```bash
git add .
git commit -m "feat: 中转 API 模型检测器（14 路探针 + Token 预算保护 + deploy-safe）"
git branch -M main
git remote add origin git@github.com:<you>/relay-model-guard.git
git push -u origin main
```
