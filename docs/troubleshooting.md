# 故障排查

按**症状**组织，不是按模块。每条都给出真实原因和验证命令。

## 一、命令跑不起来

### `prompt-ids: command not found` / 不是内部或外部命令

包没装。三种方式任选：

```bash
pip install -e .                        # 之后才有 prompt-ids 命令
python -m prompt_ids.cli "..."          # 模块形式，完全等价
python E:/Code/Ai-guard/scripts/smoke.py  # 脚本自己会 sys.path.insert 项目根
```

### `ModuleNotFoundError: No module named 'prompt_ids'`

不在项目根目录。`cd` 到仓库根再跑。

### `ImportError: No module named 'numpy'`

⚠ **这条报错与真正的原因无关。** `memory/store.py` 与 `encoder.py` 在**模块级**
`import numpy`，而 `core/pipeline.py` 传递依赖它们 —— 所以只装了 PyYAML 时
连**纯规则层**都起不来。报错只说缺 numpy，看不出跟规则层有关。

```bash
pip install -e .        # numpy 已在核心依赖里，pip install -e . 会带上
```

## 二、检测结果不对

### 规则层几乎不检出「角色扮演」「任务改写」型注入

**不是 bug，是这类注入的本质。** 它们的载荷是目标导向的业务指令
（"把一笔交易转给 US1330… 并带上用户订阅的音乐服务"），
没有 "ignore all previous instructions" 这种钓鱼措辞，**短语匹配必然抓不到**。

实测：agent 面 47 条 Agent-Dojo 攻击，规则层 block 召回 **0.0000**。
约 70% 的 deepset「攻击」也是这一类。

解法是加语义层（见下节）。

### 明明是攻击却只判到 medium

看响应的 `skipped` 字段。命中高危规则时会短路，启发层和语义层**根本没跑** ——
`skipped: ["heuristic"]` 就是这个意思。想让所有层都参与：

```bash
python -m prompt_ids.cli --no-short-circuit "..."
```

### 正常的 RAG 请求被误判

两个已知原因：

1. **system 提示被判成注入** —— 语义层把「对助手下的祈使句」当注入，
   而系统提示按定义就是对助手的祈使句，**每个 RAG 请求都带**。
   实测 6 条诊断探针：DeBERTa 误判 3 条、LLM 裁判 5 条。
   ⇒ 代理对 `system` 消息默认只走规则层；若你显式开了
   `PROMPT_IDS_PROXY_SEMANTIC_SYSTEM=1`，关掉它。

2. **预筛门没起作用** —— `fallback` 模式下这类文本常先被启发规则推过预筛线，
   于是照样调了语义层（实测 84.3% 的良性样本仍被调用）。

### `action` 是 `sandbox` 但我以为是拦截了

`default` 策略把 `high` 映射成 **`sandbox`** = **放行 + 记审计，HTTP 200**。
只有 `critical` 才 `block`。

⚠ 统计拦截率时按 `action == "block"`，**不要**按 `level >= high` ——
否则默认策略下会把 sandbox 算成拦截，虚报约 27%。

### 阈值/去重/规则改了但数字没变

**报告文件会悄悄过期。** `reports/*.json` 的内容取决于跑它时的配置，
文件名不变不代表内容是新的。换数据集、规则、后端后**必须重跑**：

```bash
python scripts/eval_semantic.py --dataset data/full.jsonl
```

⚠ LLM 后端写 `reports/ablation_llm.json`，**不要覆盖 `ablation.json`**
（那是 DeBERTa/默认基线）。

## 三、语义层（L3）不生效

### 加了 `--semantic` 但分数和规则层一样

先确认**实际生效的后端**：

```bash
python -m prompt_ids.cli --probe      # 首行就是 effective（权威答案）
```

⚠ **`auto` 不等于你配的那家。** 顺序是 `llm > local > lightweight`
（云端优先）—— 配了 Key 就用云端裁判，即使本地模型快 50 倍。
想用本地：

```bash
--semantic-backend local
```

### 忘了加 `--semantic-mode always`

默认 `fallback` 只在规则层先报警时才调 L3。而「规则层抓不到」正是加 L3 的理由
—— `fallback` 在这类攻击上等于没开。实测红队集上 `fallback` 召回比 `always`
低 0.06，且更慢。

```bash
python -m prompt_ids.cli --semantic --semantic-backend local --semantic-mode always "..."
```

### 语义层静默失效（最难查的一种）

**症状**：加了语义层，指标正常、分数正常、没有任何报错 —— 但 L3 实际从没生效。

原因链：`is_available()` **只看 Key 配没配，不看网关通不通** ⇒ 配了 Key 但网关
挂着时 `auto` 照样选它 ⇒ 每次调用都失败并**按弃票处理**（`ok=False` ⇒
`contribution()` 返回 None）⇒ 结果悄悄退回规则层。

**唯一的检测信号**：

```bash
curl -s localhost:8790/v1/metrics | jq '.semantic.info'
# { "backend": "deepseek", "abstained": 47, "degraded": true, ... }
```

`degraded: true` ⇒ 调用失败率 >20% ⇒ **L3 未生效**。CLI 在降级时也会打一行
`⚠ 语义层已降级：a/b 次调用弃权（>20%），L3 实际未生效`。
**务必为它配告警**，否则这个失效形态完全不可见。

### 网关返回 403

多半是 **UA 拦截**（Cloudflare 那种 `403 error code: 1010`）。报错里完全看不出
是鉴权/网络问题。

```bash
PROMPT_IDS_LLM_USER_AGENT="Mozilla/5.0" python scripts/llm_check.py
```

### 网关返回 200 但内容是 HTML

**静默假成功，比 502 更危险。** 通常是 `base_url` **漏了 `/v1` 前缀**。

```bash
python -m prompt_ids.cli --list-models deepseek   # 应返回 JSON 模型列表
```

### 连通但每条都退化成 p=0.5

推理模型把 token 全烧在 `reasoning_content` 上，`content` 空 +
`finish_reason=length` ⇒ 每条退化成中立却「调用成功」。

```bash
PROMPT_IDS_LLM_MAX_TOKENS=2048     # 默认 1024
python scripts/llm_check.py        # 判据是 backend.last_parsed，不是连通性
```

### 「连通」不等于「可用」

`scripts/llm_check.py` 的判据是 `backend.last_parsed` —— 只看连通**分不出**
「调通了」和「全退化成 0.5」。退出码：`0` 通 / `2` 没配 Key / `1` 失败。

## 四、代理问题

### 应用报 404 / 501

**代理不是全透传。** 未知路径 404，已知但未接入的 501 —— 这是刻意的
（防止「不在扫描列表里就悄悄放行」）。挂代理前先确认你的应用只用支持的路径。

⚠ 历史上 `/v1/messages`（Anthropic）曾**静默透传**，等于 Anthropic 客户端
完全不过检测。现在已改成扫描。

### 上游 502 但日志没线索

先看 `logs/audit.jsonl` 里的 `note`。⚠ 500 响应**不回显异常文本** ——
绝对路径、内网 base_url（含内嵌凭据）都不给客户端，完整栈只进 stderr。

### 客户端收到 `ConnectionResetError` 而不是 413

body 上限触发时**必须先分块把 body 读干净**再响应。这三个坑在 proxy、api、
playground 各踩过一次。你自己写客户端时注意：发大 body 被拒后，
连接会先被读完再回 413。

### 流式响应里收不到告警

告警帧必须排在 `data: [DONE]` **之前** —— 官方 SDK 与任何合规 SSE 解析器
读到 `[DONE]` 就停止消费，追加在后面的帧会被丢弃。

⚠ 如果你看到的响应里告警帧排在 `[DONE]` 之后，那是 bug，请报。
代理侧的正确做法是「按完整帧转发、最后一帧扣住」，代价是一帧延迟。

### 扫描好像只看了开头

**这是设计，不是 bug。** 取任何默认值前先看审计里的
`truncated` / `dropped` / `scanned_chars`：

- 20KB 以内是**完整扫描**（RAG 分块的常见量级）
- 2MB 文档只有 **1% 覆盖**

⚠ 别对外宣称「工具内容全量检测」。要提高覆盖就调
`PROMPT_IDS_PROXY_MAX_TOTAL_SCAN_CHARS`，但规则层实测 **≈5.4µs/字符** ⇒
去掉预算等于 2MB body = 11s CPU 的放大器。

### 批量提交时真正的攻击被前面的正常文本稀释了

⚠ 预算**均分**、不是先到先得 —— 攻击者在注入前塞 31 条无关文档就能挤掉自己
那段。守护 `test_budget_is_shared_fairly_so_padding_cannot_evade` 钉着这条。
若你看到这种行为，那是回归。

### 流式转写/翻译的响应没被检查

`stream: true` 现在**已覆盖**（跨帧拼接 + 有界累积 + 告警帧排在 `[DONE]` 前），
结论落审计 `extra["transcript_scan"]`，其中 `capped: true` 表示
**超出预算的尾部没被扫**。

⚠ 流式**只能告警、不能拦** —— 内容已经发出去了。

## 五、服务起不来 / 部署问题

### 绑了 `0.0.0.0` 就被警告

```
⚠ 透明代理绑在 0.0.0.0 且未配置客户端鉴权（--client-key）
```

**这不是错误，是提醒你暴露了什么。** 容器/K8s 部署必然要 `--host 0.0.0.0`
（Pod 里别的容器摸不到 `127.0.0.1`），所以不硬拦。正确做法是配三道门：

```bash
python scripts/deploy_check.py            # 逐条检查，并明确列出哪些查不到
python scripts/deploy_check.py --runtime  # 真起服务验鉴权行为
```

⚠ **反代与内置鉴权是两道独立门，不要只配一道**：
反代给了 TLS 但忘透传 `X-API-Key` ⇒ 服务侧鉴权等于没开；
只配服务侧鉴权不给反代 ⇒ Key 走明文。

### 反代下所有人共用一个限流桶

nginx **必须**配 `X-Forwarded-For`。缺它则按 IP 限流把所有人算成一个桶，
第一个请求就耗尽额度。

### 间歇性 504 但服务日志一切正常

nginx 默认超时 60s，覆盖不住实测 p90≈40s 的 LLM 长尾。
把超时调到 **> LLM 的 p90**。

### 看板数字和卡片显示不一致 / 卡片空白

先确认**没有旧 `--serve` 进程在跑**：`--serve` 会每 15s 用**进程启动时**加载的
模板重写 `reports/dashboard.html`，所以「先起服务、后改 dashboard.py」时，
长驻进程会把新看板**覆盖回旧模板**。现象是「卡片加了却生成不出来」，
且每 15 秒自我复现。

```bash
python scripts/check_dashboard.py   # 13 项检查，数字从报告现算
```

⚠ `node --check` 只查 JS 语法，DOM-id 契约只查元素存在 ——
**两个都过 ≠ 显示正确**。渲染函数共用时，每个分支只允许依赖该响应
真实存在的字段。

## 六、审计与复核

### 审计里有 `leak` / `redact_secrets` 这类旧 kind

历史日志的兼容期读数。它们现在归到 `extra["outbound"]` 维度。
⚠ **一次请求只落一条事件** —— `by_decision` 不该把一次请求数成两次。
CLI 会显式提示这些是旧口径。

统计拦截用 `decision == "block"`，出站处置另看 `outbound_acted`
（不含 `warned`）与 `leaked`（含 `warned`）。

### 复核队列里有永远清不掉的工单

复核后样本**必须从队列消失**。留在队列里等于一条永远清不掉的工单，
页面正常、无报错、就是不对。

### 嫌疑榜显示某条规则 100% 误报

**台账按指纹去重**了。若你看到 100%，先确认去重逻辑没被绕过 ——
否则「同一篇文档复核 5 次」就能刷出这个假象。

### 记忆库里混进了良性文本

`label` **必须是 JSON 布尔**。传字符串 `"false"` 会被 `bool("false")`
判成 True。检查你的客户端有没有把布尔序列化成字符串。

## 七、测试与验证

### pytest 报 `N passed` 但退出码非 0

`pyproject.toml` 的 `addopts="-q"` 再叠命令行 `-q` 会变 `-qq`，pytest
**连总结行一起吞掉**。判全绿看**退出码**。

数用例用 `--collect-only -q`，别数总结行。

### 子进程测试报 `UnicodeDecodeError` / `NoneType.splitlines`

Windows 上 `text=True` 却不钉 `encoding`，解码跟随本机代码页 cp936。
子进程 env 要钉 `PYTHONIOENCODING=utf-8`，父进程读的时候
`encoding="utf-8", errors="replace"`。

### 改仓库文件后中文全变成问号

⚠ **绝不拿 PowerShell 的文本管道改仓库里的 UTF-8 文件**：

```powershell
(Get-Content f -Raw) -replace ... | Set-Content f   # ❌ 灾难
```

它会按本机代码页 cp936 读 UTF-8，再写回时每个 3 字节汉字的尾字节被换成 `?`。
**报错为零、文件仍是合法 UTF-8、`git status` 之外没有任何信号**
（实测 README 丢 1000 字节、AGENTS.md 吃掉 299 个换行）。

用 `edit`/`write` 工具，或 Python 显式 `encoding=`。

⚠ 判断文件是否被弄坏**不能只看「能不能解码」** —— 损坏后的文件仍是合法 UTF-8。
真正的判据是逐字节对不上。

## 八、还需要人判断的

以下**不是缺陷**，是设计上刻意留下的边界，不要当成 bug 去"修"：

| 现象 | 为什么留着 |
|---|---|
| PINT 留出集零覆盖类别 | 补规则就得声明那批样本已被「烧掉」，否则留出集失去意义 |
| OR-Bench 的 block 级误伤 4.2~4.8% | 这是**加语义层的价签**，也是 agent 面召回 0.0000→0.4469 的代价。两者必须一起引用 |
| `fallback` 仍调 84.3% 的良性样本 | 预筛门只能保护「规则层完全没声音」的部分；这类文本先被启发规则推过线了 |
| `skipped` 字段存在 | 短路是**特性**（高危规则命中后不再浪费时间），不是漏检 |
| 仓库文件被密钥扫描器命中 | 测试夹具**按设计就写着凭据形状**，扫到它们是检测成立而非误报 |