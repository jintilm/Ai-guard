# 部署与运维

## 一、接入方式

### 方式 A：Python SDK（零网络开销）

```python
import prompt_ids

result = prompt_ids.scan(user_input, user="alice")
if result.level == "critical":
    return {"error": "rejected"}, 403
```

批量：

```python
results = prompt_ids.scan_batch(["文本1", "文本2"])
```

要控制策略/启用语义层就得显式装配（`scan()` 走的是默认轻量配置）：

```python
from prompt_ids import create_pipeline, PipelineConfig

pipeline = create_pipeline(PipelineConfig(
    policy_name="strict",
    semantic_enabled=True,
    semantic_backend="local",
    semantic_mode="always",
))
result = pipeline.scan(user_input)
```

⚠ **`Pipeline(config=...)` 不会装配语义层** —— 检测器由 `create_pipeline`
显式创建。直接 `Pipeline(config=cfg)` 得到的 `enabled=False / backend=null`
的语义层**看起来一切正常**（不报错、有分数），只是从没被调用过。
这是本项目踩过的一个真实坑：`scripts/build_overrefusal.py` 第一版就这么写的，
三份配置的数字完全相同（都是 1.34ms/条），报告照写 —— 看起来毫无问题，
实际上什么都没测。

### 方式 B：REST API（8790）

```bash
python -m prompt_ids.api --port 8790 --api-key "$API_KEY" --audit logs/audit.jsonl
```

应用侧改一行 base_url。详见 [API 参考](api.md)。

### 方式 C：透明代理（8787）

**应用零代码改造**，只改 base_url：

```bash
python -m prompt_ids.proxy \
  --upstream https://api.openai.com/v1 \
  --upstream-key "$OPENAI_API_KEY" \
  --port 8787 --audit logs/audit.jsonl
```

```python
# 应用侧唯一改动
client = OpenAI(base_url="http://127.0.0.1:8787/v1", api_key="dummy")
```

拦截时返回 **403**。代理会转发所有已支持路径：聊天、embedding、
moderations、图像、音频、Anthropic `/v1/messages` 等。

⚠ **代理不是全透传**。未知路径返回 404，已知但未接入的返回 501 ——
这是刻意的（防止「不在扫描列表里就悄悄放行」）。所以把代理挂上去之前，
**先确认你的应用只用支持的路径**，否则会 404。

#### 代理的分角色策略（重要，容易踩）

`system` / `developer` 消息**默认只走规则层**，不过语义层。
这是实测驱动的决定：

| | 良性 RAG 请求被误拦 | 攻击藏在 system 角色的召回 |
|---|---|---|
| system 也过 L3 | **0.5278** | 0.4468 |
| system 只走规则层（默认） | **0.0833** | 0.0638 |

旧行为下 18/19 次拦截来自 `system` 段 —— 也就是「正常 RAG 请求被自己的
系统提示拦下」，53% 的误拦率等于这个功能在 RAG 场景不可用。

代价是真实的：藏在 system 里的注入召回从 0.4468 掉到 0.0638。
前提是威胁模型 —— **能改你自己系统提示的攻击者，已经拿到了你的应用配置**。
你的应用若把外部内容拼进系统提示，正确做法是放进 `user`/`tool` 消息
（那条路 L3 全覆盖）。要回到旧行为：`PROMPT_IDS_PROXY_SEMANTIC_SYSTEM=1`。

## 二、安全：三道门，缺一不可

⚠ **默认只绑 `127.0.0.1`，但这不是安全承诺。** 想让别人访问就得改
`--host`，一旦改成 `0.0.0.0` 就没有任何鉴权了。所以：

| 入口 | 客户端鉴权参数 | 环境变量 |
|---|---|---|
| API | `--api-key` | `PROMPT_IDS_API_KEY` |
| 代理 | `--client-key` | `PROMPT_IDS_PROXY_CLIENT_KEY` |
| 检测台 | `--client-key` | `PROMPT_IDS_WEB_CLIENT_KEY` |

⚠ **三个环境变量名刻意不同** —— 复用会让「我给 API 开了鉴权」被误读成
三个入口都开了。鉴权方式是 `X-API-Key` 头。
⚠ 代理的 `Authorization` 头是**透传给上游**的，所以它只能用 `X-API-Key`
表达自己的凭据。

**另外两道门**（反代侧）：TLS、请求体上限。
⚠ **反代与内置鉴权是两道独立门，不要只配一道**：
反代给了 TLS 但忘透传 `X-API-Key` ⇒ 服务侧鉴权等于没开；
只配服务侧鉴权不给反代 ⇒ Key 走明文。

```bash
python scripts/deploy_check.py            # 逐条检查三道门，并明确列出哪些查不到
python scripts/deploy_check.py --runtime  # 真起服务验鉴权行为
```

参考配置：[`deploy/nginx.conf`](../deploy/nginx.conf)。

⚠ **超时必须 > LLM 的 p90**。nginx 默认 60s 覆盖不住实测 p90≈40s 的长尾
⇒ 间歇性 504 而服务日志一切正常。

⚠ **`X-Forwarded-For` 必须配**，否则按 IP 限流会把所有人算成一个桶，
第一个请求就耗尽额度。

### 健康检查

`/healthz` **不鉴权**（编排探针不带业务凭据），只回 `{"status": ...}`。

## 三、容器

```bash
docker compose up -d          # proxy + api
docker compose logs -f proxy
```

三个镜像阶段：`base` → `slim`（只装 `.[speed]` + numpy，**纯规则层镜像**，
不需要 torch）→ `full`（`.[semantic]`，torch 走官方 CPU 源避免被换回 CUDA 版）。
非 root 用户 uid 10001，**零 apt-get**。

compose 里端口**只发布到宿主回环**。⚠ 刻意**不设 `--api-key` 的占位默认值** ——
一个众所周知的默认值比「没有鉴权」更糟：后者会触发暴露面告警。

## 四、配置项

### 环境变量（全部 36 个）

**LLM 后端**（厂商通用）

| 变量 | 说明 |
|---|---|
| `PROMPT_IDS_LLM_API_KEY` | 通用 Key，21 家中通用 |
| `PROMPT_IDS_LLM_PROVIDER` | 厂商名，如 `deepseek` |
| `PROMPT_IDS_LLM_MODEL` | 模型名（`provider/model` 或直接写） |
| `PROMPT_IDS_LLM_BASE_URL` | ⚠ **必须带 `/v1`** |
| `PROMPT_IDS_LLM_FALLBACKS` | 逗号分隔的备用厂商 |
| `PROMPT_IDS_LLM_MAX_TOKENS` | 默认 1024 |
| `PROMPT_IDS_LLM_EXTRA_BODY` | 如 `{"thinking":{"type":"disabled"}}` |
| `PROMPT_IDS_LLM_USER_AGENT` | 被网关拦 403 时需要 |

⚠ **`base_url` 漏了 `/v1` 前缀**，部分网关返回 **200 + HTML** ——
静默假成功，比 502 更危险。判连通要看响应体是 JSON，不能只看状态码。
⚠ `PROMPT_IDS_LLM_EXTRA_BODY` 关思考链能省一半时间但**掉精度**
（P 1.000 → 0.500），质量评测必须开着。

**代理**

| 变量 | 默认 | 说明 |
|---|---|---|
| `PROMPT_IDS_UPSTREAM` | — | 上游 base_url |
| `PROMPT_IDS_UPSTREAM_KEY` | — | 上游凭据 |
| `PROMPT_IDS_PROXY_SCAN_TOOL` | 开 | 扫 `tool`/`function` 消息 |
| `PROMPT_IDS_PROXY_SCAN_SECRETS` | 开 | 响应侧凭据扫描 |
| `PROMPT_IDS_PROXY_MAX_TOTAL_SCAN_CHARS` | 60000 | ⚠ 去掉预算 = CPU DoS 放大器 |
| `PROMPT_IDS_PROXY_MAX_TOOL_SEGMENTS` | — | ⚠ **均分**，不是先到先得 |
| `PROMPT_IDS_PROXY_MAX_RESPONSE_SCAN_CHARS` | 200000 | 出站扫描预算 |
| `PROMPT_IDS_PROXY_MAX_RESPONSE_MB` | 32 | 超限返 502 而非半截 JSON |
| `PROMPT_IDS_PROXY_RATE_LIMIT` | 关 | 按来源 IP |
| `PROMPT_IDS_PROXY_RATE_WINDOW_S` | 60 | 限流窗口 |
| `PROMPT_IDS_PROXY_MAX_SEGMENT_CHARS` | — | 单段上限（超出走取样） |
| `PROMPT_IDS_PROXY_SEMANTIC_SYSTEM` | 关 | 打开则 system 也过 L3（不推荐） |

**观测（OTel / Langfuse）**

| 变量 | 说明 |
|---|---|
| `PROMPT_IDS_OBSERVABILITY` | 总开关 |
| `PROMPT_IDS_OTEL_ENDPOINT` | OTLP 接收端 |
| `PROMPT_IDS_OTEL_SERVICE` | 服务名 |
| `PROMPT_IDS_OBSERVABILITY_TIMEOUT_S` | 导出超时（**失败不影响检测**） |
| `PROMPT_IDS_LANGFUSE_HOST` | Langfuse 实例地址 |
| `PROMPT_IDS_LANGFUSE_PUBLIC_KEY` | 认证（公开半） |
| `PROMPT_IDS_LANGFUSE_SECRET_KEY` | 认证（私密半） |

⚠ 遥测属性走**白名单**（`sanitize()`）—— 只有白名单里的键能出网，
超长值**直接丢而不是截断**（截断后的片段仍可能是原文的可用前缀）。
与内容相关的唯一标识是**指纹**。

**Azure 专用**（仅当 provider 是 azure 时需要）

| 变量 | 说明 |
|---|---|
| `PROMPT_IDS_LLM_API_VERSION` | API 版本 |
| `PROMPT_IDS_LLM_DEPLOYMENT` | 部署名 |

⚠ Azure 因此是**三行数据而不是特殊分支** —— 21 家提供商共用同一套解析逻辑。

**其他**

`PROMPT_IDS_RULE_ENGINE`（`regex` / `re`）、`PROMPT_IDS_ENV_FILE`
（指定 env 文件路径）、`PROMPT_IDS_CANARY_ISSUE_LIMIT`（默认 30/分钟·每身份）、
`PROMPT_IDS_CANARY_ISSUE_WINDOW_S`（默认 60 秒）

⚠ `.env` 在 **import 期**被读进 `os.environ`，且**真实环境变量优先**。

## 五、监控

```bash
curl -s localhost:8790/v1/metrics | jq
```

关键字段：

| 字段 | 怎么读 |
|---|---|
| `semantic.info.abstained` | ⚠ **最重要的一个**。调用失败弃权次数 |
| `semantic.info.degraded` | `true` ⇒ L3 实际未生效 |
| `cache.scope` | `process` ⇒ 多实例部署时命中率**不可比** |
| `guard.cache` / `guard.rate_limited` | 缓存与限流状态 |
| `semantic.info.in_flight` / `running` / `queued` | 占用的预测槽位、正在执行的任务、等待执行或清理的任务 |
| `semantic.info.capacity` | 预测槽位上限，默认 8（4 个工作线程 + 4 个等待位置） |
| `semantic.info.overloaded` | 容量已满而直接弃票的调用数，计入 `abstained` |
| `semantic.info.cancelled` | 已取消的等待任务数，包括超时和关闭时的取消 |

⚠ **`is_available()` 只看 Key 配没配，不看网关通不通**。所以配了 Key
但网关挂着时，`auto` 照样选它，于是每次调用都失败并**按弃票处理**
⇒ **L3 静默失效，分数看起来仍然正常**（只是悄悄退回规则层）。
所以 `degraded` 必须配告警 —— 这是唯一能看见它的信号。

### 语义层负载与超时保护

默认最多占用 8 个预测槽位。容量满时本次 L3 返回 `ok=False`，按既有规则弃票，
由已执行的检测层继续决定结果。这个机制限制后台工作量，不能把弃票理解为“文本安全”。
未拿到 L3 判决的扫描结果不会进入最终结果缓存，恢复后相同文本会重新调用 L3。
`max_workers` 与 `max_pending` 可通过 `SemanticDetector` 的 SDK 参数配置；
`max_pending=0` 表示线程池不留等待位置。
较小的队列会更早弃票；较大的队列可以吸收短突发，但会增加排队时间和资源占用。

`timeout_s` 包括排队时间。LLM 的 HTTP 重试、JSON 模式回退、备用提供商和退避等待
共用同一截止时间；SDK 直接调用 `LLMBackend.predict()` 时，总预算使用
`default_timeout_s`。检测器设置了预算时，后端沿用该预算，单次 HTTP 操作仍受
后端自己的超时上限约束。

超时的排队任务不会再调用后端，但占位会保留到工作线程清理它，防止连续超时把
线程池内部队列再次撑大。已经开始的 Python 推理或 HTTP 操作无法保证立即中断，
会继续占用槽位直到返回，过期结果不参与融合。关闭检测器会取消等待任务，并在
已运行任务结束后释放后端资源；关闭后的检测器不能再次使用。

可复跑的合成负载测量：

```bash
python -X utf8 scripts/semantic_load_check.py --out reports/semantic_load_after.json
```

2026-11-20 的 [增强前](../reports/semantic_load_before.json) / [增强后](../reports/semantic_load_after.json)
记录：16 个并发请求、4 个工作线程、50ms 请求预算、250ms 模拟后端耗时。
超时后额外启动的后端调用从 12 次降到 0 次；60ms 的模拟 LLM 重试预算从
约 3125ms 收敛到约 60ms。此测量使用本地替身，不代表真实厂商延迟或攻击检出率。

### LLM 长文本分窗取样

LLM 裁判默认仍使用 `head`（前 3000 字符）。在 `.env` 中显式配置以下选项可切换为
分层取样；启动服务或 CLI 时生效，仅适用于 LLM 裁判后端，本地 DeBERTa 的 token 截断行为不变。

```dotenv
PROMPT_IDS_LLM_INPUT_STRATEGY=stratified
PROMPT_IDS_LLM_INPUT_CHARS=3000
PROMPT_IDS_LLM_INPUT_WINDOWS=3
```

```bash
python -m prompt_ids.cli --semantic --semantic-backend llm --semantic-mode always --file document.txt --json
```

SDK 可显式构造后端，显式参数优先于环境变量：

```python
from prompt_ids import PipelineConfig, create_pipeline
from prompt_ids.detectors.semantic.detector import SemanticDetector
from prompt_ids.detectors.semantic.llm import LLMBackend

backend = LLMBackend(input_strategy="stratified", max_input_chars=3000, max_windows=3)
pipeline = create_pipeline(
    config=PipelineConfig(semantic_enabled=True, semantic_mode="always"),
    semantic=SemanticDetector(enabled=True, backend=backend, mode="always"),
)
try:
    result = pipeline.scan("your document")
    print(result.to_dict()["semantic_coverage"])
finally:
    pipeline.close()
```

短于预算的文本保持完整。长文本分配头部、中间和尾部窗口（窗口数可设 1–8）；
窗口之间插入 `[... content omitted ...]`，避免把不相邻的文字拼成原文里不存在的指令。
**所有窗口合成一次裁判输入**，3000 字符预算包含断点标记，但不包含固定裁判提示。
重试和备用端点仍可能产生多次 HTTP 请求，沿用同一个时间预算。

结果增加两个字段：

- `semantic_ok`：是否取得有效语义判决；`null` 表示本次没有取得执行结果，例如 L3 被跳过。
- `semantic_coverage`：所选输入的 `input_chars`、`sampled_chars`、`coverage_ratio`、
  `window_count`、`strategy`、`truncated` 和 `[start, end)` 区间；没有可靠信息时为 `null`。

**覆盖是输入选择的记录，不是“判定成功”的证明。** 应同时看 `semantic_ok`。
区间以归一化后的后端输入为基准，不能直接当作原始文档位置；代理可能已经先做了分段或抽样，
应结合 `trajectory.coverage` 阅读。审计、SSE、代理每段轨迹只记录区间和计数，不记录片段原文。
取样配置进入缓存键；更换策略、窗口数或字符预算不会复用旧判定。

[覆盖测量](../reports/semantic_windows.json) 只使用 `deepset_train` 的攻击原文，
将它们放入合成长文档的头部、中段、尾部，未调用真实模型，也未使用留出集。
12,000 字符文档、3000 字符预算下，三窗完整保留中段或尾部载荷 200/203 条，
头部截取为 0/203；头部载荷则从 202/203 降到 200/203。三窗实际选择 2942 字符，
覆盖约 24.5%；30,000 字符时仅约 9.8%。

该结果量的是载荷可见性，**不能引用为检测召回**。取样仍有空洞，长载荷可能被切断，
真实误报率、延迟和 token 成本需要用所选模型另行评测，因此此策略保持显式开启。

```bash
python -X utf8 scripts/semantic_window_check.py --out reports/semantic_windows.json
```

## 六、审计日志

```jsonl
logs/audit.jsonl
```

**只存指纹，不存原文** —— 审计层一旦存原文就成了业务数据副本，代理场景下
等于凭空多一个泄露面。要原文走复核队列（`POST /v1/review` 提供）。

事件有两个**正交**维度：

| 字段 | 含义 |
|---|---|
| `decision` | **请求**的处置（allow/block/review/sandbox/...） |
| `extra["outbound"]` | **响应**出去时发生了什么（none/redacted/warned/...） |

**一次请求只落一条事件**。⚠ `warned`（流式事后告警）**不算「已处置」** ——
内容已经发出去了，算成处置了就是自欺。

只读：

```bash
python -m prompt_ids.audit tail logs/audit.jsonl
python -m prompt_ids.audit review logs/audit.jsonl      # 复核台账 + 规则级嫌疑榜
```

⚠ 看板/报表统计拦截数请用 `decision == "block"`。历史上还存在
`leak`/`redact_secrets` 这类旧 `kind` 值，别混算。

## 七、人工复核闭环

检测 → 复核 → 学习，把误报反馈回规则：

```bash
# 队列（只收 medium 及以上，只给指纹）
curl -s "localhost:8790/v1/review/queue?limit=50" | jq

# 提交人工结论
curl -X POST localhost:8790/v1/review -H 'Content-Type: application/json' -d '{
  "fingerprint": "...", "text": "<原文，这里才提供>",
  "label": false, "note": "正常业务请求", "action": ""
}'

# 规则级嫌疑榜（台账按指纹去重，否则同一篇文档复核 5 次能刷出 100% 误报率）
curl -s localhost:8790/v1/review/patterns | jq
```

⚠ **`action` 留空** —— 人工结论填进 `action` 会污染 `by_action` 聚合，
让「系统自己判了多少次阻断」这个数字失真。
⚠ **绝不自动改规则 / 自动降权**：分母偏向已触发规则、3 次误报证明不了什么、
降权毁掉可解释性且等于告诉攻击者打哪条。

启动时接 `--review-corpus <路径>` 才会落复核语料（含原文，
**自动进 .gitignore**）。不配就不写。

## 八、Canary 令牌

证明「攻击真的成功了」，而不是「我们觉得可能成功」：

```bash
TOKEN=$(curl -s -X POST localhost:8790/v1/canary/issue \
  -H 'Content-Type: application/json' -d '{"label":"prod"}' | jq -r .token)
# 把 token 埋进你的系统提示/工具输出，然后正常调用模型
curl -s -X POST localhost:8790/v1/canary/check \
  -H 'Content-Type: application/json' -d "{\"text\": \"模型输出原文\"}" | jq
# => {"leaked": true, "match": {...}, "tokens_known": 3}
```

⚠ 签发**默认有配额**（30/分钟·每身份，`--canary-issue-limit` 可调）——
这个端点明文发令牌，默认关等于默认没防护。签发会落审计（只落脱敏令牌）。
