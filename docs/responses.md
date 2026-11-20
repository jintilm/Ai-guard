# Responses API 代理接入

[English](#english) · [部署与运维](operations.md)

代理支持 `POST /v1/responses`（也接受 `/responses`）的**文本与应用函数工具**流程。
它复用现有的分段检测、共享字符预算、策略和出站检查。上游本身需要支持 Responses API；
此功能不把 Chat Completions 网关转换成 Responses 服务。

## 普通调用

先启动代理，配置应用模型的上游。裁判后端配置与这里的上游是两件事。

```bash
python -m prompt_ids.proxy --upstream https://api.openai.com/v1 --port 8787 --audit logs/audit.jsonl
```

上游凭据通过 `PROMPT_IDS_UPSTREAM_KEY` 配置。如果代理另设了客户端鉴权，
SDK 的 `default_headers` 需提供对应的 `X-API-Key`。这些设置详见 [部署与运维](operations.md)。

```python
import os
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:8787/v1", api_key="unused")
response = client.responses.create(
    model=os.environ["APP_MODEL"],
    instructions="根据提供的文档回答问题，只做总结。",
    input="请解释部署文档中的资源限制。",
    store=False,
)
print(response.output_text)
```

正常请求的 JSON 字节和参数原样转发；阻断时返回 `403 injection_detected`，请求不会到达上游。
`default` 策略的 `high` 仍是放行并审计的 `sandbox`；真正阻断以 `action` 为准。

## 函数工具和完整历史

每次调用都提交完整、显式的文本历史。应用执行函数后，将工具返回值作为
`function_call_output` 提交，不把它塞进 `instructions`。

```python
history = [{"role": "user", "content": "总结检索到的部署文档"}]
tools = [{
    "type": "function",
    "name": "lookup_docs",
    "description": "检索部署文档",
    "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    "strict": True,
}]
first = client.responses.create(
    model=os.environ["APP_MODEL"], input=history, tools=tools, store=False,
)
history.extend(first.output)
for item in first.output:
    if item.type == "function_call" and item.name == "lookup_docs":
        # 实际应用在这里验证参数、执行已授权工具，并取得检索文本。
        document_text = "应用取得的文档正文"
        history.append({
            "type": "function_call_output",
            "call_id": item.call_id,
            "output": document_text,
        })
second = client.responses.create(
    model=os.environ["APP_MODEL"], input=history, tools=tools, store=False,
)
```

分段方式：

| 输入 | 检测方式 | 审计位置 |
|---|---|---|
| `input` 字符串、`user` 消息 | 合并用户文本后检测 | `author#-1` |
| `instructions`、`system` / `developer` 消息、函数声明 | 合并，默认只走规则层 | `system#-1` |
| `function_call_output.output` | 每条独立检测，剩余预算均分 | `function#N`，N 是 `input` 数组下标 |
| `assistant` 消息、`function_call`、`reasoning` 历史 | 按既有模型输出排除策略跳过 | `ignored_model_items` 计数 |

文本内容支持字符串或 `input_text` 内容数组；助手历史还接受 `output_text` 和 `refusal`。
消息角色必须由应用正确设置，外部文档不能自称 `system`、`assistant` 或 `reasoning`。
`instructions` 不会自动成为 `ScanContext`；原有高危规则、L3 门控和分角色策略继续生效。

审计的 `extra.trajectory.coverage` 包含 `protocol="responses"`、`input_mode`、
`input_items`、`ignored_model_items` 和 `omitted_tool_outputs`；遗漏的工具结果也计入 `dropped`。
文本仍受单段/总字符预算限制，这不代表全文扫描。审计不保存文档、工具参数、调用 ID 或任务正文。

## 流式响应

```python
with client.responses.create(
    model=os.environ["APP_MODEL"], input="解释资源限制", stream=True, store=False,
) as stream:
    for event in stream:
        if event.type == "response.output_text.delta":
            print(event.delta, end="")
        elif event.type == "prompt_ids.warning":
            print("\n输出检测告警：", event.warning)
```

出站检测会按输出项分别拼接文本增量和函数参数增量，避免交错的工具调用破坏凭据识别。
重复的完成快照不会重复计数；不同输出字段之间保留明确断点。
告警使用额外的 `event: prompt_ids.warning`，位于
`response.completed` / `response.failed` / `response.incomplete` 之前，即使之后还有心跳也如此。
客户端需要显式消费该事件；未发生出站命中时 SSE 原始字节保持不变。

**流式内容已经发出，告警无法撤回文本或已执行的工具操作。** 必须在调用工具前完成应用自己的
授权和参数检查。需要在交付前脱敏时，使用非流式请求：命中的结构化凭据会被替换，Canary 泄漏会触发响应替换。

流式检查仅保存配置预算内的文本，超预算在审计中标记 `secret_sampled=true`。
完整 SSE 帧另受 `max_response_bytes` 限制；帧过大时发出 `response_frame_too_large` 告警并终止连接，
不会伪造成功完成事件。HTTP 响应头此时可能已经是 200，应用还需检查终止事件。

## 首版支持边界

| 形态 | 结果与原因 |
|---|---|
| 文本输入、显式消息历史、应用函数工具与结果 | 支持 |
| `previous_response_id`、`conversation`、`prompt` 引用、`item_reference` | 501，代理看不到上游保存的上下文 |
| `input_image`、`input_file`、音频及未知输入类型 | 501，不能当作已扫描的文本 |
| hosted web/file search、MCP、computer、custom 等非 `function` 工具 | 501，尚未接入这些工具的内容和生命周期 |
| `background=true` | 501，异步结果不在当前检查链路内 |
| `GET /v1/responses/...` 读取、恢复流及输入项列表 | 501，防止绕过出站检查 |
| 无效字段类型、非法角色、空输入 | 400 `invalid_responses_input` |

不支持的形态返回 `responses_scan_unsupported`，响应中只指出字段位置；该类拒绝不算注入命中。
不要通过删掉历史引用来掩盖上下文缺失，应由应用完整重放历史。`store=False` 是示例的存储选择，
代理不会暗中改写调用方的 `store` 参数。

已用本地模拟上游验证 OpenAI Python SDK 2.37.0 的普通调用、`stream=True`、
`responses.stream(...).get_final_response()` 和 403 错误路径；这属于协议验证，未调用外部模型，
也不代表新增了攻击召回率。格式参考 [官方请求文档](https://developers.openai.com/api/reference/resources/responses/methods/create)
和 [官方流式事件文档](https://developers.openai.com/api/reference/resources/responses/streaming-events)。

## English

The proxy now accepts `POST /v1/responses` and `/responses` for explicit text history and
application-run function tools. Point the OpenAI SDK at `http://127.0.0.1:8787/v1`; the upstream
must support Responses itself. This adapter does not translate Chat Completions into Responses.

User text is scanned as `author#-1`. Application instructions and function declarations are scanned
as `system#-1`, using rules only by default. Each `function_call_output` is scanned independently as
`function#N`, where N is its index in the request's `input` array. Existing budgets and tool limits
apply; omitted tool results appear in audit coverage. Model-generated assistant, function-call and
reasoning history follows the existing exclusion policy. Applications must assign roles correctly.

Replay the entire history in `input` on each turn. Hidden context references (`previous_response_id`,
`conversation`, stored `prompt`, `item_reference`), nontext input, hosted/custom tools, background
requests and stored-response GET routes return 501 `responses_scan_unsupported`. Invalid supported
shapes return 400. These responses expose field locations, not input contents.

Nonstreaming output receives secret redaction and Canary checks. Streaming output is assembled per
text or function-argument field. The proxy emits `prompt_ids.warning` before the terminal Responses
event; applications must handle this extra event explicitly. **Streaming warnings cannot retract
content or undo tool actions.** Content beyond the scan budget is reported as partial coverage;
an oversized SSE frame produces a warning and terminates the stream without a fabricated completion.

The examples above use `store=False`; caller request bytes are otherwise preserved. Validation used
OpenAI Python SDK 2.37.0 with a local mock upstream, covering ordinary requests, both streaming APIs,
redaction, warning delivery and blocked inputs. No external model calls or detection-quality claims
are involved.
