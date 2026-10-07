"""OpenAI 兼容透明代理 —— 应用零改造接入。

应用侧只需把 base_url 指向本代理，其余代码一行不用动：

    openai.base_url = "http://127.0.0.1:8787/v1"

代理在请求发出前做入站检测；判定为阻断时直接返回 403，
请求根本不会到达上游，因此也不会产生 token 费用。

凭据一律从环境变量读取，不硬编码、不写进审计日志。
"""
from __future__ import annotations

import http.client
import json
import os
import posixpath
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from prompt_ids.audit import AuditLogger, event_from_proxy
from prompt_ids.audit.events import (
    KIND_PROXY,
    OUTBOUND_NONE,
    OUTBOUND_REDACTED,
    OUTBOUND_REJECTED,
    OUTBOUND_REPLACED,
    OUTBOUND_WARNED,
    AuditEvent,
)
from prompt_ids.canary.tokens import CanaryRegistry
from prompt_ids.core.pipeline import Pipeline, PipelineConfig
from prompt_ids.core.types import Action, ScanResult, level_rank
from prompt_ids.net import warn_if_exposed
from prompt_ids.output import MAX_HITS, redact_bytes, scan_text, summary
from prompt_ids.preprocess.guard import RateLimiter, fingerprint
from prompt_ids.proxy import trajectory
from prompt_ids.proxy.forward import UpstreamError, forward_headers, post_json, post_stream

DEFAULT_PORT = 8787
# 请求体上限。不设的话攻击者可以用超大 Content-Length 吃满内存与 CPU：
# 规则层耗时随长度线性增长（72KB 约 135ms），超大 body 足以拖垮代理
MAX_BODY_BYTES = 2 * 1024 * 1024
#: 需要**检测**的路径。`/v1/messages` 是 Anthropic 原生形态，body 里同样有
#: `messages`，现成的分段提取直接可用 —— 之前它落在「其余路径」里被静默透传，
#: 等于 Anthropic 客户端**完全不过检测**，而这件事没有任何日志或提示。
SCANNED_PATHS = (
    "/v1/chat/completions", "/v1/completions",
    "/chat/completions", "/completions",
    "/v1/messages",
)
#: 明确**不检测**、直接透传的路径。逐个列出来，而不是「不在扫描列表里就透传」——
#: 后者的含义是「将来新增的生成端点会自动被跳过检测」，而这正是静默漏检的来源。
PASSTHROUGH_PATHS = (
    "/v1/models", "/v1/embeddings",
    "/v1/audio/speech", "/v1/audio/transcriptions", "/v1/audio/translations",
    "/v1/images/generations", "/v1/images/edits", "/v1/moderations",
)
#: 已知但**尚未支持检测**的生成端点。明确报 501 而不是透传：
#: 调用方能立刻知道「这里没有防护」，而不是以为检测过了。
UNSUPPORTED_SCAN_PATHS = {
    "/v1/responses": "OpenAI Responses API 的载荷结构（input / instructions）尚未接入分段提取",
    "/v1/complete": "legacy completions 需要 prompt 而非 messages，尚未接入",
}
#: 代理支持的 HTTP 方法。其余返回 JSON 405，而不是 BaseHTTPRequestHandler 的 HTML 501
#: （「所有响应都是 JSON」是本服务的对外约定，HTML 错误页会让 SDK 解析失败）。
SUPPORTED_METHODS = ("GET", "POST", "OPTIONS")


def _first_env(*names: str, default: str = "") -> str:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return default


class ProxyConfig:
    def __init__(
        self,
        upstream: str = "",
        api_key: str | None = None,
        port: int = DEFAULT_PORT,
        host: str = "127.0.0.1",
        audit_path: str | None = None,
        timeout_s: float = 60.0,
        # 判定为 sandbox 时是否仍然放行（False 表示也拦截）
        allow_sandbox: bool = True,
        pipeline: Pipeline | None = None,
        canary: CanaryRegistry | None = None,
        # 检出 Canary 泄漏时是否用告警替换响应（否则只记录审计）
        redact_leak: bool = True,
        # 出站密钥扫描：模型输出里出现第三方凭据就抹掉（AWS/OpenAI/Slack/私钥/JWT…）。
        # 默认开 —— 实测良性语料 5580 条零误报（scripts/output_check.py），
        # 而「模型把 RAG 文档里的密钥复述出去」是 Canary 覆盖不到的出站事故。
        # 代价是把用户答案里**真的**贴了密钥的那一段替换成 [REDACTED:…]；
        # 要放行就 PROMPT_IDS_PROXY_SCAN_SECRETS=0。
        scan_secrets: bool = True,
        # 出站扫描的字符预算。请求侧有 max_total_scan_chars，**响应侧原来一个都没有**：
        # 出站扫描实测 0.126µs/字符（1MB≈126ms、2MB≈258ms），而响应体没有上限 ——
        # 照请求侧的做法加预算，超限走分层取样并把覆盖率记进审计。
        max_response_scan_chars: int = 200_000,
        # 非流式响应体的**内存硬边界**（MB）。超限按上游错误拒收而不是静默给半截响应 ——
        # 半截 JSON 会让调用方解析失败却看不出是代理干的。
        max_response_mb: int = 32,
        # 直接给字节数的版本（测试与小内存部署用；给了就以它为准）
        max_response_bytes: int = 0,
        # 每来源 IP 的请求上限（**默认 0 = 关闭**）。此前代理**完全没有**限流，
        # 而 Guard 里的 rate_limit 是死配置（check_rate 全仓库无调用点）。
        # 生产建议显式打开：默认关是为了不改变既有行为。
        rate_limit: int = 0,
        rate_window_s: float = 60.0,
        # 是否扫描 tool / function 角色的内容（间接注入面，默认开）。
        # 关掉它只为取证用：留一个能跑 A/B 的开关，才能说清「扫工具返回内容」本身
        # 带来多少检出、带来多少过防御。
        scan_tool_messages: bool = True,
        # system/developer 段是否也走语义层。默认 False（只走规则层）——
        # 实测 DeBERTa 3/6、LLM 裁判 4/6 把正常 RAG 系统提示判成注入，而每个
        # RAG 请求都带 system 消息。开成 True 就等于「按内容」判断，
        # 按角色判断才解释得清：这段文字是谁写的。
        semantic_system: bool = False,
        # 单段文本的检测字符上限（超出做分层取样，见 clip_segment）
        max_segment_chars: int = 20_000,
        # 最多扫多少条 tool / function 消息（超出部分不扫，并在审计里记账）
        max_tool_segments: int = 32,
        # 全部段共享的字符预算：规则层约 5.4µs/字符，2MB body ≈ 11s CPU
        max_total_scan_chars: int = 60_000,
        # **客户端**鉴权用的 Key（与 `PROMPT_IDS_UPSTREAM_KEY` 完全是两件事：
        # 后者是给上游的凭据，客户端的 Authorization 头会被透传给它）。
        #
        # 为什么代理现在也需要这个：容器/K8s 部署必然 `--host 0.0.0.0`
        # （Pod 里 127.0.0.1 别的容器摸不到），而此前**没有任何东西挡得住**
        # 同网段的任何人 —— 限流不是鉴权。此前唯一「正确姿势」是文档里的一句话，
        # 没有可运行的示例。现在有了开关与 `scripts/deploy_check.py`。
        #
        # ⚠ 用独立的 env 名而不是复用 `PROMPT_IDS_API_KEY`：复用会让「我给 API
        # 配了鉴权」被误读成「代理也有鉴权」，而那两处的威胁面完全不同。
        # **默认空 = 不鉴权**，保持既有行为不变；对外暴露时 `net.py` 会告警。
        client_key: str = "",
    ):
        self.upstream = (upstream or _first_env("PROMPT_IDS_UPSTREAM", "OPENAI_BASE_URL",
                                                default="https://api.openai.com/v1")).rstrip("/")
        self.api_key = api_key if api_key is not None else _first_env("PROMPT_IDS_UPSTREAM_KEY", "OPENAI_API_KEY")
        # 客户端鉴权用**独立**的 env 名（见 __init__ 里的注释：不能复用
        # PROMPT_IDS_API_KEY，否则「给 API 配了鉴权」会被误读成代理也有）
        self.client_key = client_key or _first_env("PROMPT_IDS_PROXY_CLIENT_KEY", default="")
        self.port = port
        self.host = host
        self.timeout_s = timeout_s
        self.allow_sandbox = allow_sandbox
        self.audit = AuditLogger(audit_path)
        self.pipeline = pipeline
        self.canary = canary
        self.redact_leak = redact_leak
        self.scan_secrets = scan_secrets
        self.scan_tool_messages = scan_tool_messages
        self.max_segment_chars = max(1000, int(_first_env(
            "PROMPT_IDS_PROXY_MAX_SEGMENT_CHARS", default=str(max_segment_chars))
            or max_segment_chars))
        self.max_tool_segments = max(1, int(_first_env(
            "PROMPT_IDS_PROXY_MAX_TOOL_SEGMENTS", default=str(max_tool_segments))
            or max_tool_segments))
        self.max_total_scan_chars = max(1000, int(_first_env(
            "PROMPT_IDS_PROXY_MAX_TOTAL_SCAN_CHARS", default=str(max_total_scan_chars))
            or max_total_scan_chars))
        self.max_response_scan_chars = max(1000, int(_first_env(
            "PROMPT_IDS_PROXY_MAX_RESPONSE_SCAN_CHARS", default=str(max_response_scan_chars))
            or max_response_scan_chars))
        self.max_response_bytes = max(
            1024, int(max_response_bytes) if max_response_bytes
            else max(1, int(_first_env("PROMPT_IDS_PROXY_MAX_RESPONSE_MB",
                                       default=str(max_response_mb)) or max_response_mb))
            * 1024 * 1024)
        self.rate_limit = int(_first_env("PROMPT_IDS_PROXY_RATE_LIMIT",
                                         default=str(rate_limit)) or rate_limit)
        self.rate_window_s = float(_first_env("PROMPT_IDS_PROXY_RATE_WINDOW_S",
                                              default=str(rate_window_s)) or rate_window_s)
        self.limiter = (
            RateLimiter(self.rate_limit, self.rate_window_s)
            if self.rate_limit and self.rate_limit > 0
            else None
        )
        env_scan = _first_env("PROMPT_IDS_PROXY_SCAN_TOOL")
        if env_scan:
            # 显式开关优先于构造参数：代理是长驻进程，运维改环境变量比改代码现实
            self.scan_tool_messages = env_scan not in ("0", "false", "no", "off")
        env_sys = _first_env("PROMPT_IDS_PROXY_SEMANTIC_SYSTEM")
        self.semantic_system = (
            env_sys in ("1", "true", "yes", "on") if env_sys else bool(semantic_system)
        )
        env_secret = _first_env("PROMPT_IDS_PROXY_SCAN_SECRETS")
        if env_secret:
            self.scan_secrets = env_secret not in ("0", "false", "no", "off")

    def leak_check(self, text: str):
        """出站检测：模型输出里是否出现了 Canary 令牌。"""
        if not self.canary or not text:
            return None
        return self.canary.check(text)

    def secret_check(self, text: str):
        """出站检测：模型输出里是否出现了第三方凭据（与 Canary 语义不同，见 output.secrets）。

        返回 (命中列表, 是否取样, 实际扫描字符数)：
        - 超预算走**分层取样**（复用请求侧的 `clip_segment`，不另写一套），
        - 取样必须回报，否则「只看了开头」与「完整看过」在日志里长得一样。
        """
        if not self.scan_secrets or not text:
            return [], False, 0
        sampled, truncated = clip_segment(text, self.max_response_scan_chars)
        result = scan_text(sampled)
        return list(result.hits), truncated, len(sampled)

    @property
    def pipeline_instance(self) -> Pipeline:
        if self.pipeline is None:
            self.pipeline = Pipeline(config=PipelineConfig(enable_cache=True))
        return self.pipeline


# ---------------------------------------------------------------- 分段
# 代理要面对几类来源，检测策略不该一样：
#   1. user / human —— 合成一段。多轮上下文合起来看才有意义，拆开单看每轮会把
#      「上文提到 X、本轮问 X」这类正常请求切碎。走完整流水线（含 L3）。
#   2. system / developer —— **应用自己写的**，与 3 分开成段并默认只走规则层。
#      理由见 `SYSTEM_ROLES` 上面的说明（实测 L3 会把正常 RAG 系统提示判成注入）。
#   3. tool / function 返回的内容 —— **间接注入面**。这些文本来自检索库、网页、
#      外部 API，攻击者不需要碰你的应用就能把指令塞进来。逐条独立成段：合成一段会让
#      攻击者把注入拆到两条文档里互相掩护，也让审计说不清是哪一条命中的。走完整流水线。
#   4. assistant —— 默认不扫。它是模型自己的输出：上一轮被注入后模型复述载荷，
#      扫它得到的是「模型已经照做了」的噪声，不是「输入有害」的信号。
AUTHOR_ROLES = frozenset({"user", "human", ""})
#: 应用自己写的消息。不是用户输入，且**每个请求都带** —— 这两点决定了它不能和其他
#: 段共用一条检测策略：DeBERTa / LLM 裁判把「对助手下的祈使句」判成注入
#: （实测 6 条典型 RAG 系统提示误杀 3~4 条，p 最高 0.9998，中文系统提示也中招），
#: 而系统提示按定义就是对助手的祈使句。合在一起扫等于「按内容」判断，按角色判断才
#: 能解释：这段文字是谁写的，比它写了什么更决定该不该信。
SYSTEM_ROLES = frozenset({"system", "developer"})
TOOL_ROLES = frozenset({"tool", "function"})
SKIPPED_ROLES = frozenset({"assistant", "model"})


@dataclass(frozen=True, slots=True)
class Segment:
    """一条待检测文本，带来源标记（审计里只留 role#index，不留内容）。

    `rules_only` 表示这一段**不走语义层**。目前只有 system/developer 段会置位。
    """

    role: str
    index: int
    text: str
    truncated: bool = False
    rules_only: bool = False

    @property
    def tag(self) -> str:
        return f"{self.role}#{self.index}"


def _message_text(item: dict[str, Any]) -> str:
    """取出单条消息的文本部分（兼容多模态 content 数组）。"""
    content = item.get("content")
    if isinstance(content, list):
        return " ".join(
            str(part.get("text", "")) for part in content if isinstance(part, dict)
        )
    return content if isinstance(content, str) else ""


_GAP = "\n[…跳过若干字符…]\n"


def clip_segment(text: str, limit: int) -> tuple[str, bool]:
    """超长文本做**分层取样**，返回 (文本, 是否截断)。

    只取头尾是不够的：间接注入既能藏在文档末尾（「IMPORTANT: ignore all previous
    instructions」），也能藏在正中间某段「注意事项」里 —— 实测把载荷放在长文档中段时，
    纯头尾取样的 block 召回是 **0.0000**（review 口径 0.99，即所有注入都掉到了
    medium 那一档，等于没检出）。所以这里头尾各留 30%，中间摊成 4 个等距窗口。

    窗口之间必须插 `_GAP`：直接拼接会把「窗口 A 结尾的 ignore all」和
    「窗口 B 开头的 previous instructions」粘成原文里并不存在的一句话 ——
    取样自己造出来的假阳性比漏检更难解释。

    截断必须回报给调用方 —— 静默截断就是静默漏检。
    """
    if len(text) <= limit:
        return text, False
    keep = limit - (len(_GAP) + 1) * 5
    if keep < 400:  # limit 极小，退化成纯头尾
        head = limit // 2
        return f"{text[:head]}{_GAP}{text[-(limit - head):]}", True
    edge = int(keep * 0.3)
    window = (keep - 2 * edge) // 4
    middle = text[edge: len(text) - edge]
    span = len(middle)
    parts = [text[:edge]]
    for i in range(4):
        start = int(span * i / 4)
        parts.append(middle[start:start + window])
    parts.append(text[len(text) - edge:])
    return _GAP.join(parts), True



def extract_segments(payload: dict[str, Any], config: ProxyConfig) -> list[Segment]:
    """把请求体拆成待检测段。

    - messages 里的 user/human 合成一段（保持既有行为）
    - system/developer 合成另一段，默认只走规则层（见 SYSTEM_ROLES 说明）
    - tool/function 逐条成段（间接注入面）；数量受 max_tool_segments 限制
    - assistant/model 不扫（理由见上面注释）
    - prompt 字段（补全接口形态）单独成一段
    """
    author_parts: list[str] = []
    system_parts: list[str] = []
    segments: list[Segment] = []
    tool_count: list[int] = []
    messages = payload.get("messages")
    if isinstance(messages, list):
        for index, item in enumerate(messages):
            if not isinstance(item, dict):
                continue
            role = str(item.get("role", "")).lower()
            if role in SKIPPED_ROLES:
                continue
            text = _message_text(item)
            if not text.strip():
                continue
            if role in TOOL_ROLES:
                if not config.scan_tool_messages:
                    continue
                if len(tool_count) >= config.max_tool_segments:
                    continue
                clipped, truncated = clip_segment(text, config.max_segment_chars)
                if not clipped.strip():
                    continue
                tool_count.append(index)
                segments.append(Segment(role or "tool", index, clipped, truncated))
            elif role in SYSTEM_ROLES:
                system_parts.append(text)
            else:
                author_parts.append(text)

    if author_parts:
        clipped, truncated = clip_segment("\n".join(author_parts), config.max_segment_chars)
        segments.insert(0, Segment("author", -1, clipped, truncated))
    # system 段最后插入到最前：命中它时能在审计里第一时间看出「是应用自己的配置有问题」
    if system_parts:
        clipped, truncated = clip_segment("\n".join(system_parts), config.max_segment_chars)
        segments.insert(0, Segment("system", -1, clipped, truncated,
                                    rules_only=not config.semantic_system))

    prompt = payload.get("prompt")
    if isinstance(prompt, str) and prompt.strip():
        clipped, truncated = clip_segment(prompt, config.max_segment_chars)
        segments.append(Segment("prompt", -1, clipped, truncated))
    elif isinstance(prompt, list) and prompt:
        joined = "\n".join(str(p) for p in prompt)
        clipped, truncated = clip_segment(joined, config.max_segment_chars)
        segments.append(Segment("prompt", -1, clipped, truncated))
    return segments


def extract_prompt(payload: dict[str, Any]) -> str:
    """从 OpenAI 兼容请求体里取出待检测文本（所有段拼起来）。

    保留这个函数是为了兼容既有调用方与测试；**代理主流程走 extract_segments**，
    因为它要按来源分段检测并记账（见那里的三类来源说明）。
    """
    config = ProxyConfig(scan_tool_messages=True)
    return "\n".join(seg.text for seg in extract_segments(payload, config)).strip()


#: 预算剩余不足这么多字符时就不再扫了：扫 200 个字符既没有检出价值，
#: 又会让审计里出现一串「扫过了但什么也没看」的记录。
MIN_SCAN_CHARS = 500


@dataclass(frozen=True, slots=True)
class SegmentScan:
    """一次分段检测的结果与「覆盖账」。

    覆盖账必须跟着结果一起走：截断了几段、丢了几段、总共扫了多少字符。
    没有它，一次 medium 判定和一个「其实只看了开头」的 medium 判定长得一模一样。
    """

    result: Any
    trigger: Segment | None
    truncated: int = 0
    dropped: int = 0
    scanned_chars: int = 0
    #: 逐段判定的**纯索引**轨迹（role#index / level / score / pattern_id，无原文）。
    #: 以前这里只留最严重的那一段，于是「注入从哪一条进来的」在日志里查不到 ——
    #: 而那恰恰是排查 agent 被注入时第一个要回答的问题。
    steps: tuple = ()


def _allocate(segments: list[Segment], budget: int) -> tuple[list[tuple[Segment, str, bool]], int]:
    """按预算**公平**分配每段能扫多少字。

    返回 ([(段, 待扫文本, 是否被取样)], 段数)。分配规则：

    - 应用自己写的段（user/system/developer）优先按它自己的上限拿满 —— 那是主向量，
      前面实测过：多轮上下文拆开单看会被切碎，不能省。
    - 剩下的预算被**所有工具段均分**。

    均分这条是关键。早期的「先到先得」分配下，攻击者只要在注入文档前面塞 31 条
    无关文档，就能把自己的那段挤出预算 —— 实测最坏情况下判定从 critical 掉到 low，
    而日志一切正常。先到先得把预算当成了攻击者能操纵的资源。
    """
    if not budget:
        return [(s, s.text, False) for s in segments], 0
    tool_pos = [i for i, s in enumerate(segments) if s.role in TOOL_ROLES]
    tool_set = set(tool_pos)
    plan: list[tuple[Segment, str, bool] | None] = [None] * len(segments)
    spent = 0
    for i, seg in enumerate(segments):
        if i in tool_set:
            continue
        room = budget - spent
        if room < MIN_SCAN_CHARS:
            break
        if len(seg.text) > room:
            text, cut = clip_segment(seg.text, room)
        else:
            text, cut = seg.text, False
        plan[i] = (seg, text, cut)
        spent += len(text)
    if tool_pos:
        share = (budget - spent) // len(tool_pos)
        for i in tool_pos:
            seg = segments[i]
            if share < MIN_SCAN_CHARS:
                plan[i] = None  # 预算渣到扫了也没意义
                continue
            if len(seg.text) > share:
                text, cut = clip_segment(seg.text, share)
            else:
                text, cut = seg.text, False
            plan[i] = (seg, text, cut) if text.strip() else None
    return [p for p in plan if p is not None], sum(1 for p in plan if p is None)


def scan_segments(pipeline: Pipeline, segments: list[Segment],
                  *, budget_chars: int = 0) -> SegmentScan:
    """逐段检测，返回最严重的那个结果 + 覆盖账。

    取最严重而不是求和/平均：几段里有一段 critical 就是这次请求有 critical，
    平均会让不可信数据稀释掉强证据（同一个坑，融合层已经踩过一次）。

    `budget_chars` 是**全部段共享**的字符预算：规则层约 5.4µs/字符（实测 80KB≈430ms），
    而 body 上限 2MB 意味着一次请求能塞进 200 万字符 = 11 秒 CPU。不设总预算，
    「扫工具内容」就把代理变成了一个可被文档体积放大的放大器。
    """
    plan, dropped = _allocate(segments, budget_chars)
    worst = None
    worst_seg: Segment | None = None
    truncated = scanned = 0
    results: list = []
    for seg, text, cut in plan:
        result = pipeline.scan(text, semantic=False if seg.rules_only else None)
        results.append(result)
        scanned += len(text)
        truncated += int(seg.truncated or cut)
        if worst is None or (level_rank(result.level), result.score) > (
            level_rank(worst.level), worst.score
        ):
            worst, worst_seg = result, seg
    # 逐段判定记成纯索引轨迹（不含原文）。构造放在最后：它会断言
    # 「计划与结果一一对应」，数量对不上时要响亮失败而不是少记一步。
    steps = trajectory.build_steps(plan, results)
    return SegmentScan(worst, worst_seg, truncated, dropped, scanned, steps)


def decide(result, config: ProxyConfig, trigger: Segment | None = None) -> tuple[str, int, str]:
    """返回 (决策, HTTP 状态码, 说明)。

    `trigger` 非空时说明命中来自哪一段。只报 role 不报内容 —— 调用方看得到自己发的
    请求，但「命中来自工具返回内容」这条信息必须给出去：否则应用方会去查用户输入，
    而真正的入口是它自己检索回来的文档。
    """
    where = ""
    if trigger is not None and trigger.role in TOOL_ROLES:
        where = "（命中来自工具返回内容）"
    if result.action is Action.BLOCK:
        return "block", 403, f"请求被提示词注入防护拦截{where}"
    if result.action is Action.SANDBOX and not config.allow_sandbox:
        return "sandbox", 403, f"请求被判定为高风险，已隔离{where}"
    if result.action is Action.SANDBOX:
        return "sandbox", 200, f"高风险命中，已放行但记录审计{where}"
    if result.action is Action.REVIEW:
        return "review", 200, f"中等风险，已放行并记录{where}"
    return "allow", 200, ""


class ProxyHandler(BaseHTTPRequestHandler):
    server_version = "prompt-ids-proxy/0.1"
    config: ProxyConfig  # 由 create_server 注入

    # ---------- 基础 ----------
    def log_message(self, fmt: str, *args) -> None:
        # 默认实现会往 stderr 打访问日志，代理场景交由审计模块负责
        pass

    def _send_json(self, status: int, obj: dict[str, Any]) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _relay_response(self, status: int, headers: dict[str, str], *,
                         body_modified: bool = False) -> None:
        """把上游响应头搬回来。

        `body_modified=True` 时剥掉**表示层校验头**：脱敏改写了 body 之后，
        原样转发 `ETag` / `Content-MD5` / `Digest` 会让客户端的完整性校验必然失败
        （而失败信息只会指向客户端，不会指向代理这次改写）。
        """
        skip = {"transfer-encoding", "content-length", "connection"}
        if body_modified:
            skip |= {"etag", "content-md5", "digest", "content-digest"}
        self.send_response(status)
        for key, value in headers.items():
            if key.lower() in skip:
                continue
            self.send_header(key, value)
        self.end_headers()

    # ---------- 路由 ----------
    def _rate_limited(self) -> bool:
        """按来源 IP 限流（默认关闭，`rate_limit=0`）。

        为什么按 IP：代理把客户端的 Authorization 头透传给上游，自己没有可验证的
        调用方身份 —— 拿请求头当分桶键等于「换个 key 换桶」，限流形同虚设。
        """
        limiter = self.config.limiter
        if limiter is None:
            return False
        return not limiter.try_acquire(str(self.client_address[0]))

    def _too_many_requests(self, path: str = "", result=None) -> None:
        """回 429，并**落一条审计**。

        限流发生在读 body 与检测之前，所以这条事件没有指纹、也没有判定 ——
        但必须留痕：否则「限流把请求挡了」在日志里完全看不见，
        而运维看到的是「请求数变少了」，猜不出原因。
        """
        retry = max(1, int(self.config.rate_window_s))
        note = f"超过限流（{self.config.rate_limit} 次/{retry}s），未做检测"
        self.config.audit.log(
            event_from_proxy(result or ScanResult(), path=path or self._upstream_path(),
                             client=self.client_address[0], stream=False, detect_ms=0.0,
                             status=429, decision="rate_limited", note=note))
        body = json.dumps({"error": {
            "message": f"超过限流（{self.config.rate_limit} 次/{retry}s），请稍后再试",
            "type": "rate_limited", "code": "rate_limited"}}, ensure_ascii=False).encode()
        self.send_response(429)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Retry-After", str(retry))
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _method_not_allowed(self) -> None:
        """未实现的方法返回 JSON 405。

        BaseHTTPRequestHandler 的默认实现回的是 **HTML** 501 错误页 ——
        与「所有响应都是 JSON」的对外约定冲突，SDK 侧会在解析错误体时再炸一次。
        """
        self._send_json(405, {"error": {
            "message": f"不支持的方法 {self.command}；支持 {'/'.join(SUPPORTED_METHODS)}",
            "type": "method_not_allowed", "code": "method_not_allowed"}})

    def do_GET(self) -> None:
        # 健康检查**不鉴权**：编排系统（compose / K8s）探针通常不带自定义头，
        # 而 /healthz 只回 {status, upstream}，没有敏感信息。
        # ⚠ upstream 那部分是 URL —— 别把它当成「无害」：某些网关把凭据放
        # query 里。所以这里只回「配置了没配置」，不回 URL 本身。
        if self.path.rstrip("/") in ("/healthz", "/health"):
            self._send_json(200, {"status": "ok",
                                  "upstream_configured": bool(self.config.upstream)})
            return
        if not self._client_authorized():
            self._send_json(401, {"error": {
                "message": "缺少或错误的客户端 Key（X-API-Key）",
                "type": "unauthorized", "code": "unauthorized"}})
            return
        self._passthrough("GET", b"")

    # 其余方法统一走 JSON 405，而不是 BaseHTTPRequestHandler 的 HTML 501
    do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _method_not_allowed

    def _content_length(self) -> int:
        raw = (self.headers.get("Content-Length") or "").strip()
        if not raw:
            return 0
        try:
            value = int(raw)
        except ValueError as exc:
            raise ValueError("Content-Length 不是合法整数") from exc
        if value < 0:
            # rfile.read(-1) 会一直读到对端关闭 —— 若干个慢连接就能把线程耗死
            raise ValueError("Content-Length 不能为负")
        return value

    def _drain(self, length: int) -> None:
        """把请求体分块读干净（不装进内存），避免回 RST。"""
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            remaining -= len(chunk)

    def _drain_chunked(self, *, max_bytes: int = MAX_BODY_BYTES) -> tuple[bool, int]:
        """丢弃一个 chunked 请求体，返回 (是否读完, 读了多少字节)。

        必须真的读掉再回 411：与 413 同理，客户端还在发 body 时服务端写错误并
        关连接 ⇒ RST，调用方看到的是 ConnectionAbortedError 而不是 411。
        超过 `max_bytes` 就放弃读完（那是超大 body，本就该被拒），此时靠
        `Connection: close` 收尾。
        """
        total = 0
        while True:
            line = self.rfile.readline(1024)
            if not line:
                return False, total
            try:
                size = int(line.split(b";", 1)[0].strip() or b"0", 16)
            except ValueError:
                return False, total
            if size == 0:
                # 读掉 trailer 直到空行
                while True:
                    trailer = self.rfile.readline(1024)
                    if not trailer or trailer in (b"\r\n", b"\n"):
                        break
                return True, total
            remaining = size
            total += size
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    return False, total
                remaining -= len(chunk)
            self.rfile.read(2)          # CRLF
            if total > max_bytes:
                return False, total

    def _client_authorized(self) -> bool:
        """客户端鉴权（`PROMPT_IDS_PROXY_CLIENT_KEY`，默认空 = 不鉴权）。

        ⚠ 与 `self.config.api_key` **完全无关**：那个是给上游的凭据，
        而客户端的 Authorization 头会被**透传**给它（`_upstream_headers`）。
        混用会导致「客户端令牌顶掉上游凭据」或「上游凭据被当成客户端令牌」。
        """
        from prompt_ids.auth import authorized

        return authorized(self.headers, self.config.client_key)

    def _reject_unauthorized(self) -> None:
        """401。**先排空 body 再响应**，否则客户端收到的是 RST 而不是 401
        （与 413 / 411 同一个坑，本项目已因此复发三次）。"""
        self._drain(len(self.headers.get("Content-Length") or 0) or 0)
        if self.headers.get("Transfer-Encoding", "").lower().strip() == "chunked":
            self._drain_chunked()
        self._send_json(401, {"error": {
            "message": "缺少或错误的客户端 Key（X-API-Key）",
            "type": "unauthorized", "code": "unauthorized"}})

    def do_POST(self) -> None:
        # 鉴权在读 body **之前**：与限流同一个理由 —— 否则被拒的请求仍然能
        # 把 2MB body 灌进代理，等于给未鉴权的调用方一个免费的流量放大器。
        if not self._client_authorized():
            self._reject_unauthorized()
            return
        # 限流在**读 body 之前**判：否则被限流的请求仍然能把 2MB body 灌进代理
        if self._rate_limited():
            self._drain(len(self.headers.get("Content-Length") or 0) or 0)
            self._too_many_requests()
            return
        try:
            length = self._content_length()
        except ValueError:
            # Content-Length 非法值：400 而不是 int() 的 ValueError 冒泡成 traceback
            self._send_json(400, {"error": "Content-Length 不是合法整数"})
            return
        if length > MAX_BODY_BYTES:
            # 先把请求体读掉再拒绝：否则客户端还在发送时关闭连接会触发 RST，
            # 调用方（如 OpenAI SDK）看到的是 ConnectionResetError 而不是清晰的 413。
            # 分块丢弃，不把整个 body 装进内存。
            self._drain(length)
            self._send_json(413, {"error": {
                "message": f"请求体过大（{length} 字节 > 上限 {MAX_BODY_BYTES}）",
                "type": "payload_too_large", "code": "payload_too_large"}})
            return
        body = self.rfile.read(length) if length else b""
        if self.headers.get("Transfer-Encoding", "").lower().strip() == "chunked":
            # 不支持分块：静默当空 body 会让扫描路径报 400、而**非**扫描路径
            # （如 /v1/embeddings）把空 body 转发给上游，调用方的数据无声消失。
            # 先把 chunked body 读干净再回 411，否则又是 RST（同一个坑的另一种形态）。
            drained, total = self._drain_chunked()
            self.close_connection = True
            self._send_json(411, {"error": {
                "message": "不支持 Transfer-Encoding: chunked，请带 Content-Length",
                "code": "length_required"}})
            return
        path = self._upstream_path()

        if path in UNSUPPORTED_SCAN_PATHS:
            # 响亮失败：明确知道「这里没有防护」，好过静默透传让人以为检测过了
            self._send_json(501, {"error": {
                "message": f"{path} 尚未接入检测：{UNSUPPORTED_SCAN_PATHS[path]}。"
                           f"请改用 {'/'.join(SCANNED_PATHS[:2])}，或让应用直接指向上游。",
                "type": "scan_unsupported", "code": "scan_unsupported"}})
            return
        if path not in SCANNED_PATHS:
            if path in PASSTHROUGH_PATHS:
                self._passthrough_post(path, body)
                return
            # 未知路径：不转发。一个没被列进来的新端点如果被自动透传，
            # 等于「新增生成端点 = 自动失去检测」，而没人会看到这件事发生。
            self._send_json(404, {"error": {
                "message": f"未识别的路径 {path}。检测路径：{'/'.join(SCANNED_PATHS)}；"
                           f"直通路径：{'/'.join(PASSTHROUGH_PATHS)}",
                "type": "unknown_path", "code": "unknown_path"}})
            return

        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"error": "请求体不是合法 JSON"})
            return
        if not isinstance(payload, dict):
            self._send_json(400, {"error": "请求体必须是 JSON 对象"})
            return

        segments = extract_segments(payload, self.config)
        if not segments:
            self._passthrough("POST", body)
            return

        pipeline = self.config.pipeline_instance
        started = time.perf_counter()
        scan = scan_segments(pipeline, segments,
                             budget_chars=self.config.max_total_scan_chars)
        detect_ms = (time.perf_counter() - started) * 1000
        result, trigger = scan.result, scan.trigger
        decision, status, note = decide(result, self.config, trigger)
        # 指纹覆盖所有**实际扫过**的文本：谁被拦下，指纹就该对得上被扫的那部分
        text = "\n".join(seg.text for seg in segments)
        coverage = dict(segments=len(segments), trigger=trigger.tag if trigger else "",
                        truncated=scan.truncated, dropped=scan.dropped,
                        scanned_chars=scan.scanned_chars)
        # 轨迹**单独传**，不混进 coverage：coverage 是 splat 进 event_from_proxy 的
        # 关键字参数集合，而轨迹要先在 proxy 侧转成 dict（audit 层不能反向 import
        # proxy —— proxy 已经依赖 audit 了）。
        traj = trajectory.to_dict(
            scan.steps,
            coverage={"segments": len(segments), "budget_chars": self.config.max_total_scan_chars,
                      "scanned_chars": scan.scanned_chars,
                      "truncated": scan.truncated, "dropped": scan.dropped})

        if decision == "block":
            self.config.audit.log(
                event_from_proxy(
                    result, path=path, client=self.client_address[0], stream=False,
                    detect_ms=detect_ms, status=status, decision=decision, note=note, text=text,
                    trajectory=traj,
                    **coverage,
                )
            )
            self._send_json(
                403,
                {
                    "error": {
                        "message": note,
                        "type": "prompt_injection_blocked",
                        "code": "injection_detected",
                    },
                    "prompt_ids": {
                        "score": result.score,
                        "level": result.level.value,
                        "action": result.action.value,
                        "findings": [f.pattern_id for f in result.findings][:10],
                        "explained": result.explained,
                        "trigger": trigger.tag if trigger else "",
                        # 纯索引轨迹：告诉调用方「注入从哪一条进来」。
                        # ⚠ 只给 role#index 与命中规则，**不回显内容** ——
                        #   调用方看得到自己发的请求，能自己对回那一条。
                        "trajectory": trajectory.to_dict(
                            scan.steps,
                            coverage={"segments": len(segments),
                                      "truncated": scan.truncated,
                                      "dropped": scan.dropped,
                                      "scanned_chars": scan.scanned_chars}),
                    },
                },
            )
            return

        self._forward(path, body, payload, result, decision, detect_ms, text,
                        steps=scan.steps, **coverage)

    # ---------- 转发 ----------
    def _build_headers(self) -> dict[str, str]:
        headers = forward_headers(self.headers)
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        headers["Content-Type"] = "application/json"
        return headers

    def _stream_body(self, chunks, path: str, result, status: int, detect_ms: float,
                     text: str, segments: int, trigger: str, truncated: int,
                     dropped: int, scanned_chars: int, started: float):
        """转发 SSE 流并做**出站**检测，返回 (出站处置, 说明, 类别计数, 是否取样, 扫描字符数)。

        这里**不落审计**：出站结论由 `_forward` 统一写成一条事件（一次请求一条），
        此前流式路径自己发两条事件（leak / secret_leak），
        与非流式路径的重复计数是同一个毛病。

        转发 SSE 流并做**出站**检测（Canary + 密钥）。

        三个坑在这里处理：
        1) **按完整帧转发，且最后一帧要扣住**。告警帧必须排在 `data: [DONE]` **之前**：
           OpenAI / Anthropic 官方 SDK 与任何合规 SSE 解析器读到 `[DONE]` 就停止消费，
           追加在后面的帧会被丢弃 —— 也就是「最常见的用法收不到告警」。
           而 `[DONE]` 在读到流尾之前无法与别的帧区分，所以**每帧都先扣住**，
           收到下一帧再把上一帧发出去（代价是一帧的延迟，对 SSE 无关紧要）。
        2) **累积缓冲必须有上限**。原本整个流进内存，而 `timeout_s` 是每次 socket
           操作的超时，一个稳定吐数据的长流永远不会超时 ⇒ 内存无界增长。
           超限后停止累积（仍照常转发，只是不再扫尾部）并记审计。
        3) **逐帧取内容再拼接**才能认出跨帧的凭据（见 `_response_text`）。
        """
        budget = self.config.max_response_scan_chars
        buffered = bytearray()      # 只用于出站检测，受 budget 限制
        pending = bytearray()       # 尚未凑满一个 SSE 帧的部分
        held: bytes = b""           # 已凑成帧但还没发的「上一帧」
        capped = False

        def absorb(data: bytes) -> None:
            nonlocal capped
            if len(buffered) < budget:
                take = data[: budget - len(buffered)]
                buffered.extend(take)
                if len(take) < len(data):
                    capped = True
            else:
                capped = True

        def flush_held() -> None:
            nonlocal held
            if held:
                self.wfile.write(held)
                self.wfile.flush()
                held = b""

        for chunk in chunks:
            if not chunk:
                continue
            absorb(chunk)
            pending.extend(chunk)
            while True:
                cut = pending.find(b"\n\n")
                if cut < 0:
                    break
                frame = bytes(pending[: cut + 2])
                del pending[: cut + 2]
                flush_held()      # 上一帧现在确定不是最后一帧了
                held = frame

        scanned = bytes(buffered).decode("utf-8", "replace")
        leak = self.config.leak_check(scanned)
        secrets_found, secret_sampled, secret_chars = self.config.secret_check(
            _response_text(scanned))
        notices = b""
        if leak is not None:
            notices += _leak_event(leak)
        if secrets_found:
            notices += _secret_event(secrets_found[:MAX_HITS])

        # 收尾：先补没凑成帧的尾巴，再按 [notices] + [最后一帧] 的顺序发。
        if pending:
            flush_held()
            held = bytes(pending)
        if notices:
            self.wfile.write(notices)
            self.wfile.flush()
        flush_held()

        # 出站处置：流式一律是「已发出、无法撤回」⇒ warned。
        # 「无法撤回」这句话也进审计 note —— 别把它读成已拦住。
        if leak is not None:
            detail = f"Canary 泄漏({leak.how})（流式，内容已发出，无法撤回，只能事后告警）"
        elif secrets_found:
            detail = (f"出站密钥 {len(secrets_found)} 处"
                      "（流式，内容已发出，无法撤回，只能事后告警）")
        else:
            detail = ""
        out = OUTBOUND_WARNED if (leak is not None or secrets_found) else OUTBOUND_NONE
        return out, detail, summary(secrets_found), secret_sampled or capped, secret_chars

    def _forward(
        self,
        path: str,
        body: bytes,
        payload: dict[str, Any],
        result,
        decision: str,
        detect_ms: float,
        text: str = "",
        segments: int = 0,
        trigger: str = "",
        truncated: int = 0,
        dropped: int = 0,
        scanned_chars: int = 0,
        steps: tuple = (),
    ) -> None:
        url = self._upstream_url(path)
        headers = self._build_headers()
        stream = bool(payload.get("stream"))
        started = time.perf_counter()
        # 出站结论先攒着，**最后只落一条事件**。此前为记录出站结论会额外发一条
        # `redact_secrets`/`leak`/`secret_leak` 事件 ⇒ by_decision 把一次请求数成两次，
        # 而且三个名字语义重叠（都是「响应里有凭据」）。
        outbound = OUTBOUND_NONE
        outbound_detail = ""
        secret_kinds: dict[str, int] = {}
        secret_sampled = False
        secret_chars = 0

        def audit_one(status_code: int, note: str, *, upstream_ms: float,
                      out: str | None = None, detail: str | None = None) -> None:
            """一次请求一条事件。`out` 是出站处置，与 decision 正交。

            ⚠ 默认值必须用 None 再回退到闭包变量：写成 `out: str = outbound`
            会在**定义时**求值，把出站结论永远冻在 `none`（踩过：脱敏生效了、
            审计里 outbound 却是 none）。
            """
            self.config.audit.log(
                event_from_proxy(result, path=path, client=self.client_address[0], stream=stream,
                                 upstream_ms=upstream_ms, detect_ms=detect_ms, status=status_code,
                                 decision=decision, note=note, text=text, segments=segments,
                                 trigger=trigger, truncated=truncated, dropped=dropped,
                                 scanned_chars=scanned_chars, secret_kinds=secret_kinds,
                                 secret_sampled=secret_sampled,
                                 secret_scanned_chars=secret_chars,
                                 outbound=outbound if out is None else out,
                                 outbound_detail=outbound_detail if detail is None else detail,
                                 trajectory=trajectory.to_dict(steps, coverage={
                                     "segments": len(steps),
                                     "budget_chars": self.config.max_total_scan_chars,
                                     "scanned_chars": scanned_chars,
                                     "truncated": truncated,
                                     "dropped": dropped,
                                 }))
            )

        try:
            if stream:
                status, resp_headers, chunks, _, close_upstream = post_stream(
                    url, body, headers, self.config.timeout_s)
                self._relay_response(status, resp_headers)
                try:
                    outbound, outbound_detail, secret_kinds, secret_sampled, secret_chars = \
                        self._stream_body(chunks, path, result, status, detect_ms, text,
                                          segments, trigger, truncated, dropped,
                                          scanned_chars, started)
                finally:
                    # 任何退出路径都关上游连接（生成器未被启动时它的 finally 不会跑）
                    close_upstream()
            else:
                status, resp_headers, payload_bytes, _ = post_json(
                    url, body, headers, self.config.timeout_s,
                    max_bytes=self.config.max_response_bytes)
                # gzip 响应会让出站扫描**静默失效**：解析失败、正则扫压缩字节必然 0 命中，
                # 而日志显示一切正常。请求侧已经钉了 accept-encoding: identity，
                # 但并非所有网关都尊重 —— 遇到就拒收并说清原因。
                encoding = {k.lower(): v for k, v in (resp_headers or {}).items()}.get(
                    "content-encoding", "identity")
                if encoding not in ("", "identity"):
                    audit_one(502, f"上游回了 {encoding} 响应，出站扫描无法保证，已拒收",
                              upstream_ms=(time.perf_counter() - started) * 1000,
                              out=OUTBOUND_REJECTED, detail=f"content-encoding:{encoding}")
                    self._send_json(502, {"error": {
                        "message": f"上游返回 {encoding} 编码的响应，出站检测无法保证，已拒收",
                        "code": "unsupported_content_encoding"}})
                    return
                # 一次 decode 供两处用：Canary 与密钥扫描都只认「模型输出文本」，
                # 而脱敏必须按**原始响应体**的偏移就地替换（见下面注释）。
                payload_text = payload_bytes.decode("utf-8", "replace")
                leak = self.config.leak_check(_response_text(payload_text))
                # 密钥扫描扫**整个响应体**，不是 _response_text 抽出来的 content：
                # 1) redact 按偏移就地替换，偏移必须与被切的字符串同源，否则改不到东西；
                # 2) tool_calls[].function.arguments 才是凭据最常漏出去的地方 ——
                #    「把 API key 写进配置文件」这类请求根本不出现在 message.content 里。
                secrets_found, secret_sampled, secret_chars = self.config.secret_check(payload_text)
                if secrets_found:
                    # 非流式可以真正拦住：把命中片段就地抹成 [REDACTED:<kind>]，
                    # 审计只记类别与计数，不记原文（密钥进了审计文件就是新的泄露面）。
                    payload_bytes = redact_bytes(payload_bytes, secrets_found)
                    secret_kinds = summary(secrets_found)
                    outbound = OUTBOUND_REDACTED
                    outbound_detail = f"出站密钥 {len(secrets_found)} 处已脱敏"
                if leak is not None:
                    outbound = OUTBOUND_REPLACED
                    outbound_detail = f"Canary 泄漏({leak.how})，响应已替换"
                if leak is not None and self.config.redact_leak:
                    # 令牌已经出现在输出里，原文不能再往前传，换成告警。
                    # 状态码沿用上游的：post_json 对 4xx/5xx 不抛异常，硬写 200 会让
                    # SDK 把「上游鉴权失败」读成「请求成功了」。
                    audit_one(status, outbound_detail,
                              upstream_ms=(time.perf_counter() - started) * 1000)
                    self._send_json(status, _leak_warning(leak))
                    return
                # 不重新 json.loads 再序列化：payload_bytes 已经在手上了，
                # 而且上游可能根本不是 JSON（`stream:false` 被忽略时回 SSE）。
                self._relay_response(status, resp_headers, body_modified=bool(secrets_found))
                self.wfile.write(payload_bytes)
        except UpstreamError as exc:
            status = exc.status
            audit_one(status, f"上游错误 {exc.status}",
                      upstream_ms=(time.perf_counter() - started) * 1000)
            self._send_json(status, json.loads(exc.body.decode("utf-8", "replace")))
            return
        except OSError:
            # 客户端提前断开。**照样要落审计** —— 用户中断生成恰恰是最需要留证的场景，
            # 而这里以前直接 return，整条请求（含判定与出站结论）从日志里消失。
            audit_one(499, "客户端提前断开，响应未发完",
                      upstream_ms=(time.perf_counter() - started) * 1000)
            return
        upstream_ms = (time.perf_counter() - started) * 1000

        audit_one(status, outbound_detail, upstream_ms=upstream_ms)

    def _upstream_path(self) -> str:
        """把请求路径规范化后再拼到上游。

        原来是 `self.path` 原样拼接 —— `POST /v1/../../internal/debug` 会被转发成
        `https://上游/v1/../../internal/debug`，而代理会把自己的上游 Key 一并挂上去。
        这里做 `normpath` + 前导斜杠规范化，再校验它仍是预期的 API 路径形状。
        """
        raw = self.path.split("?")[0]
        normalized = posixpath.normpath(raw if raw.startswith("/") else "/" + raw)
        if not normalized.startswith("/"):
            normalized = "/" + normalized
        return normalized.rstrip("/") or "/"

    def _upstream_url(self, path: str) -> str:
        """拼上游地址，折叠重复的 `/v1`。

        上游地址常以 `/v1` 结尾（OpenAI 兼容网关都是），而客户端请求路径通常
        也带 `/v1` —— 原样拼接会得到 `/v1/v1/chat/completions`。
        这个重复前缀此前只影响**透传**路径（扫描路径写死用相对路径掩盖了它），
        直到新增 `/v1/messages` 扫描才暴露出来。

        注意与 `_upstream_path()` 分开：路由判定要用**客户端看到的路径**
        （否则 `/v1/messages` 会被折叠成 `/messages` 而匹配不上扫描列表），
        只有拼 URL 时才折叠。
        """
        base = self.config.upstream.rstrip("/")
        if base.endswith("/v1"):
            # 只削**路径**里的前缀，base 的 /v1 保留：
            # 两边同时削会让 /v1 整个消失（上游收到 `/embeddings`），
            # 两边都不削则得到 `/v1/v1/embeddings`。两者都实测过。
            while path.startswith("/v1/"):
                path = path[3:]
        return base + path

    def _passthrough(self, method: str, body: bytes) -> None:
        """非检测路径（如 /v1/models 的 GET）原样转发。路径先规范化。"""
        self._relay_passthrough(method, body)

    def _fetch_passthrough(self, method: str, body: bytes) -> tuple[int, dict, bytes]:
        """只取回上游响应，**不写给客户端**。返回 (状态码, 头, 体)。

        与 `_relay_passthrough` 的差别就是「不写」—— 调用方需要在回给客户端
        **之前**先检查响应内容（转写文本注入）并落审计。
        状态码 0 = 上游不可达（调用方自己回 502）。
        """
        url = self._upstream_url(self._upstream_path())
        headers = self._build_headers()
        request = urllib.request.Request(url, data=body or None, headers=headers,
                                         method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_s) as response:
                data = response.read(self.config.max_response_bytes + 1)
                if len(data) > self.config.max_response_bytes:
                    return 413, {}, b""      # 上游体过大：调用方按 502 拒收
                return response.status, dict(response.headers), data
        except urllib.error.HTTPError as exc:
            return exc.code, {}, b""
        except (urllib.error.URLError, TimeoutError):
            return 0, {}, b""
        except http.client.HTTPException:
            return 0, {}, b""

    def _relay_passthrough(self, method: str, body: bytes) -> tuple[int, bytes]:
        """转发并返回 (状态码, 响应体)，供调用方决定要不要落审计。"""
        status, response_headers, data = self._fetch_passthrough(method, body)
        if status == 0:
            self._send_json(502, {"error": "上游不可达"})
            return 502, b""
        if status == 413:
            self._send_json(502, {"error": "上游响应体过大，已拒收"})
            return 502, b""
        if status >= 400:
            self._send_json(status, {"error": f"上游返回 {status}"})
            return status, b""
        self._relay_response(status, response_headers)
        self.wfile.write(data)
        return status, data

    # ---------- 直通路径的输入侧扫描 ----------
    def _passthrough_post(self, path: str, body: bytes) -> None:
        """直通路径的 POST：**先扫文本再转发**，并落审计。

        为什么这些端点也要扫（`proxy/passthrough.py` 的 docstring 写了完整
        威胁模型）：`/v1/embeddings` 的输入文本几乎一定会被某次检索捞出来、
        拼进**另一个** prompt —— 那是 RAG 间接注入链的**入口**。只在
        `/v1/chat/completions` 上检测等于在链条开头就放行。

        ⚠ 与聊天路径的差别：这里**没有 role 语义**（没有 system/user 之分），
        所以每段都是普通 author 段（走完整流水线）。
        """
        from prompt_ids.proxy.passthrough import (
            PASSTHROUGH_NO_TEXT,
            extract_passthrough_segments,
        )

        payload: dict[str, Any] = {}
        if body:
            try:
                parsed = json.loads(body.decode("utf-8", "replace"))
                payload = parsed if isinstance(parsed, dict) else {}
            except (ValueError, TypeError):
                payload = {}
        if not payload:
            # 不是 JSON 对象（如 multipart 音频）：**输入**没有可扫的文本，直通并留痕。
            # ⚠ 说明要取**该路径专属**的那条（音频转写写明「输入是音频字节」），
            # 而不是笼统的「非 JSON 请求体」—— 后者读起来像是代理坏了。
            note = PASSTHROUGH_NO_TEXT.get(path) or "非 JSON 请求体，无文本可扫"
            # ⚠⚠ **但不能就此返回**：音频转写的请求体**就是** multipart，
            #   提前返回会让**响应侧**检查永远没机会跑 ——
            #   而音频里的注入恰恰只能从响应侧抓到。
            #   （第一版就是这里 return 了，被 `test_transcript_scan.py` 抓到。）
            self._relay_and_audit_no_input_text(path, body, note, input_kind="not_json")
            return

        segments, _fields, note, input_kind = extract_passthrough_segments(path, payload)
        if not segments:
            # ⚠ `input_kind` 必须一起落审计：「全是 token id 所以扫不了」与
            # 「扫了没命中」在 note 之外必须**结构化可查** —— 否则统计上两者
            # 长得一样，运维看到「没有命中」会以为那段内容干净。
            self._relay_and_audit_no_input_text(path, body, note or "无文本可扫",
                                                input_kind=input_kind)
            return

        pipeline = self.config.pipeline_instance
        started = time.perf_counter()
        scan = scan_segments(pipeline, segments,
                             budget_chars=self.config.max_total_scan_chars)
        detect_ms = (time.perf_counter() - started) * 1000
        decision, status, why = decide(scan.result, self.config, scan.trigger)

        if decision == "block":
            self._audit_passthrough(
                path, scan, note, status=status, scanned=True, detect_ms=detect_ms,
                decision=decision, reason=why, segments=len(segments),
                input_kind=input_kind,
                text="\n".join(seg.text for seg in segments))
            self._send_json(403, {
                "error": {
                    "message": f"{why}（{note}）",
                    "type": "prompt_injection_blocked",
                    "code": "injection_detected",
                },
                "prompt_ids": {
                    "score": scan.result.score,
                    "level": scan.result.level.value,
                    "action": scan.result.action.value,
                    "findings": [f.pattern_id for f in scan.result.findings][:10],
                    "explained": scan.result.explained,
                    "scanned_path": path,
                },
            })
            return

        status_code, data = self._relay_passthrough("POST", body)
        # 转写/翻译端点：**输入**是音频字节（没有文本可扫），但**输出**是
        # 模型生成的文本，而那段文本会被应用方当成可信用户输入、或被后续检索拼进
        # 另一个 prompt —— 那正是 RAG 间接注入链，只是起点是音频。
        # ⚠ 音频注入（Whisper 类模型对抗样本）是**已知的弱面**，不是理论风险。
        transcript_scan = self._scan_transcript_response(path, data, body)
        self._audit_passthrough(
            path, scan, note, status=status_code or status, scanned=True,
            detect_ms=detect_ms, decision=decision, reason=why,
            segments=len(segments),
            input_kind=input_kind,
            **({"transcript_scan": transcript_scan} if transcript_scan else {}),
            # 指纹必须覆盖**实际扫过的文本**，否则同一条攻击从 chat 走和从
            # embeddings 走会算出两个指纹，`by_fp` 聚合把它们当成两次事件。
            # 此前这里漏了（ruff F841 顺带查出来的：text 算了却没用）。
            text="\n".join(seg.text for seg in segments))

    def _relay_and_audit_no_input_text(self, path: str, body: bytes, note: str,
                                       *, input_kind: str) -> None:
        """**输入**侧无文本可扫时的通路。**按是否流式分两条路。**

        - `stream: true` ⇒ 逐帧转发 + 收尾时检查累积的转写文本
          （`_stream_passthrough`）。⚠ 不能走缓冲路径：缓冲整段等于把
          **流式语义破坏掉** —— 调用方还在等增量结果，却一次拿到全部。
        - 非流式 ⇒ 取回 → 检查 → 落审计 → 再回给客户端。

        两个顺序问题，都是被 `tests/test_transcript_scan.py` 抓出来的：

        1. **不能「审计完就 return」**：音频转写/翻译的请求体**就是 multipart**
           （不是 JSON），所以它们**总是**走这条路。若在这里提前返回，
           响应侧检查永远不会跑 —— 而音频里的注入恰恰只能从响应侧抓到
           （输入侧是字节，没有文本可扫）。第一版就是这么写的。
        2. **审计必须早于响应落盘**（非流式路径）：先回响应再落审计的话，
           客户端可能先看到 200，而审计记录还没写进文件 —— 于是
           「请求已处理」与「已留痕」之间有一个窗口，而审计日志的价值
           恰恰在于事后追责。
        """
        # ⚠ 流式必须先分派：**缓冲整段等于把流式语义破坏掉** ——
        #   调用方还在等增量结果，却一次拿到全部。
        if _wants_stream(path, body):
            self._stream_passthrough(path, body, note, input_kind=input_kind)
            return
        status_code, headers, data = self._fetch_passthrough("POST", body)
        if status_code == 0:
            self._audit_passthrough(path, None, note, status=0, scanned=False,
                                    input_kind=input_kind)
            self._send_json(502, {"error": "上游不可达"})
            return
        if status_code == 413:
            self._audit_passthrough(path, None, note, status=502, scanned=False,
                                    input_kind=input_kind)
            self._send_json(502, {"error": "上游响应体过大，已拒收"})
            return
        transcript_scan = self._scan_transcript_response(path, data, body)
        self._audit_passthrough(
            path, None, note, status=status_code, scanned=False,
            input_kind=input_kind,
            **({"transcript_scan": transcript_scan} if transcript_scan else {}))
        self._relay_response(status_code, headers)
        self.wfile.write(data)


    def _stream_passthrough(self, path: str, body: bytes, note: str, *,
                            input_kind: str) -> None:
        """直通路径的**流式**响应：逐帧转发 + 收尾时检查转写文本。

        与聊天路径的 `_stream_body` 同一套纪律（**不写第二套**）：

        1. **按完整帧转发，且最后一帧扣住** —— 告警帧必须排在
           `data: [DONE]` **之前**：官方 SDK 与任何合规 SSE 解析器读到
           `[DONE]` 就停止消费，追加在后面的帧会被丢弃
           （= 最常见的用法收不到告警）。而 `[DONE]` 在读到流尾之前
           无法与别的帧区分，所以每帧都先扣住，收到下一帧再发上一帧。
        2. **累积缓冲有上限**（`max_response_scan_chars`）——
           `timeout_s` 是每次 socket 操作的超时，一个稳定吐数据的长音频流
           永远不会超时 ⇒ 无界累积就是内存无界增长。超限后停止累积
           （仍照常转发，只是不再扫尾部）并如实记账。
        3. **跨帧拼接**（`StreamTranscriptScanner`）—— 逐帧扫必然漏掉
           「拆成两个 delta 发出来」的载荷。

        ⚠ **流式只能告警、不能拦**：内容已经发出去了。与 Canary/密钥的
        出站扫描是同一个取舍，所以审计 detail 里必须写明「已发出，无法撤回」
        —— 别把它读成已拦住。
        """
        from prompt_ids.proxy.passthrough_out import (
            StreamTranscriptScanner,
            extract_transcript_segments,
        )

        url = self._upstream_url(path)
        headers = self._build_headers()
        scanner = StreamTranscriptScanner(
            budget_chars=self.config.max_response_scan_chars)
        started = time.perf_counter()
        try:
            status, resp_headers, chunks, _ms, close_upstream = post_stream(
                url, body, headers, self.config.timeout_s)
        except UpstreamError as exc:
            self._audit_passthrough(path, None, note, status=exc.status,
                                    scanned=False, input_kind=input_kind)
            self._send_json(exc.status, exc.payload)
            return
        self._relay_response(status, resp_headers)

        pending = bytearray()
        held: bytes = b""
        notices = b""
        record: dict[str, Any] = dict(scanner.account())
        try:
            for chunk in chunks:
                if not chunk:
                    continue
                pending.extend(chunk)
                while True:
                    cut = pending.find(b"\n\n")
                    if cut < 0:
                        break
                    frame = bytes(pending[: cut + 2])
                    del pending[: cut + 2]
                    scanner.feed_frame(frame)
                    if held:
                        self.wfile.write(held)
                        self.wfile.flush()
                    held = frame
            if pending:
                scanner.feed_frame(bytes(pending))

            transcript = scanner.text
            record = dict(scanner.account())
            if transcript.strip():
                segments, seg_note = extract_transcript_segments({"text": transcript})
                if segments:
                    scan = scan_segments(self.config.pipeline_instance, segments,
                                         budget_chars=self.config.max_total_scan_chars)
                    record.update({
                        "segments": len(segments),
                        "chars": scan.scanned_chars,
                        "level": scan.result.level.value,
                        "action": scan.result.action.value,
                        "score": round(scan.result.score, 2),
                        "patterns": [f.pattern_id for f in scan.result.findings][:10],
                        "flagged": scan.result.action.value != "pass",
                        "note": seg_note,
                    })
                    if record["flagged"]:
                        # 告警帧必须排在 [DONE] 之前（见 docstring 第 1 条）
                        notices = _transcript_warning_event(record)
            elif record["checked_chars"] == 0:
                record["note"] = "流式转写里没有可扫的文本增量"
        except (BrokenPipeError, ConnectionResetError):
            record = dict(scanner.account())
            record["note"] = "客户端中途断开（已发出的内容无法撤回）"
        finally:
            try:
                if notices:
                    self.wfile.write(notices)
                    self.wfile.flush()
                if held:
                    self.wfile.write(held)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            close_upstream()

        detail = ""
        if record.get("flagged"):
            detail = (f"流式转写检出注入 {record['level']}"
                      f"（内容已发出，无法撤回，只能事后告警；"
                      f"已扫 {record.get('checked_chars', 0)} 字符"
                      + ("，**超出预算的尾部未被扫描**）" if record.get("capped") else "）"))
        # ⚠ `outbound=warned` 而不是别的：内容**已经发出去了**，说成「已处置」
        # 是自欺（与 Canary/密钥的流式处置同一口径）。
        self._audit_passthrough(
            path, None, note, status=status, scanned=False, input_kind=input_kind,
            detect_ms=(time.perf_counter() - started) * 1000,
            decision="allow", reason=detail, transcript_scan=record,
            **({"outbound": OUTBOUND_WARNED} if record.get("flagged") else {}))

    def _scan_transcript_response(self, path: str, body: bytes,
                                  _request_body: bytes) -> dict[str, Any]:
        """转写/翻译响应里的文本要不要再过一次检测。返回审计用的 dict。

        **不修改响应**：内容已经发出去了（`redact()` 那种就地脱敏在这里不可能），
        悄悄改写模型输出会让调用方拿到一句「用户没说过的���」而毫无察觉。
        所以这里只判定、只记账 —— 拦不拦由 `extra` 告诉调用方。

        ⚠ `stream: true` 的流式转写**不在这里**：它的 delta 逐帧到达，
        要在 SSE 通路里处理。本函数在流式情况下明确记 `streamed: not_checked`
        而不是假装检查过 —— 「没扫」必须与「扫了没命中」分得开。
        """
        from prompt_ids.proxy.passthrough_out import (
            extract_transcript_segments,
            is_transcript_path,
        )

        if not is_transcript_path(path):
            return {}
        record: dict[str, Any] = {"enabled": True}
        try:
            payload = json.loads((body or b"").decode("utf-8", "replace"))
        except (ValueError, UnicodeDecodeError):
            record["error"] = "响应体不是合法 JSON"
            return record
        if not isinstance(payload, dict):
            record["error"] = "响应体不是 JSON 对象"
            return record
        segments, note = extract_transcript_segments(payload)
        if not segments:
            record.update({"segments": 0, "note": note})
            return record
        pipeline = self.config.pipeline_instance
        started = time.perf_counter()
        scan = scan_segments(pipeline, segments,
                             budget_chars=self.config.max_total_scan_chars)
        record.update({
            "segments": len(segments),
            "chars": scan.scanned_chars,
            "truncated": scan.truncated,
            "dropped": scan.dropped,
            "level": scan.result.level.value,
            "action": scan.result.action.value,
            "score": round(scan.result.score, 2),
            "patterns": [f.pattern_id for f in scan.result.findings][:10],
            "detect_ms": round((time.perf_counter() - started) * 1000, 2),
            "note": note,
        })
        # 触发规则与阈值都记下来，调用方可据此决定要不要拒收这次转写
        record["flagged"] = record["action"] != "pass"
        return record

    def _audit_passthrough(self, path: str, scan, note: str, *, status: int,
                           scanned: bool, detect_ms: float = 0.0,
                           decision: str = "allow", reason: str = "",
                           segments: int = 0, text: str = "",
                           input_kind: str = "",
                           transcript_scan: dict[str, Any] | None = None,
                           outbound: str = OUTBOUND_NONE) -> None:
        """直通路径也落审计。

        此前直通请求**一条事件都不写** —— 于是「请求总数」只统计被检测的调用，
        而 `/v1/embeddings` 里流过多少文本在日志里完全不存在。写一条
        `passthrough` 事件（`scanned=false` 时 note 说清为什么没扫）之后，
        「没扫」与「扫了没命中」才分得开。
        """
        extra = {"scanned": bool(scanned), "passthrough": True}
        if outbound and outbound != OUTBOUND_NONE:
            # 流式检出注入属于**出站**处置（内容已发出），与请求处置正交 ——
            # 不记的话，报表里这条事件看起来像「什么都没发生就放行了」。
            extra["outbound"] = outbound
        # ⚠ **扫过**也要记形态：`mixed` 意味着只有文本部分被检测，
        # 说成「已扫描」是误导（token id 部分根本没看）。
        # 空字符串 = 聊天路径那种分段检测，没有「单一 input」可言。
        if input_kind:
            extra["input_kind"] = input_kind
        # 转写/译文的**响应侧**判定。⚠ 它与 `decision`（请求处置）是两件事：
        # 请求放行了、但响应里的转写文本被判有注入 —— 只看 decision 会漏掉。
        # 这与「decision / outbound 两个正交维度」是同一个教训的第三次应用。
        if transcript_scan:
            extra["transcript_scan"] = dict(transcript_scan)
        # ⚠ **出站处置与请求处置正交**（同一个教训的第三次应用）：
        #   请求放行了、但响应里的转写被判注入 —— 只看 `decision` 会漏掉，
        #   报表里那条事件看起来像「什么都没发生就放行了」。
        #   ⚠ 流式只能是 `warned`：内容**已经发出去了**，算成「已处置」是自欺。
        if outbound and outbound != OUTBOUND_NONE:
            extra["outbound"] = outbound
        if scan is not None:
            extra.update({
                "segments": segments,
                "trigger": scan.trigger.tag if scan.trigger else "",
                "truncated": scan.truncated,
                "dropped": scan.dropped,
                "scanned_chars": scan.scanned_chars,
            })
        self.config.audit.log(AuditEvent(
            ts=time.time(), kind=KIND_PROXY, source="proxy",
            level=(scan.result.level.value if scan is not None else "info"),
            action=(scan.result.action.value if scan is not None else "pass"),
            detect_ms=round(detect_ms, 2), note=(reason or note)[:200],
            # 指纹覆盖**实际扫过**的文本（与 chat 路径同源）。`text` 只用来算
            # 指纹，绝不写入日志 —— 审计层「只落指纹」这条边界对直通路径同样成立。
            fp=fingerprint(text) if text else "",
            extra={"decision": decision, "path": path, "status": status,
                   "client": self.client_address[0], **extra},
        ))


def _collect_output(obj: Any, parts: list[tuple[str, str]]) -> None:
    """把一个 OpenAI 响应 JSON 里的**全部模型输出字段**收进 parts。

    元素是 (kind, value)：kind 为 ``delta`` 表示这是同一段文本的续片，
    拼接时**不能加任何分隔符**（加了就把跨帧的凭据拆断了）；
    ``line`` 表示另一段独立文本，用换行隔开即可。
    """
    for choice in (obj.get("choices") or []) if isinstance(obj, dict) else []:
        if not isinstance(choice, dict):
            continue
        message = choice.get("message") or {}
        if isinstance(message, dict):
            if isinstance(message.get("content"), str):
                parts.append(("line", message["content"]))
            # tool_calls 的参数是凭据最常漏出去的地方：agent 写文件时代码里就带着 key
            for call in message.get("tool_calls") or []:
                if not isinstance(call, dict):
                    continue
                function = call.get("function") or {}
                if isinstance(function, dict):
                    for key in ("arguments", "name"):
                        if isinstance(function.get(key), str):
                            parts.append(("line", function[key]))
        if isinstance(choice.get("text"), str):
            parts.append(("line", choice["text"]))
        if isinstance(choice.get("delta"), dict):
            delta = choice["delta"]
            parts.append(("delta", str(delta.get("content", ""))))
            for call in delta.get("tool_calls") or []:
                if not isinstance(call, dict):
                    continue
                function = call.get("function") or {}
                if isinstance(function, dict) and isinstance(function.get("arguments"), str):
                    parts.append(("delta", function["arguments"]))


def _join_parts(parts: list[tuple[str, str]]) -> str:
    out: list[str] = []
    previous: str | None = None
    for kind, value in parts:
        if kind == "line" and previous is not None:
            out.append("\n")
        out.append(value)
        previous = kind
    return "".join(out)


def _response_text(payload: bytes | str) -> str:
    """从响应体里取出模型输出文本，用于出站检测（Canary 与密钥扫描共用）。

    接受 bytes 或 str：非流式路径上调用方已经把 body decode 过一次给密钥扫描用，
    不该为了这里再解一遍（2MB 响应体每次全量 decode 都是一份完整拷贝）。

    要同时认两种形态：
    - 非流式 JSON：choices[].message.content / .text / .tool_calls[].function.arguments
    - 流式 SSE：一行一个 `data: {...}`

    **流式必须逐帧取出内容再拼接**，不能直接扫原始缓冲：帧与帧之间隔着
    `}}]}` 与换行，线上根本不存在连续的密钥串 —— 「把密钥拆成两个 delta 发出来」
    会让逐帧扫描与原始扫描双双漏掉，只有拼起来才认得出。
    （这条对 Canary 同样成立：令牌被拆帧也应当算泄露。）
    """
    text = payload if isinstance(payload, str) else payload.decode("utf-8", "replace")
    parts: list[tuple[str, str]] = []
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        saw_frame = False
        for line in text.splitlines():
            if not line.startswith("data:"):
                continue
            chunk = line[len("data:"):].strip()
            if not chunk or chunk == "[DONE]":
                continue
            try:
                frame = json.loads(chunk)
            except json.JSONDecodeError:
                continue
            saw_frame = True
            _collect_output(frame, parts)
        return _join_parts(parts) if saw_frame else ""
    _collect_output(obj, parts)
    return _join_parts(parts)


def _leak_warning(leak) -> dict[str, Any]:
    return {
        "error": {
            "message": "响应包含机密标识符，已被防护系统替换",
            "type": "canary_leak",
            "code": "system_prompt_leaked",
        },
        # public=True：对外只回显脱敏令牌，否则等于把令牌亲手交给攻击者
        "prompt_ids": {"leak": leak.as_dict(public=True)},
    }


def _secret_event(hits) -> bytes:
    """流式响应末尾补的告警帧。**只给类别与脱敏形态**，不给原文。

    沿用 Canary 那一帧的写法（`data: ` 前缀 + 空行结尾），否则严格的 SSE
    解析器会把这一行当垃圾丢掉，告警等于没发。
    """
    return b"data: " + json.dumps({
        "prompt_ids_warning": "secret_scan",
        "note": "响应中含有凭据，已记审计；内容已发出，无法撤回",
        "secrets": [h.as_dict() for h in hits],
    }, ensure_ascii=False).encode("utf-8") + b"\n\n"


def _leak_event(leak) -> bytes:
    return b"data: " + json.dumps(
        {"prompt_ids_warning": "canary_leak", "leak": leak.as_dict(public=True)}, ensure_ascii=False
    ).encode("utf-8") + b"\n\n"


def _wants_stream(path: str, body: bytes) -> bool:
    """这个直通请求要的是不是 SSE 流。

    ⚠ **multipart 请求体不是 JSON**（音频转写就是 multipart），所以不能只
    解析 JSON body —— 那样 `stream: true` 这个字段**永远读不到**，
    流式请求会被当成非流式缓冲转发，客户端等增量结果却一次拿到全部。
    所以要从 multipart 里粗扫一层 `stream` 标记。
    """
    try:
        payload = json.loads(body.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        payload = None
    if isinstance(payload, dict):
        return bool(payload.get("stream"))
    if b"stream" in body[:8192]:
        # multipart: name="stream" 后面跟 true
        lowered = body[:8192].lower()
        return (b'name="stream"' in lowered or b"name=stream" in lowered) and \
            (b"true" in lowered)
    return False


def _transcript_warning_event(record: dict) -> bytes:
    """流式转写检出注入时补的告警帧。**只给判定与命中规则，不给转写原文。**

    沿用 `_leak_event` / `_secret_event` 的帧形态（`data: ` 前缀 + 空行结尾），
    且**必须排在 `data: [DONE]` 之前** —— 官方 SDK 与合规 SSE 解析器读到
    `[DONE]` 就停止消费，追加在后面的帧会被丢弃。

    ⚠ 「内容已发出，无法撤回」这句话必须出现在 frame 里：调用方看到告警后
    很容易以为「被拦下了」，而实际上转写音频/文本已经出去了。
    """
    return b"data: " + json.dumps({
        "prompt_ids_warning": "transcript_injection",
        "note": "转写内容中检出提示词注入；内容已发出，无法撤回",
        "level": record.get("level", ""),
        "action": record.get("action", ""),
        "score": record.get("score", 0),
        "patterns": record.get("patterns", []),
        "checked_chars": record.get("checked_chars", 0),
        "capped": record.get("capped", False),
    }, ensure_ascii=False).encode("utf-8") + b"\n\n"


def create_server(config: ProxyConfig) -> ThreadingHTTPServer:
    # `client_key` 配了 ⇒ 有客户端鉴权（`X-API-Key`）。⚠ 与 `api_key` 无关：
    # 那个是给上游的凭据，客户端的 Authorization 头会被**透传**给它。
    # 按 IP 的限流与 canary 签发配额**都不是鉴权**。
    warn_if_exposed(config.host, service="透明代理",
                    authenticated=bool(config.client_key))
    handler = type("BoundProxyHandler", (ProxyHandler,), {"config": config})
    return ThreadingHTTPServer((config.host, config.port), handler)


def serve(config: ProxyConfig) -> None:  # pragma: no cover - 阻塞调用
    server = create_server(config)
    print(f"透明代理已启动 http://{config.host}:{config.port} -> {config.upstream}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
