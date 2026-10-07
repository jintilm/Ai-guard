"""多提供商注册表 —— 借鉴 LiteLLM 的 `provider/model` 约定。

设计取舍（答辩会被问，所以写在这里）：

1. **数据驱动，不写 if/else 分支。** 所有提供商都是表里的一行。加一家新厂商 = 加一行；
   只有当「线路协议」真的不同（目前只有 openai / anthropic 两种）时才需要加适配器。
   反面教材是 `if provider == "deepseek": ... elif provider == "openai": ...` 这种写法，
   加到第 20 家时会变成一坨无法审计的分支泥潭。

2. **协议与厂商解耦。** 厂商之间的差异有 90% 是纯数据：
   端点 URL、鉴权头名字、是否支持 JSON 模式、路径里要不要塞 deployment、要不要 api-version。
   这些全部做成字段，于是「支持 Azure」不是一次特殊分支，而是三行数据
   （`path` 带 `{deployment}` 占位符 + `auth_header="api-key"` + `api_version`）。

3. **模型名会漂移，所以提供运行时发现。** 2026-09 核实时发现各家几乎都换代了：
   DeepSeek 走到 `deepseek-v4-*`（`deepseek-chat` 已成映射别名）、OpenAI 到 `gpt-5.x`、
   Kimi 到 K2.x、GLM 到 5.x。**任何写死在代码里的默认模型名都有保质期。**
   因此：默认值只当「起步用的合理猜测」，配套 `list_models()` 打 `GET {base}/models`
   查该端点的真实清单，模型名错误时报错信息里也会提示去看清单。
   本项目已有「报告文件会悄悄过期」的教训，这里是同一条纪律的延伸。

4. **本地推理是一等公民。** `ollama` / `vllm` / `lmstudio` 的 `needs_key=False`：
   离线可用不能因为「没配 Key」被误判成不可用 —— 那会让 `auto` 选型跳过本地模型，
   静默降级到 NullBackend。

5. **端点永远可被覆盖。** 任何厂商都能被 `PROMPT_IDS_LLM_BASE_URL` 或 `--base-url` 盖掉，
   指向自建网关（vLLM / one-api / LiteLLM proxy / 企业网关）时不必新增提供商条目。
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, NamedTuple

#: 通用覆盖项，优先于任何厂商专属变量
GENERIC_KEY_ENVS = ("PROMPT_IDS_LLM_API_KEY",)
GENERIC_BASE_URL_ENV = "PROMPT_IDS_LLM_BASE_URL"
GENERIC_MODEL_ENV = "PROMPT_IDS_LLM_MODEL"
GENERIC_PROVIDER_ENV = "PROMPT_IDS_LLM_PROVIDER"
GENERIC_FALLBACK_ENV = "PROMPT_IDS_LLM_FALLBACKS"
GENERIC_API_VERSION_ENVS = ("PROMPT_IDS_LLM_API_VERSION",)
GENERIC_DEPLOYMENT_ENVS = ("PROMPT_IDS_LLM_DEPLOYMENT",)
GENERIC_USER_AGENT_ENV = "PROMPT_IDS_LLM_USER_AGENT"
GENERIC_MAX_TOKENS_ENV = "PROMPT_IDS_LLM_MAX_TOKENS"
GENERIC_EXTRA_BODY_ENV = "PROMPT_IDS_LLM_EXTRA_BODY"

#: 裁判回复的默认 token 上限。
#: **别调回 120**：推理模型（glm-4.5、deepseek-v4 等）会先把 token 花在
#: `reasoning_content` 上，120 会在推理阶段就被截断，导致 `content` 为空、
#: 每条样本都退化成"非 JSON → 0.5 中立"，而外面看起来一切正常（最恶劣的静默失效）。
#: 实测 2026-09-30：推理模型 completion 用量 200-500 token，512 起才稳定出 content。
DEFAULT_MAX_TOKENS = 1024

#: Cloudflare 按 UA 拦截时的可执行提示。默认**不改** UA，
#: 只在失败时把原因说清楚，由用户显式决定要不要冒充浏览器。
CLOUDFLARE_UA_HINT = (
    f"（疑似被 Cloudflare 的浏览器完整性校验拦下，属 UA 拦截而非网络故障；"
    f"可设 {GENERIC_USER_AGENT_ENV} 为一个浏览器 UA 后重试）"
)

#: 线路协议。只有两种真正不同的请求/响应形状，其余厂商都是其中之一的方言。
KINDS = ("openai", "anthropic")


class Provider(NamedTuple):
    """一家厂商的全部接入信息。纯数据，不含行为。"""

    name: str
    label: str
    kind: str = "openai"
    base_url: str = ""
    default_model: str = ""
    key_envs: tuple[str, ...] = ()
    #: 额外的 base_url 环境变量名（厂商约定名，如 AZURE_OPENAI_ENDPOINT）
    base_url_envs: tuple[str, ...] = ()
    needs_key: bool = True
    #: 该端点是否支持 OpenAI 的 response_format={"type":"json_object"}
    json_mode: bool = True
    #: 候选模型名，仅供 CLI 提示 / 文档；真实清单请用 list_models()
    models: tuple[str, ...] = ()
    #: 相对 base_url 的路径，可含 {deployment} 占位符（Azure 用）
    path: str = "/chat/completions"
    #: 非空则拼 `?api-version=xxx`（Azure 用）
    api_version: str = ""
    auth_header: str = "Authorization"
    auth_prefix: str = "Bearer "
    docs: str = ""
    notes: str = ""

    @property
    def is_local(self) -> bool:
        return not self.needs_key


def _p(*args, **kwargs) -> Provider:
    return Provider(*args, **kwargs)


#: 全部提供商。顺序影响 `auto` 之外的一切展示顺序，不影响 auto 选型（见 AUTO_PRIORITY）。
PROVIDERS: dict[str, Provider] = {
    # ---------------------------------------------------------------- 国内
    "deepseek": _p(
        "deepseek", "DeepSeek 深度求索",
        base_url="https://api.deepseek.com/v1",
        default_model="deepseek-v4-flash",
        key_envs=("DEEPSEEK_API_KEY",),
        models=("deepseek-v4-flash", "deepseek-v4-pro", "deepseek-chat"),
        docs="https://api-docs.deepseek.com/zh-cn",
        notes="deepseek-chat / deepseek-reasoner 已是被映射的旧别名，建议用 v4 直名",
    ),
    "qwen": _p(
        "qwen", "阿里云百炼 通义千问",
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        default_model="qwen3-plus",
        key_envs=("DASHSCOPE_API_KEY", "QWEN_API_KEY"),
        base_url_envs=("DASHSCOPE_BASE_URL",),
        models=("qwen3-plus", "qwen3-max", "qwen3.6-plus", "qwen-plus"),
        docs="https://bailian.console.aliyun.com",
        notes="Key 与地域绑定，跨地域会 401；自带 /compatible-mode/v1 已含版本号",
    ),
    "zhipu": _p(
        "zhipu", "智谱 GLM",
        base_url="https://open.bigmodel.cn/api/paas/v4",
        default_model="glm-4-flash",
        key_envs=("ZHIPUAI_API_KEY", "ZHIPU_API_KEY", "GLM_API_KEY"),
        models=("glm-4-flash", "glm-5.1", "glm-5.2"),
        docs="https://open.bigmodel.cn",
        notes="端点已带 /api/paas/v4，不要再拼 /v1；glm-4-flash 有长期免费额度",
    ),
    "moonshot": _p(
        "moonshot", "月之暗面 Kimi",
        base_url="https://api.moonshot.cn/v1",
        default_model="kimi-k2-0905-preview",
        key_envs=("MOONSHOT_API_KEY", "KIMI_API_KEY"),
        models=("kimi-k2-0905-preview", "kimi-k2.6", "moonshot-v1-8k"),
        docs="https://platform.moonshot.cn",
        notes="国际站为 api.moonshot.ai/v1，用 BASE_URL 覆盖即可",
    ),
    "siliconflow": _p(
        "siliconflow", "硅基流动 SiliconFlow",
        base_url="https://api.siliconflow.cn/v1",
        default_model="Qwen/Qwen3-8B",
        key_envs=("SILICONFLOW_API_KEY",),
        models=("Qwen/Qwen3-8B", "deepseek-ai/DeepSeek-V3", "moonshotai/Kimi-K2-Instruct"),
        docs="https://cloud.siliconflow.cn",
    ),
    "volces": _p(
        "volces", "火山方舟 豆包",
        base_url="https://ark.cn-beijing.volces.com/api/v3",
        default_model="doubao-seed-2-0-pro",
        key_envs=("ARK_API_KEY", "VOLCES_API_KEY"),
        models=("doubao-seed-2-0-pro", "deepseek-v4-pro"),
        docs="https://console.volcengine.com/ark",
        notes="端点已带 /api/v3；也可填推理接入点 ID（ep-xxxx）当模型名",
    ),
    "qianfan": _p(
        "qianfan", "百度千帆 ERNIE",
        base_url="https://qianfan.baidubce.com/v2",
        default_model="ernie-5.0",
        key_envs=("QIANFAN_API_KEY", "BAIDU_API_KEY"),
        models=("ernie-5.0", "deepseek-v4-pro", "qwen3.6-plus"),
        docs="https://console.bce.baidu.com/qianfan",
        notes="端点已带 /v2",
    ),
    "minimax": _p(
        "minimax", "MiniMax",
        base_url="https://api.minimaxi.com/v1",
        default_model="MiniMax-M2.7",
        key_envs=("MINIMAX_API_KEY",),
        models=("MiniMax-M2.7", "MiniMax-M2.7-highspeed"),
        docs="https://platform.minimaxi.com",
    ),
    # ---------------------------------------------------------------- 国际
    "openai": _p(
        "openai", "OpenAI",
        base_url="https://api.openai.com/v1",
        default_model="gpt-5.4",
        key_envs=("OPENAI_API_KEY",),
        models=("gpt-5.4", "gpt-5.5", "gpt-5.2-chat", "gpt-4o-mini"),
        docs="https://platform.openai.com/docs",
        notes="本表默认值会随官方换代漂移，务必用 --list-models 核对",
    ),
    "azure": _p(
        "azure", "Azure OpenAI",
        base_url="",  # 必须由 AZURE_OPENAI_ENDPOINT 提供
        default_model="gpt-4o-mini",  # 兜底：没有 deployment 时拿它当 deployment 名
        key_envs=("AZURE_OPENAI_API_KEY", "AZURE_API_KEY"),
        base_url_envs=("AZURE_OPENAI_ENDPOINT", "AZURE_API_BASE"),
        models=("gpt-4o-mini", "gpt-4o"),
        path="/openai/deployments/{deployment}/chat/completions",
        api_version="2024-06-01",
        auth_header="api-key",
        auth_prefix="",
        docs="https://learn.microsoft.com/azure/ai-services/openai/",
        notes="鉴权用 api-key 头而非 Bearer；URL 里塞 deployment + api-version，"
              "模型名位置填「部署名」；资源级端点无 /v1 后缀",
    ),
    "anthropic": _p(
        "anthropic", "Anthropic Claude",
        kind="anthropic",
        base_url="https://api.anthropic.com/v1",
        default_model="claude-sonnet-4-6",
        key_envs=("ANTHROPIC_API_KEY",),
        json_mode=False,  # 用 messages 协议，没有 response_format 这个字段
        models=("claude-sonnet-4-6", "claude-opus-4-7", "claude-sonnet-4-5"),
        path="/messages",
        auth_header="x-api-key",
        auth_prefix="",
        docs="https://docs.anthropic.com",
        notes="协议与 OpenAI 不同：system 是顶层字段、必填 max_tokens、"
              "响应在 content[] 里；由 anthropic 适配器处理",
    ),
    "groq": _p(
        "groq", "Groq",
        base_url="https://api.groq.com/openai/v1",
        default_model="llama-3.3-70b-versatile",
        key_envs=("GROQ_API_KEY",),
        models=("llama-3.3-70b-versatile", "moonshotai/kimi-k2-instruct", "qwen/qwen3-32b"),
        docs="https://console.groq.com/docs",
        notes="推理极快、有免费额度，适合当 fallback 兜底",
    ),
    "mistral": _p(
        "mistral", "Mistral AI",
        base_url="https://api.mistral.ai/v1",
        default_model="mistral-small-latest",
        key_envs=("MISTRAL_API_KEY",),
        models=("mistral-small-latest", "mistral-medium-latest", "open-mistral-nemo"),
        docs="https://docs.mistral.ai",
        notes="-latest 是官方别名，比日期版稳定",
    ),
    "together": _p(
        "together", "Together AI",
        base_url="https://api.together.xyz/v1",
        default_model="meta-llama/Llama-3.3-70B-Instruct-Turbo",
        key_envs=("TOGETHER_API_KEY", "TOGETHERAI_API_KEY"),
        models=("meta-llama/Llama-3.3-70B-Instruct-Turbo", "Qwen/Qwen3-235B-A22B-Instruct"),
        docs="https://docs.together.ai",
    ),
    "openrouter": _p(
        "openrouter", "OpenRouter（聚合网关）",
        base_url="https://openrouter.ai/api/v1",
        default_model="openai/gpt-5.4",
        key_envs=("OPENROUTER_API_KEY",),
        models=("openai/gpt-5.4", "anthropic/claude-sonnet-4-6",
                "deepseek/deepseek-v4-pro", "z-ai/glm-5.1"),
        docs="https://openrouter.ai/docs",
        notes="一家 Key 通吃多家模型，模型名形如 vendor/model —— 会与本项目的 "
              "provider/model 前缀写法撞车，所以用本 provider 时请用 --model 传全名",
    ),
    "xai": _p(
        "xai", "xAI Grok",
        base_url="https://api.x.ai/v1",
        default_model="grok-4.3",
        key_envs=("XAI_API_KEY", "GROK_API_KEY"),
        models=("grok-4.3", "grok-4.20"),
        docs="https://docs.x.ai",
    ),
    "perplexity": _p(
        "perplexity", "Perplexity",
        base_url="https://api.perplexity.ai",
        default_model="sonar",
        key_envs=("PERPLEXITY_API_KEY", "PPLX_API_KEY"),
        json_mode=False,  # 不支持 response_format，靠提示词约束
        models=("sonar", "sonar-pro"),
        docs="https://docs.perplexity.ai",
        notes="端点无 /v1 后缀；不支持 response_format，已置 json_mode=False",
    ),
    # ---------------------------------------------------------------- 本地 / 自建
    "ollama": _p(
        "ollama", "Ollama（本地）",
        base_url="http://localhost:11434/v1",
        default_model="qwen3:8b",
        key_envs=(),
        needs_key=False,
        models=("qwen3:8b", "llama3.2", "deepseek-r1:7b"),
        docs="https://docs.ollama.com/api/openai-compatibility",
        notes="免 Key；模型要先 ollama pull。本机离线可用，是 auto 选型的理想兜底",
    ),
    "vllm": _p(
        "vllm", "vLLM（自建）",
        base_url="http://localhost:8000/v1",
        default_model="Qwen/Qwen3-8B",
        key_envs=("VLLM_API_KEY",),
        needs_key=False,
        models=("Qwen/Qwen3-8B",),
        docs="https://docs.vllm.ai",
        notes="免 Key；模型名必须与启动时 --model 加载的一致，用 --list-models 查",
    ),
    "lmstudio": _p(
        "lmstudio", "LM Studio（本地）",
        base_url="http://localhost:1234/v1",
        default_model="local-model",
        key_envs=(),
        needs_key=False,
        models=("local-model",),
        docs="https://lmstudio.ai/docs/api/openai-api",
        notes="免 Key；模型名以 /models 返回为准",
    ),
    "custom": _p(
        "custom", "自定义 OpenAI 兼容端点",
        base_url="",  # 必须由 PROMPT_IDS_LLM_BASE_URL 提供
        default_model="",
        key_envs=(),
        needs_key=False,  # 内网网关常常不鉴权
        models=(),
        docs="",
        notes="企业网关 / one-api / LiteLLM proxy 指向这里；"
              "填 PROMPT_IDS_LLM_BASE_URL 即可，不需要为每家网关加一条注册表",
    ),
}

#: `auto` 模式的选型顺序：先国内直连（中文场景 + 成本），再国际，最后本地。
#: 本地放最后是有意的 —— 只在前面都没配 Key 时才退到本地推理。
AUTO_PRIORITY: tuple[str, ...] = (
    "deepseek", "qwen", "zhipu", "moonshot", "siliconflow", "volces", "qianfan", "minimax",
    "openai", "anthropic", "azure", "groq", "mistral", "together", "openrouter", "xai",
    "perplexity", "ollama", "vllm", "lmstudio",
)


def provider_names() -> tuple[str, ...]:
    return tuple(PROVIDERS)


def get(name: str) -> Provider | None:
    return PROVIDERS.get((name or "").strip().lower())


def _env(*names: str) -> str:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return ""


# ---------------------------------------------------------------- provider 解析
def local_candidates() -> tuple[str, ...]:
    """不需要 Key、且自带可用默认端点的本地推理提供商。"""
    return tuple(
        name for name in AUTO_PRIORITY
        if PROVIDERS[name].is_local and PROVIDERS[name].base_url
    )


def resolve_provider(requested: str = "auto") -> str:
    """决定用哪一家。

    顺序：显式参数 > PROMPT_IDS_LLM_PROVIDER > 按 AUTO_PRIORITY 找第一个已配 Key 的
    > 空串（表示「没得选」，调用方据此报不可用并给出可执行提示）。

    `auto` **不选** `custom`（没有可推断的端点）也**不选**本地端点（ollama/vllm/lmstudio）——
    这两个都必须显式指定。理由：
      - `custom` 的端点无从推断，猜一个只会 404；
      - 本地端点虽然免 Key，但「本机装了 Ollama」不等于「Ollama 正在跑」。
        让 auto 选中一个没启动的 localhost 服务，等于把「明确不可用」换成
        「看着可用、调用时才失败」，这是降级契约里最不该出现的一种假阳性。
    要本地推理就显式 `--semantic-backend ollama`（或设 PROMPT_IDS_LLM_PROVIDER=ollama）。
    """
    key = (requested or "auto").strip().lower()
    if key in PROVIDERS:
        return key
    if key and key != "auto":
        # 未知名字不静默当成 openai（那会让人以为在用 A、其实在用 B）
        return ""

    from_env = _env(GENERIC_PROVIDER_ENV).lower()
    if from_env in PROVIDERS:
        return from_env

    for name in AUTO_PRIORITY:
        provider = PROVIDERS[name]
        if provider.needs_key and _env(*GENERIC_KEY_ENVS, *provider.key_envs):
            return name
    return ""


# ---------------------------------------------------------------- 凭据与端点
def provider_keys(provider: str) -> tuple[str, ...]:
    entry = get(provider)
    return entry.key_envs if entry else ()


def resolve_api_key(provider: str, explicit: str = "") -> str:
    """显式入参 > 通用覆盖项 > 厂商变量。本地端点返回空串不算失败。"""
    entry = get(provider)
    names = (*GENERIC_KEY_ENVS, *(entry.key_envs if entry else ()))
    return explicit or _env(*names)


def resolve_base_url(provider: str, override: str = "") -> str:
    """显式入参 > PROMPT_IDS_LLM_BASE_URL > 厂商约定名 > {NAME}_BASE_URL > 注册表默认。

    厂商约定名要排在通用名 `{NAME}_BASE_URL` 前面，因为前者才是各家的官方写法
    （例如 Azure 是 AZURE_OPENAI_ENDPOINT，不是 AZURE_BASE_URL）。
    """
    entry = get(provider)
    if not entry:
        return (override or "").rstrip("/")
    names = (GENERIC_BASE_URL_ENV, *entry.base_url_envs, f"{provider.upper()}_BASE_URL")
    base = override or _env(*names) or entry.base_url
    return base.rstrip("/")


def resolve_model(provider: str, override: str = "", fallback: str = "") -> str:
    entry = get(provider)
    return (
        override
        or _env(GENERIC_MODEL_ENV)
        or fallback
        or (entry.default_model if entry else "")
    )


def resolve_user_agent() -> str:
    """可选的自定义 User-Agent，默认空串（即沿用 urllib 默认，不改行为）。

    为什么需要它：不少第三方 OpenAI 兼容网关挂在 Cloudflare 后面，其「浏览器
    完整性校验」会对非浏览器 UA 直接回 `403 error code: 1010`，而 stdlib
    `urllib` 的默认 UA（`Python-urllib/3.x`）正好命中。这不是网络问题、也不是
    鉴权问题，从报错里看不出来，所以这里给一个显式开关而不是偷偷改默认值。
    """
    return _env(GENERIC_USER_AGENT_ENV)


def resolve_max_tokens(default: int = DEFAULT_MAX_TOKENS) -> int:
    """裁判回复的 token 上限。非法值响亮回落到默认，不静默当 0。"""
    raw = _env(GENERIC_MAX_TOKENS_ENV)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def resolve_extra_body() -> dict:
    """额外请求体字段（JSON 对象），用来打开厂商专属开关。

    主要用途：**关掉推理模型的思考链**，例如智谱的
    `PROMPT_IDS_LLM_EXTRA_BODY={"thinking":{"type":"disabled"}}` ——
    裁判只需要一句 JSON，思考链纯属浪费（实测 completion 从 283 → 34 token，
    延迟从 ~5s 降到 ~1s 量级）。

    解析失败返回空 dict（不抛异常）：这是个可选增强项，不该因为它写错就
    让整个后端不可用。想确认它有没有生效，看 `LLMBackend.info()["extra_body"]`。
    """
    raw = _env(GENERIC_EXTRA_BODY_ENV)
    if not raw:
        return {}
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return obj if isinstance(obj, dict) else {}


def resolve_deployment(provider: str, model: str = "") -> str:
    """Azure 的部署名：专用变量 > 模型名（模型名位置本来就该填部署名）。"""
    return _env(*GENERIC_DEPLOYMENT_ENVS, "AZURE_OPENAI_DEPLOYMENT") or model


def resolve_api_version(provider: str) -> str:
    entry = get(provider)
    if not entry or not entry.api_version:
        return ""
    return _env(*GENERIC_API_VERSION_ENVS, "AZURE_OPENAI_API_VERSION") or entry.api_version


def build_url(provider: str, base_url: str = "", model: str = "") -> str:
    """把 base_url + path 拼成完整端点，处理 {deployment} 与 api-version。

    base_url 留空时会走 resolve_base_url（即读环境变量），
    这样「注册表默认端点为空、靠环境变量提供」的 azure / custom 也能拼出正确 URL。
    """
    entry = get(provider)
    if not entry:
        return f"{(base_url or '').rstrip('/')}/chat/completions"
    base = (base_url or resolve_base_url(provider, "")).rstrip("/")
    path = entry.path
    if "{deployment}" in path:
        path = path.format(deployment=resolve_deployment(provider, model))
    url = f"{base}{path}"
    version = resolve_api_version(provider)
    if version:
        url = f"{url}?api-version={version}"
    return url


def auth_headers(provider: str, api_key: str) -> dict[str, str]:
    """按厂商生成鉴权头。没有 Key 就返回空（本地端点合法）。"""
    entry = get(provider)
    if not entry or not api_key:
        return {}
    return {entry.auth_header: f"{entry.auth_prefix}{api_key}"}


def build_request(
    url: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    method: str = "POST",
) -> urllib.request.Request:
    """构造请求，并**保留请求头的大小写**。

    为什么不用 `Request(..., headers=...)`：urllib 内部走的是 `add_header()`，
    而它会 `key.capitalize()` —— `api-key` 被改写成 `Api-key`，
    `x-api-key` 变成 `X-api-key`。HTTP 规范里头名不区分大小写，
    但 Azure 前置网关、企业侧的反向代理未必这么宽容，而且这类失败只会
    表现为「本地全通、上了网关就 401」，极难定位。这里直接赋值绕开改写。

    这里也是**注入自定义 User-Agent 的唯一入口**：两个调用方（LLM 推理与
    模型清单）都走本函数，加在这里就不会漏。未设 `PROMPT_IDS_LLM_USER_AGENT`
    时不写该头，行为与从前逐字节一致。
    """
    merged = dict(headers or {})
    user_agent = resolve_user_agent()
    if user_agent:
        merged.setdefault("User-Agent", user_agent)
    request = urllib.request.Request(url, data=data, method=method)
    if merged:
        request.headers = merged
    return request


# ---------------------------------------------------------------- provider/model 写法
def split_model_spec(spec: str) -> tuple[str, str]:
    """解析 LiteLLM 风格的 `provider/model` 字符串。

    返回 (provider, model)；没有已知前缀时 provider 为 ""、model 为原串。

    为什么必须「先查表再拆分」：HuggingFace 的 repo id 本身带斜杠
    （`protectai/deberta-v3-base-prompt-injection-v2`），无脑按第一个 `/` 切会把它
    误判成 provider。LiteLLM 的做法是拿左半边去比对已知 provider 名单，这里照做。

    有歧义的特例是 OpenRouter：它的模型名本身就是 `vendor/model`，于是
    `openrouter/openai/gpt-5.4` 要拆成 ("openrouter", "openai/gpt-5.4") —— 只切第一个
    分隔符，剩下的整段留给模型名。
    """
    text = (spec or "").strip()
    if "/" not in text:
        return "", text
    head, _, tail = text.partition("/")
    if head.lower() in PROVIDERS:
        return head.lower(), tail
    return "", text


# ---------------------------------------------------------------- 可用性诊断
def diagnose(provider: str, *, model: str = "", base_url: str = "", api_key: str = "") -> dict[str, Any]:
    """返回某家的接入诊断：可用与否 + 缺什么 + 该往哪个文件填。

    这是给 `probe` / `--list-providers` / 错误信息共用的单一事实来源，
    避免「工厂说可用、真调用报 401」这种口径不一致。
    """
    entry = get(provider)
    if entry is None:
        return {"provider": provider, "available": False, "missing": ["provider"],
                "reason": f"未知提供商 {provider!r}，可选：{', '.join(provider_names())}"}

    resolved_key = resolve_api_key(provider, api_key)
    resolved_base = resolve_base_url(provider, base_url)
    resolved_model = resolve_model(provider, model)

    missing: list[str] = []
    if entry.needs_key and not resolved_key:
        missing.append("api_key")
    if not resolved_base:
        missing.append("base_url")
    if not resolved_model:
        missing.append("model")

    if missing:
        reason = _missing_reason(entry, missing)
    else:
        reason = "可用"

    return {
        "provider": provider,
        "label": entry.label,
        "kind": entry.kind,
        "available": not missing,
        "missing": missing,
        "reason": reason,
        "key_env": list(entry.key_envs),
        "has_key": bool(resolved_key),
        "needs_key": entry.needs_key,
        "is_local": entry.is_local,
        "model": resolved_model,
        "models": list(entry.models),
        "base_url": resolved_base,
        "endpoint": build_url(provider, resolved_base, resolved_model),
        "docs": entry.docs,
        "notes": entry.notes,
    }


def _missing_reason(entry: Provider, missing: list[str]) -> str:
    parts: list[str] = []
    if "api_key" in missing:
        if entry.key_envs:
            parts.append(f"未设置 {' / '.join(entry.key_envs)}（可写在项目根目录 .env）")
        else:
            parts.append("缺少 API Key，但该提供商未声明 key 环境变量")
    if "base_url" in missing:
        envs = " / ".join((*entry.base_url_envs, GENERIC_BASE_URL_ENV))
        parts.append(f"未设置端点，请填 {envs}")
    if "model" in missing:
        parts.append(f"未指定模型名，请用 {GENERIC_MODEL_ENV} 或 --model，"
                     f"并用 --list-models 查当前可用清单")
    if entry.docs:
        parts.append(f"申请入口：{entry.docs}")
    return "；".join(parts)


# ---------------------------------------------------------------- 模型清单发现
def list_models(
    provider: str,
    *,
    base_url: str = "",
    api_key: str = "",
    timeout_s: float = 10.0,
    limit: int = 200,
) -> dict[str, Any]:
    """打 `GET {base}/models` 拿该端点的真实模型清单。

    存在的理由：模型名换代很快（见模块开头第 3 条），与其让用户对着文档猜，
    不如直接问端点。OpenAI 兼容网关与 Anthropic 都实现了这个端点。

    返回 dict，永不抛异常 —— 发现失败本身就是一条有用的信息。
    """
    entry = get(provider)
    if entry is None:
        return {"provider": provider, "ok": False, "error": f"未知提供商 {provider!r}"}

    resolved_base = resolve_base_url(provider, base_url)
    resolved_key = resolve_api_key(provider, api_key)
    if not resolved_base:
        return {"provider": provider, "ok": False, "error": "未配置端点（base_url）"}

    url = f"{resolved_base}/models"
    headers = {"Accept": "application/json", **auth_headers(provider, resolved_key)}
    if entry.kind == "anthropic":
        headers.setdefault("anthropic-version", "2023-06-01")

    request = build_request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        return {"provider": provider, "ok": False, "url": url,
                "error": http_error_text(exc)}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"provider": provider, "ok": False, "url": url, "error": str(exc)[:160]}
    except json.JSONDecodeError as exc:
        return {"provider": provider, "ok": False, "url": url,
                "error": f"响应不是 JSON：{exc}"}

    ids = _extract_model_ids(payload, entry.kind)
    return {"provider": provider, "ok": True, "url": url,
            "count": len(ids), "models": ids[:limit]}


def _extract_model_ids(payload: Any, kind: str) -> list[str]:
    """兼容两种响应形状：OpenAI 的 {"data":[{"id":...}]} 与 Anthropic 的同构写法。"""
    if isinstance(payload, dict):
        rows = payload.get("data") or payload.get("models") or []
    elif isinstance(payload, list):
        rows = payload
    else:
        rows = []
    ids: list[str] = []
    for row in rows:
        if isinstance(row, dict):
            value = row.get("id") or row.get("name") or row.get("model")
        else:
            value = row
        if isinstance(value, str) and value:
            ids.append(value)
    return sorted(dict.fromkeys(ids))


def error_excerpt(exc: urllib.error.HTTPError) -> str:
    """从 HTTP 错误响应体里抠出可读的一行（各家错误 JSON 形状不一，做容错）。"""
    try:
        raw = exc.read().decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001  # pragma: no cover - 读不到 body 时不该再炸一次
        return ""
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            err = obj.get("error", obj)
            if isinstance(err, dict):
                return str(err.get("message", raw))[:160]
    except json.JSONDecodeError:
        pass
    return raw[:160]


def looks_like_cloudflare_block(status: int, detail: str) -> bool:
    """`403` + 1010 / 挑战页 ⇒ 几乎可以确定是 Cloudflare 按 UA 拦截。

    判据取「状态码 + 特征串」两个条件同时成立，避免把普通的 403 鉴权失败
    误诊成 UA 问题而把用户带偏。
    """
    if status != 403:
        return False
    low = (detail or "").lower()
    return "1010" in low or "just a moment" in low or "<!doctype html" in low


def http_error_text(exc: urllib.error.HTTPError) -> str:
    """统一的 HTTP 错误文案：`HTTP <code>（可执行提示）：<摘录>`。

    提示只在真有线索时给 —— 每次报错都糊一串建议等于没建议。
    """
    detail = error_excerpt(exc)
    hint = ""
    if looks_like_cloudflare_block(exc.code, detail):
        hint = CLOUDFLARE_UA_HINT
    elif exc.code in (400, 404) and "model" in detail.lower():
        hint = "（模型名可能已过期，用 --list-models 查当前可用清单）"
    body = f"：{detail}" if detail else ""
    return f"HTTP {exc.code}{hint}{body}"


def parse_fallbacks(spec: str | list[str] | tuple[str, ...] | None) -> list[tuple[str, str]]:
    """把 `"a/x, b/y"` 或列表解析成 [(provider, model), ...]。

    逗号或分号分隔，忽略空项与重复项，保持书写顺序（顺序即优先级）。
    允许只写提供商名（`groq`），此时模型名留空、由该家的默认值/环境变量补。
    """
    if not spec:
        return []
    raw = [spec] if isinstance(spec, str) else list(spec)
    out: list[tuple[str, str]] = []
    for chunk in raw:
        for piece in str(chunk).replace(";", ",").split(","):
            piece = piece.strip()
            if not piece:
                continue
            name, model = split_model_spec(piece)
            if not name and piece.lower() in PROVIDERS:
                name, model = piece.lower(), ""
            if name and (name, model) not in out:
                out.append((name, model))
    return out


def fallbacks_from_env() -> list[tuple[str, str]]:
    return parse_fallbacks(_env(GENERIC_FALLBACK_ENV))
