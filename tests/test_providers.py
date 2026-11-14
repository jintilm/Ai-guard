"""多提供商注册表测试。

这层的失败模式很隐蔽：**注册表说可用、真调用报 401**，或者
`auto` 悄悄选了另一家却没人发现。所以这里既校验数据表的自洽性
（每家字段齐全、顺序一致），也校验解析优先级、URL/鉴权拼装、
回退链读取与模型清单发现。

全部用例都先把相关环境变量清干净 —— 否则开发机上恰好配了
DEEPSEEK_API_KEY，`auto` 的断言就会随机器而变。
"""
from __future__ import annotations

import json

import pytest

from prompt_ids.detectors.semantic import providers as P

# 需要隔离的环境变量：通用项 + 每家自己的 key/endpoint 变量 + {NAME}_BASE_URL
_ENV_NAMES = {
    *P.GENERIC_KEY_ENVS,
    P.GENERIC_BASE_URL_ENV,
    P.GENERIC_MODEL_ENV,
    P.GENERIC_PROVIDER_ENV,
    P.GENERIC_FALLBACK_ENV,
    *P.GENERIC_API_VERSION_ENVS,
    *P.GENERIC_DEPLOYMENT_ENVS,
    "AZURE_OPENAI_DEPLOYMENT",
    "AZURE_OPENAI_API_VERSION",
}
for _name, _entry in P.PROVIDERS.items():
    _ENV_NAMES.update(_entry.key_envs)
    _ENV_NAMES.update(_entry.base_url_envs)
    _ENV_NAMES.add(f"{_name.upper()}_BASE_URL")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """把所有相关环境变量清空，让每个用例都在「裸环境」下断言。"""
    for name in _ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def setenv(monkeypatch, **kv):
    for key, value in kv.items():
        monkeypatch.setenv(key, value)


class _Body:
    """最小的假响应体：HTTPError 会拿它当错误页读取，并在析构时尝试 close()。"""

    def __init__(self, data: bytes):
        self._data = data

    def read(self) -> bytes:
        return self._data

    def close(self) -> None:
        pass


class _FakeResponse:
    def __init__(self, payload):
        self._body = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# ---------------------------------------------------------------- 表结构自洽
def test_registry_is_populated():
    names = P.provider_names()
    assert len(names) >= 20
    assert "deepseek" in names and "openai" in names and "anthropic" in names
    assert "ollama" in names, "本地推理是一等公民，不能漏"


def test_auto_priority_covers_registry_except_custom():
    """auto 的选型顺序必须覆盖注册表 —— 漏掉一家等于它永远不会被 auto 选中。

    唯一的例外是 `custom`：它的端点无从推断，auto 猜一个只会 404，
    所以必须由用户显式指定（PROMPT_IDS_LLM_PROVIDER=custom 或 --semantic-backend custom）。
    """
    covered = set(P.AUTO_PRIORITY)
    assert len(P.AUTO_PRIORITY) == len(set(P.AUTO_PRIORITY)), "auto 顺序里不能有重复"
    assert set(P.PROVIDERS) - covered == {"custom"}, "除了 custom，不该有厂商漏在 auto 之外"
    assert covered <= set(P.PROVIDERS), "auto 里有注册表不认识的厂商名"


@pytest.mark.parametrize("name", sorted(P.PROVIDERS))
def test_every_provider_is_well_formed(name):
    entry = P.PROVIDERS[name]
    assert entry.name == name, "键与条目名不一致会让 driver 查错表"
    assert entry.label, "缺少中文展示名"
    assert entry.kind in P.KINDS, f"未知协议 {entry.kind}，没有适配器能处理"
    assert entry.path.startswith("/"), "path 必须是相对 base_url 的绝对路径"
    # 端点要么写死在表里，要么由厂商变量或通用变量提供 —— 三者都空才真没法拼 URL
    assert entry.base_url or entry.base_url_envs or name == "custom", (
        f"{name} 既无默认端点也无端点变量"
    )
    if entry.needs_key:
        assert entry.key_envs, f"{name} 需要 Key 却没声明环境变量名"
    if not entry.needs_key:
        assert entry.is_local


def test_domestic_providers_come_before_international_in_auto():
    """auto 先国内后国外：中文场景与成本考虑，这个顺序不能被打乱。"""
    order = P.AUTO_PRIORITY
    assert order.index("deepseek") < order.index("openai")
    assert order.index("qwen") < order.index("groq")


def test_local_endpoints_are_last_in_auto():
    order = P.AUTO_PRIORITY
    assert order.index("ollama") > order.index("openai")
    assert order.index("lmstudio") == len(order) - 1


def test_local_candidates_excludes_azure_and_custom():
    """azure 缺端点、custom 无默认端点，都不该被当成「随手可用的本地端点」。"""
    assert P.local_candidates() == ("ollama", "vllm", "lmstudio")


def test_azure_is_pure_data_not_special_case():
    azure = P.PROVIDERS["azure"]
    assert "{deployment}" in azure.path
    assert azure.api_version
    assert azure.auth_header == "api-key"
    assert azure.auth_prefix == "", "api-key 头不带 Bearer 前缀"
    assert azure.base_url == "" and azure.base_url_envs


def test_perplexity_endpoint_has_no_v1_suffix():
    assert P.PROVIDERS["perplexity"].base_url == "https://api.perplexity.ai"


def test_json_mode_declared_per_vendor():
    assert P.PROVIDERS["anthropic"].json_mode is False
    assert P.PROVIDERS["perplexity"].json_mode is False
    assert P.PROVIDERS["deepseek"].json_mode is True


# ---------------------------------------------------------------- provider/model 写法
@pytest.mark.parametrize("spec,expected", [
    # 没有斜杠 = 没有 provider 前缀，整串都是模型名（裸厂商名由 parse_fallbacks /
    # 工厂另做处理，split_model_spec 只负责「带斜杠且左半边是已知厂商」的情形）
    ("deepseek", ("", "deepseek")),
    ("deepseek/deepseek-v4-flash", ("deepseek", "deepseek-v4-flash")),
    ("groq", ("", "groq")),
    # OpenRouter 的模型名自身带斜杠：只切第一个分隔符，剩下整段留给模型名
    ("openrouter/openai/gpt-5.4", ("openrouter", "openai/gpt-5.4")),
    # HuggingFace repo id 的左半边不是已知 provider —— 必须原样保留
    ("protectai/deberta-v3-base-prompt-injection-v2",
     ("", "protectai/deberta-v3-base-prompt-injection-v2")),
    ("", ("", "")),
    ("local", ("", "local")),
])
def test_split_model_spec(spec, expected):
    assert P.split_model_spec(spec) == expected


def test_split_model_spec_is_case_insensitive_on_provider():
    assert P.split_model_spec("DeepSeek/deepseek-v4-flash") == ("deepseek", "deepseek-v4-flash")


def test_get_is_case_insensitive():
    assert P.get("DeepSeek") is P.PROVIDERS["deepseek"]
    assert P.get(" NOPE ") is None


# ---------------------------------------------------------------- 端点拼装
@pytest.mark.parametrize("provider,expected", [
    ("deepseek", "https://api.deepseek.com/v1/chat/completions"),
    ("qwen", "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions"),
    ("zhipu", "https://open.bigmodel.cn/api/paas/v4/chat/completions"),
    ("moonshot", "https://api.moonshot.cn/v1/chat/completions"),
    ("ollama", "http://localhost:11434/v1/chat/completions"),
    ("perplexity", "https://api.perplexity.ai/chat/completions"),
    ("anthropic", "https://api.anthropic.com/v1/messages"),
])
def test_build_url_for_typical_providers(provider, expected):
    assert P.build_url(provider) == expected


def test_build_url_azure_renders_deployment_and_api_version(monkeypatch):
    setenv(monkeypatch,
           AZURE_OPENAI_ENDPOINT="https://my-res.openai.azure.com",
           AZURE_OPENAI_API_KEY="k123")
    url = P.build_url("azure", model="my-gpt-deploy")
    assert url == ("https://my-res.openai.azure.com/openai/deployments/"
                   "my-gpt-deploy/chat/completions?api-version=2024-06-01")


def test_build_url_azure_falls_back_to_model_name_as_deployment(monkeypatch):
    setenv(monkeypatch, AZURE_OPENAI_ENDPOINT="https://my-res.openai.azure.com")
    # 未指定 deployment 变量时，模型名位置本就该填部署名
    assert "/deployments/gpt-4o-mini/" in P.build_url("azure", model="gpt-4o-mini")


def test_build_url_azure_api_version_override(monkeypatch):
    setenv(monkeypatch,
           AZURE_OPENAI_ENDPOINT="https://my-res.openai.azure.com",
           AZURE_OPENAI_API_VERSION="2025-01-01-preview")
    assert P.build_url("azure", model="d").endswith("api-version=2025-01-01-preview")


def test_build_url_custom_requires_explicit_endpoint(monkeypatch):
    """custom 注册表端点为空，必须靠环境变量提供，否则不该拼出一个假 URL。"""
    assert P.build_url("custom") == "/chat/completions"
    setenv(monkeypatch, PROMPT_IDS_LLM_BASE_URL="https://gw.corp/v1")
    assert P.build_url("custom") == "https://gw.corp/v1/chat/completions"


def test_build_url_unknown_provider_is_harmless():
    assert P.build_url("nope", "https://x/v1") == "https://x/v1/chat/completions"


# ---------------------------------------------------------------- 鉴权头
def test_auth_headers_per_protocol():
    assert P.auth_headers("deepseek", "sk-1") == {"Authorization": "Bearer sk-1"}
    assert P.auth_headers("azure", "k123") == {"api-key": "k123"}
    assert P.auth_headers("anthropic", "sk-ant") == {"x-api-key": "sk-ant"}


def test_auth_headers_empty_without_key():
    assert P.auth_headers("deepseek", "") == {}
    assert P.auth_headers("ollama", "") == {}
    assert P.auth_headers("nope", "k") == {}


# ---------------------------------------------------------------- 解析优先级
def test_resolve_api_key_priority(monkeypatch):
    setenv(monkeypatch, DEEPSEEK_API_KEY="vendor")
    assert P.resolve_api_key("deepseek") == "vendor"
    setenv(monkeypatch, PROMPT_IDS_LLM_API_KEY="generic")
    assert P.resolve_api_key("deepseek") == "generic", "通用变量应盖过厂商变量"
    assert P.resolve_api_key("deepseek", "explicit") == "explicit"


def test_resolve_base_url_priority(monkeypatch):
    # 1) 注册表默认
    assert P.resolve_base_url("deepseek") == "https://api.deepseek.com/v1"
    # 2) {NAME}_BASE_URL 盖过默认
    setenv(monkeypatch, DEEPSEEK_BASE_URL="https://proxy/v1")
    assert P.resolve_base_url("deepseek") == "https://proxy/v1"
    # 3) 通用变量盖过厂商变量
    setenv(monkeypatch, PROMPT_IDS_LLM_BASE_URL="https://gw/v1")
    assert P.resolve_base_url("deepseek") == "https://gw/v1"
    # 4) 显式入参最高
    assert P.resolve_base_url("deepseek", "https://x/v1") == "https://x/v1"


def test_vendor_convention_endpoint_beats_generic_name_scheme(monkeypatch):
    """Azure 的官方变量名是 AZURE_OPENAI_ENDPOINT，不是 AZURE_BASE_URL。

    顺序写反的话，用户按官方文档配的 AZURE_OPENAI_ENDPOINT 会被无视，
    然后收到一个「未配置端点」的报错 —— 极其费解。
    """
    setenv(monkeypatch,
           AZURE_OPENAI_ENDPOINT="https://official.openai.azure.com",
           AZURE_BASE_URL="https://wrong.example.com")
    assert P.resolve_base_url("azure") == "https://official.openai.azure.com"


def test_resolve_base_url_strips_trailing_slash(monkeypatch):
    assert P.resolve_base_url("deepseek", "https://proxy/v1/") == "https://proxy/v1"


def test_resolve_model_priority(monkeypatch):
    assert P.resolve_model("deepseek") == P.PROVIDERS["deepseek"].default_model
    assert P.resolve_model("deepseek", fallback="fb") == "fb"
    setenv(monkeypatch, PROMPT_IDS_LLM_MODEL="env-model")
    assert P.resolve_model("deepseek", fallback="fb") == "env-model"
    assert P.resolve_model("deepseek", override="ov") == "ov"


def test_resolve_deployment_prefers_dedicated_var(monkeypatch):
    assert P.resolve_deployment("azure", "gpt-4o") == "gpt-4o"
    setenv(monkeypatch, AZURE_OPENAI_DEPLOYMENT="prod-deploy")
    assert P.resolve_deployment("azure", "gpt-4o") == "prod-deploy"


# ---------------------------------------------------------------- auto 选型
def test_resolve_provider_explicit_wins(monkeypatch):
    setenv(monkeypatch, DEEPSEEK_API_KEY="k")
    assert P.resolve_provider("groq") == "groq"


def test_resolve_provider_unknown_is_empty_not_silent_openai():
    """未知名字必须响亮地变成「没得选」，否则会让人以为在用 A、其实在用 B。"""
    assert P.resolve_provider("anthropic-bedrock") == ""


def test_resolve_provider_auto_picks_first_keyed_by_priority(monkeypatch):
    assert P.resolve_provider("auto") == "", "裸环境下没有云 Key，应当明确报不可用"
    setenv(monkeypatch, OPENAI_API_KEY="k")
    assert P.resolve_provider("auto") == "openai"
    # 国内优先级更高，配了 deepseek 就该选 deepseek
    setenv(monkeypatch, DEEPSEEK_API_KEY="k")
    assert P.resolve_provider("auto") == "deepseek"


def test_resolve_provider_auto_ignores_local_endpoints(monkeypatch):
    """「本机装了 Ollama」不等于「Ollama 正在跑」。

    auto 若选中一个没启动的 localhost 服务，就把「明确不可用」
    换成了「看着可用、调用时才失败」—— 降级契约里最不该有的假阳性。
    """
    assert P.local_candidates(), "前提：确实存在免 Key 的本地端点"
    assert P.resolve_provider("auto") == ""


def test_resolve_provider_env_override(monkeypatch):
    setenv(monkeypatch, PROMPT_IDS_LLM_PROVIDER="qwen")
    assert P.resolve_provider("auto") == "qwen"
    setenv(monkeypatch, PROMPT_IDS_LLM_PROVIDER="nope")
    assert P.resolve_provider("auto") == ""


def test_generic_key_enables_any_provider(monkeypatch):
    setenv(monkeypatch, PROMPT_IDS_LLM_API_KEY="k", PROMPT_IDS_LLM_PROVIDER="moonshot")
    assert P.resolve_provider("auto") == "moonshot"


# ---------------------------------------------------------------- 诊断
def test_diagnose_reports_missing_key_and_where_to_put_it():
    info = P.diagnose("deepseek")
    assert info["available"] is False
    assert info["missing"] == ["api_key"]
    assert "DEEPSEEK_API_KEY" in info["reason"]
    assert ".env" in info["reason"], "要告诉用户往哪填，而不是只说缺 Key"
    assert info["endpoint"] == "https://api.deepseek.com/v1/chat/completions"


def test_diagnose_available_when_key_present(monkeypatch):
    setenv(monkeypatch, DEEPSEEK_API_KEY="sk-x")
    info = P.diagnose("deepseek")
    assert info["available"] is True
    assert info["missing"] == []
    assert info["reason"] == "可用"
    assert info["has_key"] is True


def test_diagnose_local_is_available_without_key():
    info = P.diagnose("ollama")
    assert info["available"] is True
    assert info["needs_key"] is False
    assert info["is_local"] is True


def test_diagnose_custom_without_endpoint_explains_which_var():
    info = P.diagnose("custom")
    assert info["available"] is False
    assert "base_url" in info["missing"]
    assert P.GENERIC_BASE_URL_ENV in info["reason"]


def test_diagnose_unknown_provider_lists_alternatives():
    info = P.diagnose("nope")
    assert info["available"] is False
    assert "deepseek" in info["reason"]


def test_diagnose_never_exposes_the_key(monkeypatch):
    setenv(monkeypatch, DEEPSEEK_API_KEY="sk-supersecret")
    info = P.diagnose("deepseek")
    assert "sk-supersecret" not in json.dumps(info, ensure_ascii=False)


# ---------------------------------------------------------------- 回退链
def test_parse_fallbacks_mixed_separators_and_order():
    pairs = P.parse_fallbacks("groq/llama-3.3-70b-versatile, openai/gpt-5.4 ; xai/grok-4.3")
    assert pairs == [("groq", "llama-3.3-70b-versatile"),
                     ("openai", "gpt-5.4"),
                     ("xai", "grok-4.3")]


def test_parse_fallbacks_allows_bare_provider_name():
    """只写厂商名时模型名留空，由该家的默认值/环境变量补 —— 不该被丢掉。"""
    assert P.parse_fallbacks("groq") == [("groq", "")]
    assert P.parse_fallbacks("groq, deepseek/deepseek-v4-flash") == [
        ("groq", ""), ("deepseek", "deepseek-v4-flash")]


def test_parse_fallbacks_dedups_and_skips_unknown():
    assert P.parse_fallbacks("groq, groq, nope/x") == [("groq", "")]
    assert P.parse_fallbacks("") == []
    assert P.parse_fallbacks(None) == []


def test_parse_fallbacks_accepts_list():
    assert P.parse_fallbacks(["groq", "xai/grok-4.3"]) == [("groq", ""), ("xai", "grok-4.3")]


def test_fallbacks_from_env(monkeypatch):
    setenv(monkeypatch, PROMPT_IDS_LLM_FALLBACKS="groq, openai/gpt-5.4")
    assert P.fallbacks_from_env() == [("groq", ""), ("openai", "gpt-5.4")]


# ---------------------------------------------------------------- 模型清单发现
def test_list_models_parses_openai_shape(monkeypatch):
    seen = {}

    def fake_urlopen(request, timeout=None):
        seen["url"] = request.full_url
        seen["auth"] = request.get_header("Authorization")
        return _FakeResponse({"data": [{"id": "b-model"}, {"id": "a-model"}, {"id": "a-model"}]})

    monkeypatch.setattr(P.urllib.request, "urlopen", fake_urlopen)
    setenv(monkeypatch, DEEPSEEK_API_KEY="sk-x")
    result = P.list_models("deepseek")
    assert result["ok"] is True
    assert result["url"] == "https://api.deepseek.com/v1/models"
    assert result["models"] == ["a-model", "b-model"], "应去重并排序"
    assert seen["auth"] == "Bearer sk-x"


def test_list_models_parses_anthropic_shape(monkeypatch):
    monkeypatch.setattr(P.urllib.request, "urlopen",
                        lambda request, timeout=None: _FakeResponse(
                            {"data": [{"id": "claude-sonnet-4-6"}]}))
    result = P.list_models("anthropic")
    assert result["ok"] is True and result["models"] == ["claude-sonnet-4-6"]


def test_list_models_reports_http_error_without_raising(monkeypatch):
    import urllib.error

    def boom(request, timeout=None):
        raise urllib.error.HTTPError(
            request.full_url, 401, "Unauthorized", {}, _Body(b'{"error":{"message":"bad key"}}'))

    monkeypatch.setattr(P.urllib.request, "urlopen", boom)
    result = P.list_models("deepseek")
    assert result["ok"] is False
    assert "401" in result["error"] and "bad key" in result["error"]


def test_list_models_reports_network_error_without_raising(monkeypatch):
    import urllib.error

    def boom(request, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(P.urllib.request, "urlopen", boom)
    result = P.list_models("ollama")
    assert result["ok"] is False
    assert "refused" in result["error"]


def test_list_models_without_endpoint_refuses_clearly():
    result = P.list_models("custom")
    assert result["ok"] is False
    assert "base_url" in result["error"]


def test_list_models_unknown_provider():
    assert P.list_models("nope")["ok"] is False


def test_extract_model_ids_tolerates_odd_shapes():
    assert P._extract_model_ids(["plain", {"name": "n"}], "openai") == ["n", "plain"]
    assert P._extract_model_ids({"models": [{"model": "m"}]}, "openai") == ["m"]
    assert P._extract_model_ids(None, "openai") == []
    assert P._extract_model_ids({"data": [1, None]}, "openai") == []


# ---------------------------------------------------------------- 错误摘录
def test_error_excerpt_reads_nested_message():
    import urllib.error

    exc = urllib.error.HTTPError(
        "http://x", 400, "Bad", {},
        _Body(json.dumps({"error": {"message": "model not found"}}).encode()))
    assert P.error_excerpt(exc) == "model not found"


def test_error_excerpt_falls_back_to_raw_text():
    import urllib.error

    exc = urllib.error.HTTPError("http://x", 500, "Err", {}, _Body(b"<html>oops</html>"))
    assert "oops" in P.error_excerpt(exc)


# ---------------------------------------------------------------- 请求头大小写
def test_build_request_preserves_header_casing():
    """urllib 默认会把头名 capitalize（api-key -> Api-key）。

    HTTP 规范里头名不区分大小写，但 Azure 前置网关 / 企业反代未必这么宽容，
    而这类失败只表现为「本地全通、上网关就 401」。这里把行为钉死，
    防止有人日后「简化」回 Request(headers=...) 又把它改回去。
    """
    request = P.build_request("https://x/v1/chat/completions", data=b"{}",
                              headers={"api-key": "k", "x-api-key": "y",
                                       "Content-Type": "application/json"})
    assert request.get_header("api-key") == "k", "api-key 必须原样小写"
    assert request.get_header("x-api-key") == "y", "x-api-key 必须原样小写"
    assert request.headers["Content-Type"] == "application/json"
    assert request.data == b"{}"


def test_build_request_keeps_defaults_without_headers():
    request = P.build_request("https://x/v1", method="GET")
    assert request.method == "GET"
    assert request.data is None
