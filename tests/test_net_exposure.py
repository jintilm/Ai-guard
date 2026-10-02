"""监听地址暴露面的守护（`prompt_ids/net.py`）。

守的是三件事：

1. **默认值不是保证。** `--host` 是自由字符串，改成 `0.0.0.0` 就对外监听；
   代理与检测台**没有客户端鉴权**，API 的鉴权可关。所以「绑非回环 + 无鉴权」
   这个组合必须响亮告警。
2. **告警走 stderr**，不污染 stdout —— `--json` 的输出流必须是干净 JSON。
3. **docstring 不得把默认值写成保证。** 本文件原先白纸黑字写着
   「只绑 127.0.0.1，不对外监听」，而参数默认值不是保证 —— 那是一句会误导运维的话。
"""
from __future__ import annotations

import io
from contextlib import redirect_stderr, redirect_stdout

import pytest

from prompt_ids import net


# ---------------------------------------------------------------- 判定
@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.53", "localhost", "::1",
                                  "[::1]", "LOCALHOST"])
def test_loopback_hosts_are_recognised(host: str):
    assert net.is_loopback(host) is True


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.10", "10.0.0.5",
                                  "example.internal", "", "  ", "0.0.0.0:8080"])
def test_non_loopback_and_unparseable_hosts_are_treated_as_exposed(host: str):
    """判定不了的一律按**非本机**处理 —— 宁可多报一次告警。"""
    assert net.is_loopback(host) is False


def test_empty_host_is_not_loopback():
    """空串在 HTTPServer 里等价于绑定全部地址，不能当成「本机」而静默放行。"""
    assert net.is_loopback("") is False


# ---------------------------------------------------------------- 告警内容
def test_exposes_nothing_when_bound_to_loopback():
    assert net.exposure_report("127.0.0.1", service="检测台", authenticated=False) == ""


def test_silent_when_authenticated_even_if_publicly_bound():
    """API 配了 Key 就算是有鉴权 —— 不该再告警一遍制造噪音。"""
    assert net.exposure_report("0.0.0.0", service="REST API", authenticated=True) == ""


def test_warns_with_the_right_instructions_when_public_and_unauthenticated():
    message = net.exposure_report("0.0.0.0", service="检测台", authenticated=False)
    assert "检测台" in message
    # 必须说清「暴露了什么」，否则用户不知道要不要紧
    assert "/v1/scan" in message
    assert "/v1/canary/issue" in message
    # 必须给正确姿势，而不是只说「危险」
    assert "反向代理" in message and "PROMPT_IDS_API_KEY" in message


def test_warning_goes_to_stderr_not_stdout():
    """stdout 是 `--json` 的输出流，告警污染它会直接把 JSON 解析搞坏。"""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        net.warn_if_exposed("0.0.0.0", service="透明代理", authenticated=False)
    assert out.getvalue() == "", "告警写进了 stdout"
    assert "透明代理" in err.getvalue()


def test_no_warning_emits_nothing_at_all_on_loopback():
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        assert net.warn_if_exposed("127.0.0.1", service="x", authenticated=False) == ""
    assert out.getvalue() == err.getvalue() == ""


# ---------------------------------------------------------------- 三个入口都接上了
def test_proxy_declares_itself_unauthenticated():
    """代理没有客户端鉴权：api_key 是给上游的，客户端 Authorization 是透传的。"""
    assert "warn_if_exposed" in _source_of("create_server", "prompt_ids.proxy.server")
    assert "authenticated=False" in _source_of("create_server", "prompt_ids.proxy.server")


def test_playground_declares_itself_unauthenticated():
    assert "warn_if_exposed" in _source_of("serve", "prompt_ids.web.playground")
    assert "authenticated=False" in _source_of("serve", "prompt_ids.web.playground")


def test_api_warning_depends_on_its_own_auth_switch():
    source = _source_of("create_api_server", "prompt_ids.api.server")
    assert "authenticated=config.auth_required" in source, \
        "API 只有「对外监听且没配 Key」才该告警，不能一律告警或一律沉默"


def test_playground_docstring_does_not_claim_it_never_listens_externally():
    """**docstring 不得把默认值说成保证。**

    原文有一条 bullet 写的是「只绑 127.0.0.1，不对外监听」，而 `host` 参数可传任意值
    —— 那句话会让运维以为改 `--host` 不会对外服务。守护的是**那一条 bullet**，
    而不是全文不许出现这几个字（新 docstring 里要解释「为什么不能这么写」，
    必然得引用它）。
    """
    import re

    import prompt_ids.web.playground as playground

    doc = playground.__doc__ or ""
    old_claim = re.compile(r"^\s*[*\-]?\s*只绑\s*127\.0\.0\.1[，,]\s*不对外监听", re.M)
    assert not old_claim.search(doc), \
        "docstring 里仍有「只绑 127.0.0.1，不对外监听」这条断言 —— " \
        "那是把默认值说成保证；应改为「默认只绑本机，改 --host 会告警」"
    # 正面要求：必须写清「默认值」与「无鉴权」这两件事实
    assert "默认值" in doc and "鉴权" in doc


def _source_of(func_name: str, module_path: str) -> str:
    import importlib
    import inspect

    module = importlib.import_module(module_path)
    return inspect.getsource(getattr(module, func_name))
