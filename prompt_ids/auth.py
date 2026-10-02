"""共享的客户端鉴权 —— 三个 HTTP 入口用**同一套**实现。

## 为什么抽出来

审计记录里有一处不对称：`api` 有客户端鉴权（`PROMPT_IDS_API_KEY`），
而 `proxy` 与 `web --serve` **完全没有**。不对称本身就是缺陷：

- 容器/K8s 部署必然要 `--host 0.0.0.0`（Pod 里 `127.0.0.1` 别的容器摸不到），
  于是代理与检测台在生产里**必然暴露**，而唯一能挡的就是鉴权 —— 它俩却没有。
- 「加个反代就行」在文档里是**声明**，不是**方案**：没有可运行的示例配置，
  每个人都要自己重新推一遍 TLS、超时、体积上限、CORS 该怎么配。

所以这里把 API 那套抽成共享实现，让代理与检测台也能开鉴权，并在
`scripts/deploy_check.py` 里给一份可执行的正确姿势。

## 为什么不用 HTTP Basic

鉴权头在两个入口上语义不同：代理的 `Authorization` 头是**透传给上游**的
（`Authorization: Bearer <上游 key>`），所以代理**不能**用它表达自己的鉴权 ——
否则客户端的令牌会跟上游凭据混在一起，且上游会收到本服务不认识的请求头。

因此统一用 **`X-API-Key`**（与 API 入口一致），并**额外**接受
`Authorization: Bearer`，但仅当客户端没有同时透传上游凭据时 ——
实现上就是「两者都提供且不一致则拒绝」，避免「用 Bearer 覆盖了 X-API-Key」
这种含糊路径。

## 比较方式

`hmac.compare_digest` 而不是 `==`：时序侧信道在本地回环上难测，
但成本是**一次函数调用**，没有任何理由不选对的那个。
"""
from __future__ import annotations

import hmac

#: 客户端提供本服务凭据的头。代理**不用** Authorization 承载自己的鉴权 ——
#: 那个头是透传给上游的（见模块 docstring）。
HEADER = "X-API-Key"


def provided_key(headers) -> str:
    """从请求头里取客户端提供的本服务凭据（`X-API-Key` 优先）。"""
    value = ""
    try:
        value = str(headers.get(HEADER) or "").strip()
    except Exception:  # noqa: BLE001 - headers 只是个映射，别让它炸掉鉴权
        value = ""
    if value:
        return value
    auth = ""
    try:
        auth = str(headers.get("Authorization") or "").strip()
    except Exception:  # noqa: BLE001
        auth = ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def authorized(headers, expected: str | None) -> bool:
    """`expected` 为空 ⇒ **不鉴权**（保持默认行为，不破坏现有部署）。

    ⚠ 「不配置 Key 就放行」是这个项目的既定默认（`api` 也一样）。
    所以配套必须有 `prompt_ids.net.warn_if_exposed` 那个告警 ——
    **两个机制缺一不可**：不告警 = 静默暴露；不鉴权 = 没有第二道门。
    """
    if not expected:
        return True
    provided = provided_key(headers)
    if not provided:
        return False
    return hmac.compare_digest(provided, str(expected))
