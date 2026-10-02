"""护栏 —— 长度校验、结果缓存、令牌桶限流。

放在检测之前，把 DoS、重复流量挡在门外，同时给规则层省掉大量重复计算。
"""
from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class GuardConfig:
    max_chars: int = 50_000
    max_variants_fanout: int = 5_000  # 归一化后文本长度的安全上限倍数
    cache_size: int = 1_000
    cache_ttl_s: float = 300.0
    #: 每窗口每租户的请求上限。**0 = 关闭**。
    #: 此前默认 30 且 `check_rate()` 全仓库无调用点 —— 也就是说这个「保护」
    #: 一次都没生效过，而配置看起来像是生效的。现在它真的接在 `Pipeline.scan`
    #: 上，所以默认值必须改成 0：否则离线评测（900+ 样本）与本地使用会被自己限流。
    rate_limit: int = 0
    rate_window_s: float = 60.0
    max_tracked_users: int = 10_000


def fingerprint(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]


class LengthRejected(Exception):
    def __init__(self, reason: str, chars: int):
        super().__init__(reason)
        self.reason = reason
        self.chars = chars


class LRUCache:
    """带 TTL 的 LRU。键为规范化文本的指纹，值为可序列化的扫描结果。

    **加锁**：代理/REST 是每请求一线程，共享同一个 Pipeline（因而共享同一个
    cache）。原来无锁时 `put` 里的 `while len > size: popitem` 不是原子序列 ——
    超额淘汰，而 `hits`/`misses` 计数漂移 ⇒ `/v1/metrics` 的 `cache_hits` 不可信。

    ⚠ **缓存是进程内的**（`stats()["scope"] == "process"`）：多实例部署时每个
    实例各有一份，命中率**不可横向比较**，也没有跨实例失效。当前部署形态是
    单实例（127.0.0.1 绑定的 api/proxy/web），所以按「适用」处理而不是修 ——
    但读数里必须带 `scope`，否则多实例时那个命中率会被当成全局指标。
    """

    def __init__(self, size: int = 1_000, ttl_s: float = 300.0):
        self.size = size
        self.ttl_s = ttl_s
        self._store: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Any | None:
        with self._lock:
            item = self._store.get(key)
            if item is None:
                self.misses += 1
                return None
            ts, value = item
            if self.ttl_s > 0 and (time.monotonic() - ts) > self.ttl_s:
                self._store.pop(key, None)
                self.misses += 1
                return None
            self._store.move_to_end(key)
            self.hits += 1
            return value

    def put(self, key: str, value: Any) -> None:
        with self._lock:
            self._store[key] = (time.monotonic(), value)
            self._store.move_to_end(key)
            while len(self._store) > self.size:
                self._store.popitem(last=False)

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {"size": len(self._store), "hits": self.hits, "misses": self.misses}

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated: float


class RateLimiter:
    """令牌桶。user 为空时归到 default 租户。"""

    def __init__(self, capacity: int = 30, refill_s: float = 60.0, max_users: int = 10_000):
        self.capacity = capacity
        self.refill_s = refill_s
        self.refill_rate = capacity / refill_s if refill_s > 0 else 0.0
        self.max_users = max_users
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def _evict(self, now: float) -> None:
        """惰性淘汰长期不用的桶。

        没有这一步的话：桶表只增不减，`max_users` 到顶后 `try_acquire`
        对**任何新 key** 直接 False —— 攻击者用一批假 key 就能把后续所有正常
        客户端（哪怕是同一个 IP）永久锁在 429 之外。满桶时每个已经回满的桶
        都可以丢掉：它等价于「新建一个满桶」。
        """
        if len(self._buckets) < self.max_users:
            return
        stale = [key for key, bucket in self._buckets.items()
                 if now - bucket.updated > self.refill_s * 2]
        for key in stale:
            self._buckets.pop(key, None)

    def try_acquire(self, user: str = "default", cost: float = 1.0) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(user)
            if bucket is None:
                self._evict(now)
                if len(self._buckets) >= self.max_users:
                    return False
                bucket = _Bucket(tokens=self.capacity, updated=now)
                self._buckets[user] = bucket
            bucket.tokens = min(self.capacity,
                                bucket.tokens + (now - bucket.updated) * self.refill_rate)
            bucket.updated = now
            if bucket.tokens < cost:
                return False
            bucket.tokens -= cost
            return True

    def remaining(self, user: str = "default") -> float:
        bucket = self._buckets.get(user)
        if bucket is None:
            return float(self.capacity)
        elapsed = time.monotonic() - bucket.updated
        return min(self.capacity, bucket.tokens + elapsed * self.refill_rate)


class Guard:
    def __init__(self, config: GuardConfig | None = None):
        self.config = config or GuardConfig()
        self.cache = LRUCache(self.config.cache_size, self.config.cache_ttl_s)
        # rate_limit=0 表示关闭：默认建一个 capacity=0 的桶会让每次请求都被拒，
        # 那等于把「默认关闭」变成「默认全拒」。
        self.limiter = (
            RateLimiter(self.config.rate_limit, self.config.rate_window_s,
                        self.config.max_tracked_users)
            if self.config.rate_limit and self.config.rate_limit > 0
            else None
        )
        self.rate_limited = 0

    def check_length(self, text: str) -> None:
        if len(text) > self.config.max_chars:
            raise LengthRejected(
                f"输入超长：{len(text)} 字符 > 上限 {self.config.max_chars}", len(text)
            )

    def trim(self, text: str) -> tuple[str, bool]:
        """超长输入截断到上限，返回 (文本, 是否发生截断)。"""
        if len(text) <= self.config.max_chars:
            return text, False
        return text[: self.config.max_chars], True

    def check_rate(self, user: str = "default") -> bool:
        """限流。未配置（rate_limit=0）时永远放行。"""
        if self.limiter is None:
            return True
        allowed = self.limiter.try_acquire(user)
        if not allowed:
            self.rate_limited += 1
        return allowed

    def stats(self) -> dict[str, Any]:
        return {
            "cache": {**self.cache.stats(), "scope": "process"},
            "rate_limit": self.config.rate_limit,
            "rate_window_s": self.config.rate_window_s,
            "rate_limited": self.rate_limited,
        }
