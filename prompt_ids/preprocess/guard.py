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
    rate_limit: int = 30
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
    """带 TTL 的 LRU。键为规范化文本的指纹，值为可序列化的扫描结果。"""

    def __init__(self, size: int = 1_000, ttl_s: float = 300.0):
        self.size = size
        self.ttl_s = ttl_s
        self._store: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Any | None:
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
        self._store[key] = (time.monotonic(), value)
        self._store.move_to_end(key)
        while len(self._store) > self.size:
            self._store.popitem(last=False)

    def clear(self) -> None:
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
        self.limiter = RateLimiter(
            self.config.rate_limit, self.config.rate_window_s, self.config.max_tracked_users
        )

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
        return self.limiter.try_acquire(user)
