"""流水线编排：层串联、短路、超时、缓存。"""
from __future__ import annotations

import copy
import time
from dataclasses import dataclass

from prompt_ids.core.policy import Policy, PolicyEngine
from prompt_ids.core.types import Action, Finding, Level, ScanResult
from prompt_ids.core.verdict import FusionConfig, decide, explain, fuse, grade
from prompt_ids.detectors import (
    DetectorContext,
    DetectorRegistry,
    HeuristicDetector,
    RuleDetector,
    SemanticDetector,
)
from prompt_ids.audit.logger import AuditLogger
from prompt_ids.detectors.base import Detector
from prompt_ids.detectors.semantic.detector import SemanticDetector
from prompt_ids.memory.detector import MemoryDetector
from prompt_ids.preprocess import Preprocessor
from prompt_ids.preprocess.guard import Guard, GuardConfig, LengthRejected, fingerprint
from prompt_ids.rules.loader import RuleBook

# 冷启动超过这个量级才值得在说明里点出来（规则/启发层只有几毫秒，报了是噪音）
COLD_START_REPORT_MS = 100.0


@dataclass(frozen=True, slots=True)
class PipelineConfig:
    fusion: FusionConfig = FusionConfig()
    policy: str = "default"
    enable_cache: bool = True
    short_circuit_on_critical: bool = True
    budget_ms: float = 500.0
    include_canonical: bool = False
    # 语义层开关。budget 至少要容得下一次模型推理
    semantic_enabled: bool = False
    semantic_mode: str = "fallback"
    semantic_backend: str = "auto"
    semantic_model: str = ""
    semantic_timeout_s: float | None = None
    # 向量记忆库（自进化）：开启后会把确认的攻击写回记忆
    memory_enabled: bool = False
    memory_encoder: str = "auto"
    memory_threshold: float = 0.86
    memory_auto_learn: bool = True
    memory_dir: str = ""
    # 审计日志：留空则不落盘。只记录指纹，不记录原文
    audit_path: str = ""
    audit_buffer: int = 0
    # 超长输入：截断后照常检测（False 则沿用旧行为：一律按最高危阻断）
    truncate_oversized: bool = True


class Pipeline:
    """四级主干的执行顺序编排。

    L1 → L2 →（预筛门禁）→ L3 → 决策。任一层超时不拖垮整体，降级继续。
    """

    def __init__(
        self,
        preprocessor: Preprocessor | None = None,
        registry: DetectorRegistry | None = None,
        guard: Guard | None = None,
        policies: PolicyEngine | None = None,
        config: PipelineConfig | None = None,
        audit: AuditLogger | None = None,
    ):
        self.preprocessor = preprocessor or Preprocessor()
        self.registry = registry or DetectorRegistry(
            detectors=[
                RuleDetector(rules=RuleBook()),
                HeuristicDetector(),
                SemanticDetector(enabled=False),
            ]
        )
        self.guard = guard or Guard(GuardConfig())
        self.policies = policies or PolicyEngine()
        self.config = config or PipelineConfig()
        self.audit = audit or (
            AuditLogger(self.config.audit_path, buffer=self.config.audit_buffer)
            if self.config.audit_path else None
        )
        # 已支付一次性初始化开销的层（warmup 预加载过，或已执行过一次）
        self._warm: set[str] = set()
        # 各层的一次性初始化耗时，仅用于观测，永远不占用请求预算
        self.cold_start_ms: dict[str, float] = {}

    # ---------- 内建配件 ----------
    @property
    def rule_detector(self) -> RuleDetector | None:
        return self.registry.get("rule")  # type: ignore[return-value]

    @property
    def semantic_detector(self) -> SemanticDetector | None:
        return self.registry.get("semantic")  # type: ignore[return-value]

    @property
    def memory_detector(self) -> MemoryDetector | None:
        return self.registry.get("memory")  # type: ignore[return-value]

    def reload_rules(self) -> bool:
        det = self.rule_detector
        if det is None or det.rulebook is None:
            return False
        return det.rulebook.reload_if_stale()

    def warmup(self) -> None:
        """预加载检测层，把一次性初始化开销从请求预算里摘出去。

        budget_ms 量的是"这条请求本身花了多久"，模型加载不属于请求成本。
        不预热的话语义层 10s 级的权重加载会落在首个真实请求上，直接击穿
        500ms 预算，把后面的记忆层整片跳过 —— 那是"模块显示已开启、
        实际一次没跑过"最难排查的一类故障。

        这里预加载过的层记入 cold_start_ms，之后所有请求都不再为它买单。
        """
        for detector in self.registry:
            warm = getattr(detector, "warmup", None)
            if not callable(warm):
                continue
            started = time.perf_counter()
            try:
                warm()
            except Exception:
                # 预加载失败不回滚：运行期各层会自行降级，主链路不能因为
                # 一个可选依赖装不上就起不来
                continue
            cost = (time.perf_counter() - started) * 1000.0
            self._warm.add(detector.name)
            self.cold_start_ms[detector.name] = round(
                self.cold_start_ms.get(detector.name, 0.0) + cost, 3
            )

    # ---------- 主流程 ----------
    def cache_key(self, fp: str, policy_name: str | None = None) -> str:
        """缓存键必须包含一切会影响判定结果的维度。

        只拿文本指纹当键会导致两种静默错误：
        1. 换策略后仍返回旧策略的动作（strict 被 default 的缓存绕过）
        2. 记忆库写入新攻击后仍返回旧判定（自进化对重复攻击失效）
        """
        parts = [fp, policy_name or self.config.policy]
        rule = self.registry.get("rule")
        tiers = getattr(rule, "tiers", None)
        if tiers:
            parts.append("tiers=" + ",".join(str(t) for t in tiers))
        if self.config.semantic_enabled:
            parts.append(f"sem={self.config.semantic_mode}")
        mem = self.memory_detector
        if mem is not None and mem.enabled:
            # 版本号在每次成功写入后递增，记忆一变缓存即失效
            parts.append(f"mem={mem.version}")
        return "|".join(parts)

    def scan(self, text: str, user: str = "default", policy_name: str | None = None) -> ScanResult:
        started = time.perf_counter()
        if text is None:
            text = ""
        text = str(text)
        policy, fell_back = self.policies.resolve(policy_name or self.config.policy)

        result = ScanResult()
        oversized_note = ""
        try:
            self.guard.check_length(text)
        except LengthRejected as exc:
            if self.config.truncate_oversized:
                # 超长不代表恶意：合法长合同/长文档不该被一律挡在门外。
                # 截断到上限后照常检测，并在说明里标注，避免用户被静默误杀。
                limit = getattr(self.guard.config, "max_chars", 50_000)
                original_len = len(text)
                text = text[:limit]
                result.truncated = True
                oversized_note = f"（输入 {original_len} 字符，超过上限 {limit}，已截断检测）"
            else:
                result.rejected = exc.reason
                result.level = Level.CRITICAL
                result.action = Action.BLOCK
                result.explained = f"输入被护栏拒绝：{exc.reason}"
                result.latency_ms["guard"] = (time.perf_counter() - started) * 1000.0
                return result

        t0 = time.perf_counter()
        variants = self.preprocessor.variants(text)
        canonical = variants[0].text if variants else text
        fp = fingerprint(canonical)
        result.fingerprint = fp
        result.latency_ms["preprocess"] = (time.perf_counter() - t0) * 1000.0

        # 键必须在整次扫描中固定：若在结尾重新计算，自进化刚写入的记忆
        # 会把版本号抬高，导致 put 与 get 用不同的键，缓存失效机制被架空
        cache_key = self.cache_key(fp, policy_name) if self.config.enable_cache else ""
        if self.config.enable_cache:
            cached = self.guard.cache.get(cache_key)
            if cached is not None:
                hit_result: ScanResult = copy.copy(cached)
                hit_result.cached = True
                hit_result.latency_ms = dict(cached.latency_ms)
                hit_result.latency_ms["total_cached"] = (time.perf_counter() - started) * 1000.0
                return hit_result

        ctx = DetectorContext(raw=text, canonical=canonical, variants=variants)

        findings: list[Finding] = []
        subscores: dict[str, float] = {}
        elapsed_total = 0.0

        skipped: list[str] = []
        cold_notes: list[str] = []
        detectors = [d for d in self.registry if d.enabled]
        for index, detector in enumerate(detectors):
            # 预筛门禁：L3 是否调用由前置层的初判分决定
            if isinstance(detector, SemanticDetector) and detector.layer == 3:
                preliminary = fuse(subscores, self.config.fusion)
                if not detector.should_invoke(preliminary, grade(preliminary, self.config.fusion).value):
                    skipped.append(detector.name)
                    continue
                if elapsed_total > self.config.budget_ms:
                    skipped.append(detector.name)
                    continue
            cold = detector.name not in self._warm
            layer_findings, used = detector.timed_detect(ctx)
            result.latency_ms[detector.name] = used
            if cold:
                # 首次执行含一次性初始化（模型加载 / 索引构建）。那不属于
                # 任何单条请求的成本，只记账不占预算；否则冷启动会把后面的
                # 层整片顶掉，而且这种故障只在"全新进程的第一条请求"复现。
                self._warm.add(detector.name)
                self.cold_start_ms[detector.name] = round(
                    self.cold_start_ms.get(detector.name, 0.0) + used, 3
                )
                if used >= COLD_START_REPORT_MS:
                    cold_notes.append(f"{detector.name} {used:.0f}ms")
            else:
                elapsed_total += used
            if layer_findings:
                findings.extend(layer_findings)
                subscores[detector.name] = detector.subscore(layer_findings)
            # 判别层（语义 / 记忆）即使没产生 finding 也要贡献分数 ——
            # 它们同样能把规则层的误判往安全区拉，这条降噪路径很关键
            if isinstance(detector, (SemanticDetector, MemoryDetector)):
                contribution = detector.contribution()
                if contribution is not None:
                    subscores[detector.name] = contribution
            # 短路：CRITICAL 规则命中后不再跑更贵的层
            if (
                self.config.short_circuit_on_critical
                and detector.layer == 1
                and any(
                    f.weight >= self.config.fusion.critical_rule_weight
                    and f.confidence >= self.config.fusion.critical_rule_confidence
                    for f in layer_findings
                )
            ):
                skipped.extend(d.name for d in detectors[index + 1:])
                break
            if elapsed_total > self.config.budget_ms:
                # 预算耗尽：把没跑的层记下来。静默丢弃会让"已开启的模块"
                # 看起来在工作、实际一次没执行，是最难排查的一类故障。
                skipped.extend(d.name for d in detectors[index + 1:])
                break

        result.skipped = tuple(dict.fromkeys(skipped))
        score, level, short_id = decide(findings, subscores, self.config.fusion)
        action = policy.action_for(level)
        if policy.strict and level in (Level.MEDIUM, Level.HIGH):
            action = Action.BLOCK

        result.score = score
        result.level = level
        result.action = action
        result.findings = findings
        result.explained = explain(findings, score, level, short_id)
        if oversized_note:
            result.explained += oversized_note
        if result.skipped:
            result.explained += f"；因预算/短路未执行：{', '.join(result.skipped)}"
        if cold_notes:
            result.explained += "；含冷启动开销（不计入预算）：" + ", ".join(cold_notes)
        if fell_back:
            # 未知名静默降级会让安全配置形同虚设，必须说出来
            result.explained += f"；注意：策略 {policy_name} 不存在，已回退到 {policy.name}"
        result.latency_ms["total"] = (time.perf_counter() - started) * 1000.0

        # 自进化：把确认的攻击写回记忆库，下次遇到相似措辞直接认出来
        mem = self.memory_detector
        learned_now = False
        if mem is not None and mem.enabled and mem.learn(text, result):
            result.explained += "；已写入向量记忆库"
            learned_now = True

        if self.audit is not None:
            self.audit.log_scan(result, text=text, user=user, source="pipeline")
            if learned_now and mem is not None:
                self.audit.log_memory(
                    action="auto-learn", fp=fingerprint(text), label=1,
                    source="pipeline", total=len(mem.store),
                )

        if self.config.enable_cache:
            self.guard.cache.put(cache_key, result)
        return result

    def scan_batch(self, texts: list[str], user: str = "default",
                   policy_name: str | None = None) -> list[ScanResult]:
        return [self.scan(t, user=user, policy_name=policy_name) for t in texts]


def create_pipeline(
    tiers: tuple[str, ...] = ("critical", "high", "medium"),
    rules_dir: str | None = None,
    config: PipelineConfig | None = None,
    policies: PolicyEngine | None = None,
    preprocessor: Preprocessor | None = None,
    guard: Guard | None = None,
    semantic: Detector | None = None,
    memory: Detector | None = None,
) -> Pipeline:
    """一行组装出默认流水线，CLI/SDK/服务共用同一套装配逻辑。"""
    cfg = config or PipelineConfig()
    rulebook = RuleBook(rules_dir, tiers) if rules_dir else RuleBook(tiers=tiers)
    if semantic is None:
        # 关闭时显式用 null 后端，避免白占一个模型句柄
        semantic = SemanticDetector(
            mode=cfg.semantic_mode,
            enabled=cfg.semantic_enabled,
            model_name=cfg.semantic_model,
            backend=cfg.semantic_backend if cfg.semantic_enabled else "null",
            timeout_s=cfg.semantic_timeout_s,
        )
    if memory is None:
        # 复用 L3 已加载的模型句柄：让记忆库自己 build_encoder("auto") 会再
        # 加载一份 700MB 权重，而且 Pipeline.warmup() 只预热得到语义层那一份，
        # 记忆层的冷启动照样落在首个真实请求上
        shared_backend = getattr(semantic, "backend", None)
        if not hasattr(shared_backend, "encode"):
            shared_backend = None
        memory_kwargs = dict(
            encoder_kind=cfg.memory_encoder,
            backend=shared_backend,
            threshold=cfg.memory_threshold,
            auto_learn=cfg.memory_auto_learn,
            enabled=cfg.memory_enabled,
        )
        memory = MemoryDetector(**memory_kwargs)
        if cfg.memory_enabled and cfg.memory_dir:
            from pathlib import Path

            if Path(cfg.memory_dir).exists():
                # 从磁盘恢复时必须把配置项一起带上，否则 --memory-threshold /
                # --memory-auto-learn 会被静默忽略，命令行看起来生效了实际没有
                memory = MemoryDetector.load(cfg.memory_dir, **memory_kwargs)

    detectors = [
        RuleDetector(rules=rulebook, tiers=tuple(tiers)),
        HeuristicDetector(),
        semantic,
    ]
    if cfg.memory_enabled:
        detectors.append(memory)
    registry = DetectorRegistry(detectors=detectors)
    return Pipeline(
        preprocessor=preprocessor,
        registry=registry,
        guard=guard,
        policies=policies,
        config=cfg,
    )
