"""流水线编排：层串联、短路、超时、缓存。"""
from __future__ import annotations

import copy
import time
from dataclasses import dataclass

from prompt_ids.audit.logger import AuditLogger
from prompt_ids.core.policy import PolicyEngine
from prompt_ids.core.types import Action, Finding, Level, ScanResult
from prompt_ids.core.verdict import FusionConfig, decide, explain, fuse, grade
from prompt_ids.detectors import (
    DetectorContext,
    DetectorRegistry,
    HeuristicDetector,
    RuleDetector,
    SemanticDetector,
)
from prompt_ids.detectors.base import Detector
from prompt_ids.memory.detector import MemoryDetector
from prompt_ids.preprocess import Preprocessor
from prompt_ids.preprocess.guard import Guard, GuardConfig, LengthRejected, fingerprint
from prompt_ids.rules.loader import RuleBook

# 冷启动超过这个量级才值得在说明里点出来（规则/启发层只有几毫秒，报了是噪音）
COLD_START_REPORT_MS = 100.0


def _top_pattern(result) -> str:
    """权重×置信度最高的命中规则。反哺统计按这个口径归因。"""
    findings = getattr(result, "findings", None) or []
    if not findings:
        return ""
    return max(findings, key=lambda f: f.weight * f.confidence).pattern_id


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
    #: LLM 回退链：逗号分隔的 provider/model，主端点失败时顺次尝试
    semantic_fallbacks: str = ""
    #: True 时忽略所有云端 Key，强制本地推理（断网/离线演示用）
    semantic_local_only: bool = False
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
        # 遥测开关在**构造期**读一次并缓存：scan 是热路径，不能每次查 env。
        # 默认 off ⇒ 每次扫描的代价就是读一个 bool。
        from prompt_ids.observability import exporter

        self.telemetry_enabled = exporter().enabled()

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
            except Exception:  # noqa: BLE001
                # 预加载失败不回滚：运行期各层会自行降级，主链路不能因为
                # 一个可选依赖装不上就起不来
                continue
            cost = (time.perf_counter() - started) * 1000.0
            self._warm.add(detector.name)
            self.cold_start_ms[detector.name] = round(
                self.cold_start_ms.get(detector.name, 0.0) + cost, 3
            )

    def close(self) -> None:
        """释放各层持有的外部资源（模型句柄、记忆库文件等），供服务退出时调用。

        关停路径与启动路径同理：不能因为某个可选层释放失败就把其它层漏掉，
        更不能把异常抛给调用方的 finally 块。
        """
        for detector in self.registry:
            closer = getattr(detector, "close", None)
            if not callable(closer):
                continue
            try:
                closer()
            except Exception:  # noqa: BLE001 - 关停尽力而为，不掩盖真实退出
                continue

    def review(self, text: str, *, is_attack: bool, reviewer: str = "",
               note: str = "") -> dict:
        """人工复核：给一条检测定性，并把结论喂回记忆层。

        这是「检测 → 复核 → 学习」闭环的落点。三个设计点：

        - **记忆层可选**：没开 `--memory`（或没装 faiss）时复核照样能用，
          只是结论不影响后续判定，返回 `memory_reason="memory_disabled"` 而不是报错。
        - **标记误报 = 负向记忆**：走 `feedback(is_attack=False)`，与 L4 既有的
          双向记忆是同一条通路，不为复核另造一套写入逻辑。
        - **这里能拿到原文，是因为调用方手里就有**（REST 请求体 / 控制台输入）。
          审计侧仍然只记指纹 —— 见 `audit.event_from_review` 的说明。
        """
        text = (text or "").strip()
        if not text:
            raise ValueError("复核需要非空文本")
        result = self.scan(text, user=reviewer or "reviewer")
        detector = self.memory_detector
        absorbed, reason = False, "memory_disabled"
        if detector is not None and getattr(detector, "enabled", False):
            # 记下计数器增量再调用：learn() 返回 False 有多种原因（指纹重复、
            # 容量满、编码器不可用…），混成一句「rejected」会让运维无法判断
            # 是「这条已经在库里」还是「库满了」，这两种要采取的动作完全不同。
            before = (detector.deduped, detector.rejected, detector.learned)
            absorbed = detector.feedback(
                text, is_attack=is_attack, note=note or "manual review")
            after = (detector.deduped, detector.rejected, detector.learned)
            if absorbed:
                reason = "absorbed"
            elif after[0] > before[0]:
                reason = "duplicate_fingerprint"
            elif after[1] > before[1]:
                reason = "rejected_by_gate_or_capacity"
            elif after[2] == before[2]:
                reason = "encoder_unavailable"
            else:  # pragma: no cover - 计数器没动但也没成功，属于不该出现的情况
                reason = "unknown"
        return {
            "verdict": "attack" if is_attack else "false_positive",
            "level": result.level.value,
            "action": result.action.value,
            "score": result.score,
            "fingerprint": result.fingerprint,
            # 归因：这条结论是**哪些规则**判出来的。反哺规则的第一步就是它 ——
            # 没有它，「PV-C001 误报率多高」这种问题根本无法回答，只能靠猜。
            "patterns": [f.pattern_id for f in result.findings],
            "top_pattern": _top_pattern(result),
            "memory_absorbed": absorbed,
            "memory_reason": reason,
        }

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

    def scan(self, text: str, user: str = "default", policy_name: str | None = None,
             *, semantic: bool | None = None) -> ScanResult:
        started = time.perf_counter()
        if text is None:
            text = ""
        text = str(text)
        policy, fell_back = self.policies.resolve(policy_name or self.config.policy)

        result = ScanResult()
        # 限流（默认关闭：GuardConfig.rate_limit=0）。开着时按 user 分桶，
        # 超限**不阻断**而是转人工 —— 限流的语义是「别让一个人吃掉全部算力」，
        # 不是「判定为攻击」，所以动作是 review + 说明里写明原因。
        if not self.guard.check_rate(user):
            result.level = Level.MEDIUM
            result.action = Action.REVIEW
            result.explained = (f"超过限流（{self.guard.config.rate_limit} 次/"
                                f"{self.guard.config.rate_window_s:.0f}s），本条未做检测")
            result.latency_ms["guard"] = (time.perf_counter() - started) * 1000.0
            return result
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
        cold_used_ms = 0.0
        detectors = [d for d in self.registry if d.enabled]
        for index, detector in enumerate(detectors):
            # 预筛门禁：L3 是否调用由前置层的初判分决定
            # 「这次别用语义层」这道门按 **layer == 3** 判，不按 isinstance：
            # 「第 3 层是语义层」是结构约定，写死具体类会让任何别的 L3 实现
            # （含测试替身）绕过它。
            # 但下面的预筛/预算门**仍然**只对真正的 SemanticDetector 生效 ——
            # 那两道门要读 should_invoke()，别把它顺手扩成所有 layer 3 的检测器
            # （扩过一次，直接弄挂了 test_warmup_survives_broken_backend 的替身）。
            if getattr(detector, "layer", 0) == 3 and semantic is False:
                # 调用方显式要求跳过 L3。目前只有代理的 system/developer 段在用它：
                # 那类消息是**应用自己写的**，而 DeBERTa / LLM 裁判把「对助手的祈使句」
                # 判成注入 —— system 提示按定义就是对助手的祈使句，于是每个 RAG 请求
                # 都会被自己的系统提示拦下（实测良性 RAG 请求 block 率 0.5278 → 0.0833）。
                # 规则层照跑，经典系统提示窃取照样抓得到。
                skipped.append(detector.name)
                continue
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
                cold_used_ms += used
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

        # 遥测（默认 off，未启用时只是几次字典查表）。
        # ⚠ 属性走白名单，**原文绝不出去** —— 与审计层「只落指纹」同一条边界，
        # 但遥测会被送到第三方并长期留存，比审计层更敏感。见 prompt_ids/observability.py。
        if self.telemetry_enabled:
            from prompt_ids.observability import emit_scan

            semantic_stats: dict = {}
            detector_sem = self.semantic_detector
            if detector_sem is not None and getattr(detector_sem, "enabled", False):
                try:
                    semantic_stats = detector_sem.stats()
                except Exception:  # noqa: BLE001 - 统计读不出来不该让检测失败
                    semantic_stats = {}
            emit_scan(result=result, user=user, policy=policy.name,
                      text_chars=len(text), cold_start_ms=cold_used_ms,
                      semantic=semantic_stats or None)
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
        backend_spec = cfg.semantic_backend if cfg.semantic_enabled else "null"
        backend_kwargs: dict = {}
        if cfg.semantic_fallbacks:
            backend_kwargs["fallbacks"] = cfg.semantic_fallbacks
        if cfg.semantic_local_only:
            # 离线/演示模式：直接挑一个免 Key 的本地端点，绕开云端选型
            from prompt_ids.detectors.semantic.providers import local_candidates

            locals_ = local_candidates()
            if locals_ and backend_spec in ("", "auto", "llm"):
                backend_spec = locals_[0]
            backend_kwargs["allow_fallbacks"] = False
        semantic = SemanticDetector(
            mode=cfg.semantic_mode,
            enabled=cfg.semantic_enabled,
            model_name=cfg.semantic_model,
            backend=backend_spec,
            timeout_s=cfg.semantic_timeout_s,
            backend_kwargs=backend_kwargs,
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
