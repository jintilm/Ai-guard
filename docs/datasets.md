# Contextual RAG dataset / 上下文 RAG 数据集

[中文说明](#中文说明) · [English](#english)

## 中文说明

`rag-context-v1` 新增 **1,511 条场景**，用于检验长文档中的间接注入与误报。
真实背景来自 Kubernetes 官方中英文文档；攻击和引用攻击样例的对照由本项目编写。
这是一套**真实文档背景上的合成压力评测集**，不代表生产流量，也不代表独立人工标注结果。

| 项目 | 数量 / 定义 |
|---|---|
| 原始文档 | 48 篇，24 个主题，每个主题包含英文和中文版本 |
| 独立分组 | 24 个 `group_id`；同主题、翻译、攻击模板及其变体保持在同一侧 |
| 开发集 | 1,016 条 / 16 组 |
| 冻结测试集 | 495 条 / 8 组；生成方案在检测前固定 |
| 攻击 | 690 条，针对读取文档的助手发出越权或任务替换指令 |
| 正常对照 | 690 条明确引用攻击样例的安全培训内容，131 条原始正常文档 |
| 语言 | 英文 814 条，中文 697 条；其中两组有意使用中英混写 |
| 长度 | 上限 3,000 / 12,000 / 30,000 字符；原文不足时按实际长度，不重复填充 |
| 插入位置 | 头、中、尾、随机位置，以及三窗采样的间隙和边界 |

较短中文文档使两种语言的变体数不同；不要把每行视作独立样本。
这批数据只覆盖一个来源、一个技术领域，尚不能证明跨来源泛化。
24 个双语攻击模板经过 AI 辅助语义检查，派生行经过程序完整性校验；
`human_reviewed=false`，没有声称独立人工逐条复核。

### 数据与来源

- [压缩 JSONL](../data/rag_bench.jsonl.gz)：用 gzip 减少重复文档占用，解压后每行一个场景。
- [数据清单](../data/rag_bench.manifest.json)：数量、输入文件指纹、数据 SHA-256、去重与切分校验。
- [主题与切分](../data/rag_context/catalog.json)、[攻击模板](../data/rag_context/payloads.json)。
- [来源清单](../data/rag_context/sources.json)：每份文件的固定提交 URL、Git blob、SHA-256。
- [第三方许可](../THIRD_PARTY_DATA.md)：Kubernetes 文档 CC-BY-4.0；插入模板 MIT。

来源固定在 `kubernetes/website@542bad2ab92dd6ee7916b2b916d84cda64c77f6c`。
原始 Markdown 和许可保存在 `data/raw/rag_context/`，可离线重建。
转换保留术语标签显示的词语，移除 Hugo 元信息、其余模板标签和 HTML 注释；中文页面注释中的英文原文也移除，
保留正文与代码。随后取前缀片段并插入载荷或明确标注的攻击引用。
网址与收集端点使用 `example.invalid`，不包含真实私有对话或凭据。

每条记录保留 `text`、`label`、`source`、`category`，并增加：

| 字段 | 用途 |
|---|---|
| `id` / `group_id` / `document_id` / `template_id` | 区分派生行、母组、原文和双语模板 |
| `split` / `language` / `kind` | 切分、语言，以及攻击/原文/引用对照 |
| `context` | 用户的只读解释任务、`tool` 角色、来源不可信的边界、预期行为 |
| `inserted_span` / `position` / `pair_id` | 原始文本中的插入区间和对应对照；坐标不是归一化后的模型坐标 |
| `text_sha256` / `provenance` | 内容指纹、来源、许可、转换方式、复核状态 |

当前生产检测器只接收文档文本，**尚未将 `context.user_task` 作为独立可信上下文传入裁判**。
评测报告明确写出 `context_supplied_to_detector=false`，避免把有上下文标注等同于具备上下文判断能力。

### 复现

从项目根目录运行，默认构建不联网、规则基线不调用 LLM：

```bash
python -X utf8 scripts/build_rag_bench.py
python -X utf8 scripts/build_rag_bench.py --check
python -X utf8 scripts/eval_rag_bench.py --mode rules --split dev
python -X utf8 scripts/eval_rag_bench.py --mode rules --split test
```

需要重新下载固定来源时显式增加 `--download`。构建会校验源文件和清单，拒绝重复文本、
跨切分的文档/模板/母组、不完整的攻击对照配对以及错误区间。
父文档还进行 NFKC 归一化后的字符 24-shingle Jaccard 近重复检查；
这不是语义去重，不能证明所有改写都独立。
`--check` 不写文件，核对重建内容与已保存清单，已加入 Windows/Ubuntu CI。
`.gitattributes` 保留原始来源字节和清单换行，避免 Windows 自动换行破坏指纹。

正式比较 `head` 与 `stratified` 时显式选择 LLM 模式并给出调用上限：

```bash
python -X utf8 scripts/eval_rag_bench.py --mode llm --split dev --sample 120 --plan-only --out reports/rag_balanced_plan.json
python -X utf8 scripts/eval_rag_bench.py --mode llm --split dev --sample 120 --max-llm-calls 240 --timeout 45 --out reports/rag_llm_current_balanced.json
```

小样本默认采用 `balanced-language-label-v1`：先给中英文分配相同配额，再平衡攻击/良性，
最后平分良性原文/引用对照；格内优先分散母组，再分散插入位置和长度。
120 条的构成为：每种语言 30 条攻击、15 条正常原文、15 条引用对照，覆盖 16 个开发母组。
这是有意定义的诊断分布，不代表生产或全量语料的类别占比。
`--sample 0` 仍表示完整切分；配额所需样本不足会明确报错。

此前的小样本使用细粒度比例分层，24 条样本的余数平局按名称排序，形成 22 英文/2 中文。
新方法以固定种子的 ID 指纹打破平局，测量证据见 [抽样对比](../reports/rag_sampling.json)：
24 条现在为中英文各 12，120 条为各 60；输入行倒序也得到相同样本。
旧试跑可用 `--sampling legacy` 重现；其抽样方案与新方法的数字不宜直接相减。
离线重跑 `python -X utf8 scripts/rag_sampling_check.py` 可检查配额与来源顺序独立性，已接入 CI。

模型和端点沿用 `.env`，也可用 `--provider` 和 `--model` 显式选择。
两种策略使用相同样本、交错执行，并交替先后顺序。规则和融合使用生产实现；
语义为 `always`，关闭 critical 短路和最终结果缓存，明确标为消融口径。
成功的裁判判决缓存在被 Git 忽略的 `logs/rag_eval_cache/`，失败不缓存。
重试与备用端点关闭；JSON 格式回退仍可能让一次逻辑调用产生两次 HTTP 请求。
连续三对全部失败即停止；调用失败率超过 20% 或未完成时，报告标记不可比较。

### 指标与使用边界

报告分别给出 `level >= high` 风险检出、`action == block` 实际阻断、
良性 `>= medium` 标记率、`review` 动作率、失败率和未命中缓存的耗时。
按语言、长度、位置、场景类别与分组拆分；置信区间通过重采样 `group_id` 计算，
不是把 1,511 条变体当作 1,511 个独立观察。
报告还列出按语言、场景与母组的失败分布，以及“两组均拿到判决”的配对子集统计；
后者是条件分析，不代表删除失败后就消除了偏差。
字符预算不能换算成准确 token 费用，当前报告的 `token_usage=null`。

采样覆盖统计是**原始文本上的载荷可见性**。它与模型实际判决、代理完整执行链、
攻击成功率是不同指标；规则基线不能证明两种 LLM 采样策略谁更准确。
旧网关的 [首次试跑](../reports/rag_llm_pilot.json) 返回 HTTP 404，保留为不可比较的历史记录。
新网关上的 [DeepSeek-V4.1-Flash 试跑](../reports/rag_llm_deepseek_pilot.json) 已完成：

| 指标 | `head` | `stratified` |
|---|---:|---:|
| 风险检出 / 实际阻断召回 | 9/12 = 75% | 9/12 = 75% |
| 正常样本阻断（包含降级路径） | 3/12 = 25% | 2/12 = 16.67% |
| 未取得裁判判决 | 3/24 = 12.5% | 3/24 = 12.5% |
| 成功判决的正常样本阻断 | 3/9 = 33.33% | 2/9 = 22.22% |

这是 24 条开发样本、14 个母组的配对试跑，其中英文 22 条、中文仅 2 条，
不能据此评价中文效果。样本中 12 条攻击、10 条攻击引用对照、2 条原始正常文档。
两组失败均来自同一篇文档的三个良性引用变体，网关返回 **HTTP 406 + HTML**，
因此失败并非随机缺失；生产管线在这些样本上按语义弃票处理。
对成功判决的子集单独统计也会改变人群，不能把它当成无偏修正。
该网关不支持模型列表查询，需指定模型名直接调用；模型可用性以
`POST /v1/chat/completions` 返回有效判决为准。列表请求曾返回 HTTP 502，
这不能作为模型不可用的依据，也不计入上述裁判调用失败率。

最终报告复用了每组 21 条成功预测，只补跑每组 3 条失败样本；
`model_calls_this_run` 不包含先前缓存的请求，`uncached_latency_ms` 也仅描述本次未命中缓存的调用。
按母组配对的风险召回差为 0，95% bootstrap 区间为 [-0.15, 0.15]。
这些证据不足以支持调整默认 `head` 策略，后续应先解决网关内容拒绝和小样本语言偏斜。

### 120 条平衡开发集评测

使用调用前固定的 [样本计划](../reports/rag_balanced_plan.json)，
[纯规则基线](../reports/rag_rules_balanced.json)与
[DeepSeek-V4.1-Flash 配对报告](../reports/rag_llm_deepseek_balanced.json)覆盖完全相同的 120 条。
LLM 每组实际预测 120 次，均无缓存命中；语义 `always`，关闭 critical 短路，默认 policy。

| 指标 | L1+L2 | +LLM `head` | +LLM `stratified` |
|---|---:|---:|---:|
| 风险召回（≥high） | 13/60 = 21.67% | 35/60 = 58.33% | 43/60 = 71.67% |
| 实际阻断召回 | 12/60 = 20.00% | 35/60 = 58.33% | 43/60 = 71.67% |
| 正常样本阻断 | 20/60 = 33.33% | 22/60 = 36.67% | 27/60 = 45.00% |
| 原文对照阻断 | 2/30 = 6.67% | 2/30 = 6.67% | 2/30 = 6.67% |
| 攻击引用对照阻断 | 18/30 = 60.00% | 20/30 = 66.67% | 25/30 = 83.33% |
| 无有效语义判决 | — | 17/120 = 14.17% | 18/120 = 15.00% |
| 平均扫描耗时 | 见规则报告 | 3.59 秒 | 4.33 秒 |

分窗多检出 8 条攻击，也多阻断 5 条引用对照。按母组配对的风险召回差为 +0.1458，
95% bootstrap 区间 [0.0573, 0.2448]；这是组宏平均，和表中按行计算的差值口径不同。
两组都取得判决的条件子集只有 90 条（48 攻击/42 良性）：风险召回 32/48 对 37/48，
良性阻断 15/42 对 18/42。条件子集仍显示同方向取舍，但删除失败改变了人群，不能外推。

`head` 的 17 次失败为 HTTP 403 ×9、406 ×8；分窗为 403 ×9、406 ×8、其他后端失败 ×1。
两组失败集合并不相同，报告包含按语言、场景及母组的失败分布。
[11 次直接请求对照](../reports/rag_gateway_diagnostic.json)将已知 406 定位到正常文档中的
85 字符 shell 示例：片段本身、包含它的正常原文与引用对照均 406，前后正文、引用段本身、
同长度普通文本均可用；更改 JSON 模式与 Accept 头未解决。具体拒绝规则需网关端确认。
403 的根因未由该对照确定，不与 406 混为同一种问题。

即使裁判给出低于 0.5 的注入概率，仍有 `head` 10 条、分窗 7 条良性样本被融合结果阻断。
这说明后续需要同时检查规则证据与裁判判断。尤其中文引用说明涉及的 `PV-C008` 应在开发集
定位，而不是仅靠改变取样策略处理误报。本轮未调规则、融合阈值或默认采样方式。
这批数据仍是单一领域、AI 辅助标注的压力场景；结果不是总体业务误报率。
报告保留测量时的代码指纹。后续 Windows CI 暴露了 0.1 秒 socket 预算的浮点边界，
已改为绝对截止时间比较并补回归；本轮评测使用 45 秒预算、未重跑，其指纹对应修复前版本。

初次全量规则基线（L1+L2，默认 policy，关闭 critical 短路）记录在
[rag_rules.json](../reports/rag_rules.json)。测试集的风险召回为 **48/226 = 21.24%**，
实际阻断召回 **20/226 = 8.85%**。全量正常原文阻断 **9/131 = 6.87%**；
困难的攻击引用对照阻断 **378/690 = 54.78%**。后两项包含开发与测试数据，
均为特定场景的变体级观察，不能外推成日常流量误报率。
配对对照含有重复的引用说明，因此可能同时暴露该说明模板引发的规则误报；
需在开发集定位，不能把这些数字解释成 690 个独立业务样本。

冻结测试集及其正常样本均不得用于改规则或调阈值；若用于改进，就必须重新归入开发数据，
另建最终测试集。扩展时先增加新来源、新领域和独立母组，再生成变体。
建议下一批加入非 Kubernetes 的业务文档、独立人工复核与完整 Agent 工具轨迹。

## English

`rag-context-v1` contains **1,511 contextual scenarios** built from 48 public Kubernetes
documents covering 24 topics in English and Chinese. Inserted attacks and clearly quoted
attack examples are synthetic. This is a stress corpus with authentic document backgrounds,
not a production traffic sample or an independently human-adjudicated benchmark.

There are **690 attacks, 690 benign quotation controls, and 131 clean excerpts**.
The development split has **1,016 rows / 16 parent groups**; the frozen test split has
**495 rows / 8 groups**. Translations, bilingual attack templates, length variants and
placements stay with their parent group. English has 814 rows and Chinese 697 because
source lengths differ. Length caps are 3k, 12k and 30k characters; shorter sources retain
their actual length, without repetition. Placements cover head, middle, tail, seeded random
positions, and the gaps/boundaries of three-window sampling.

The [manifest](../data/rag_bench.manifest.json), [source records](../data/rag_context/sources.json),
[catalog](../data/rag_context/catalog.json), and [payload templates](../data/rag_context/payloads.json)
provide provenance and reconstruction inputs. Original files and CC-BY-4.0 license are retained
under `data/raw/rag_context/`. Sources are pinned to Kubernetes website commit
`542bad2ab92dd6ee7916b2b916d84cda64c77f6c`. Hugo metadata, shortcodes and HTML comments
(including English originals in Chinese translation files) are removed before excerpting.
Payloads are MIT-licensed; derived documents retain source obligations. See
[third-party attribution](../THIRD_PARTY_DATA.md).

Run the commands above from the project root. Construction is offline by default;
`--download` explicitly fetches the pinned sources. It validates checksums, normalized-text
uniqueness, group/document/template isolation, insertion spans and attack/control pairs.
Parent documents undergo a character 24-shingle Jaccard near-duplicate check after NFKC
normalization. This detects lexical overlap, not all semantic paraphrases.
Glossary shortcode display text is retained so extraction does not drop nouns.

Each row includes the user task, untrusted `tool` role, expected behavior, document identity,
split, insertion coordinates, hashes and license. **The production detector currently receives
only document text**; context defines labels but is not supplied as a separate trusted judge
input. Reports record `context_supplied_to_detector=false`. Template review is AI-assisted;
`human_reviewed=false` makes the absence of independent human review explicit.

The default evaluator runs the actual L1/L2 pipeline and separately measures raw-document
payload visibility. Explicit `--mode llm` compares `head` and `stratified` on the same sample,
interleaving calls and alternating order. It uses production rules/fusion with an `always`
judge, disabling critical short-circuiting and final-result caching for the ablation.
Successful judge predictions are persisted in ignored `logs/rag_eval_cache/`; failures
are never cached. Explicit call limits are required. Retries/fallback endpoints are disabled,
although JSON-mode fallback may use two HTTP requests per logical prediction.

Small samples now use `balanced-language-label-v1`: equal language quotas, then equal
attack/benign quotas, then equal clean/quotation controls. Within each quota, sampling
spreads parent groups before placement and length. A 120-case pilot has 60 cases per
language (30 attacks, 15 clean, 15 quotation controls), covering all 16 development groups.
This defines a diagnostic population, not corpus or production prevalence. `--sample 0`
still selects the entire split. Insufficient quota capacity raises an explicit error.
`--plan-only` writes the exact sample before any model calls.

The former fine-grained proportional sampler resolved remainder ties lexicographically,
yielding 22 English cases and two Chinese cases in the 24-case pilot. Stable seeded ID
hashes now resolve ties independently of input order. The [sampling measurement](../reports/rag_sampling.json)
records 12/12 at n=24 and 60/60 at n=120, including reversed-input reconstruction.
Use `--sampling legacy` only to reproduce old pilots. The offline measurement script
`scripts/rag_sampling_check.py` is included in CI. Reports expose failures by language,
kind and group, plus statistics conditional on both judges returning valid verdicts;
that conditional subset is not an unbiased correction for missing results.

Reports distinguish risk detection (`level >= high`), blocking (`action == block`), benign
flagging (`>= medium`), review actions, failed calls and uncached latency. Confidence
intervals resample **parent groups**, not derived rows. Character counts are not tokens;
provider token usage is not collected. Incomplete runs or failure rates above 20% invalidate
strategy comparison. Three consecutive pairs without any valid verdict stop the run.
The [original pilot](../reports/rag_llm_pilot.json) received HTTP 404 responses and remains
an unusable historical record. The new [DeepSeek-V4.1-Flash pilot](../reports/rag_llm_deepseek_pilot.json)
completed on 24 development cases from 14 parent groups (22 English, two Chinese;
12 attacks, ten quotation controls, two clean excerpts). Both strategies detected and
blocked 9/12 attacks. Benign blocking, including semantic-abstention paths, was 3/12 for
`head` and 2/12 for `stratified`.

Each strategy failed on the same three benign quotation variants with **HTTP 406 and HTML**,
a 12.5% abstention rate. Among successful verdicts, benign blocking was 3/9 and 2/9;
this subset changes the population and is not an unbiased correction. This gateway does
not support model listing: specify the model and call `POST /v1/chat/completions` directly.
Availability is established by valid classification responses. The HTTP 502 observed on
the unsupported listing endpoint does not establish model unavailability and is excluded
from the classification failure rate above.
The final report reused 21 successful predictions per strategy and retried three failures
per strategy. `model_calls_this_run` excludes earlier cached calls, and uncached latency
describes only requests made during that resumed run. The paired group-macro recall
difference is zero (95% bootstrap interval [-0.15, 0.15]). These limited, language-skewed
observations do not justify changing the default `head` strategy.

### Balanced 120-case development evaluation

The [frozen sample plan](../reports/rag_balanced_plan.json),
[rules baseline](../reports/rag_rules_balanced.json), and
[DeepSeek comparison](../reports/rag_llm_deepseek_balanced.json) use identical cases.
Each strategy made 120 predictions with zero cache hits, an `always` judge, no critical
short-circuiting and the default policy.

| Metric | L1/L2 | +LLM `head` | +LLM `stratified` |
|---|---:|---:|---:|
| Risk recall (≥high) | 13/60 = 21.67% | 35/60 = 58.33% | 43/60 = 71.67% |
| Block recall | 12/60 = 20.00% | 35/60 = 58.33% | 43/60 = 71.67% |
| Benign blocking | 20/60 = 33.33% | 22/60 = 36.67% | 27/60 = 45.00% |
| Clean excerpt blocking | 2/30 | 2/30 | 2/30 |
| Quotation control blocking | 18/30 | 20/30 | 25/30 |
| Missing semantic verdicts | — | 17/120 = 14.17% | 18/120 = 15.00% |
| Mean scan latency | See baseline | 3.59 s | 4.33 s |

Distributed windows detected eight additional attacks and blocked five additional benign
quotation controls. The paired group-macro risk recall difference is +0.1458 (95% bootstrap
interval [0.0573, 0.2448]); it uses a different aggregation from the row-level table.
Both strategies succeeded on only 90 paired cases: recall 32/48 versus 37/48, benign blocking
15/42 versus 18/42. This conditional subset changes the population and is not an unbiased correction.

Failures were nine HTTP 403 and eight HTTP 406 for `head`; the same counts plus one other
backend failure for distributed windows. Their failed case sets differ. Eleven direct-request
[diagnostic controls](../reports/rag_gateway_diagnostic.json) localized a known 406 to an
85-character shell example in benign documentation. The example alone and documents containing
it were rejected; surrounding prose, the quotation alone and equal-length neutral text worked.
Changing JSON-mode or Accept did not resolve it. The exact gateway rule needs server-side
confirmation; this experiment does not establish the cause of the separate 403 responses.

Despite a semantic probability below 0.5, ten benign `head` cases and seven distributed-window
cases were still blocked by the fused decision. Follow-up work should examine both rule evidence
and judge decisions, especially `PV-C008` on Chinese quotation framing, using development data.
Rules, fusion thresholds and the default sampling strategy were not changed. This single-domain,
AI-assisted stress corpus does not estimate production FPR.
Reports retain the code fingerprints used during measurement. A subsequent Windows CI
failure exposed floating-point rounding at a 0.1-second socket budget; absolute-deadline
comparison and regression coverage fix that boundary. This 45-second-budget evaluation
was not rerun, and its fingerprint identifies the version before that fix.

The initial [L1/L2 baseline](../reports/rag_rules.json) measures test risk recall at
48/226 (21.24%) and actual block recall at 20/226 (8.85%). Across both splits, clean
documents were blocked in 9/131 cases (6.87%); quotation controls in 378/690 (54.78%).
These are variant-level observations in selected difficult scenarios, not production FPR.
Quotation controls share explanatory framing that may itself trigger rules; investigate
that effect using development cases rather than treating all variants as independent.
The offline `--check` reconstruction command is included in Windows/Ubuntu CI; Git
attributes preserve original source bytes and manifest line endings.

Do not use the frozen test split, including its benign cases, for tuning. Reclassify any
such data as development data and replace the final holdout. This corpus covers one domain
and one source; its row count must not be presented as independent generalization evidence.
Further expansion should prioritize new domains, human adjudication and complete agent/tool
trajectories. Visibility, detector recall and end-to-end attack success remain separate metrics.
