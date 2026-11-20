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
python -X utf8 scripts/eval_rag_bench.py --mode llm --split dev --sample 24 --max-llm-calls 48 --timeout 45 --out reports/rag_llm_pilot.json
```

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
字符预算不能换算成准确 token 费用，当前报告的 `token_usage=null`。

采样覆盖统计是**原始文本上的载荷可见性**。它与模型实际判决、代理完整执行链、
攻击成功率是不同指标；规则基线不能证明两种 LLM 采样策略谁更准确。
本轮 LLM 小样本试跑中网关返回 HTTP 404，报告保留失败记录并标记不可比较；
默认 `head` 策略因此没有调整。

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

Reports distinguish risk detection (`level >= high`), blocking (`action == block`), benign
flagging (`>= medium`), review actions, failed calls and uncached latency. Confidence
intervals resample **parent groups**, not derived rows. Character counts are not tokens;
provider token usage is not collected. Incomplete runs or failure rates above 20% invalidate
strategy comparison. Three consecutive pairs without any valid verdict stop the run.
The initial LLM pilot received HTTP 404 responses and is marked unusable; the default
sampling strategy remains `head`.

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
