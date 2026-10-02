# AGENTS.md · prompt-ids（提示词注入检测系统）

**先读 `.workbuddy/memory/MEMORY.md`**：跨会话不变量、基线数字、17 条已修缺陷、待办都在那里；
每日过程细节在同目录 `2026-09-2*.md`。本文件只记「不读记忆就会踩」的坑，已于 2026-10 核对代码核实。

## 运行（本机现状）

- **包未安装**（仓库 98 个 tracked 文件，三个 console script 都不存在）⇒ `prompt-ids` /
  `prompt-ids-api` / `prompt-ids-proxy` 命令**不可用**。一律模块形式、从项目根跑：
  `python -m prompt_ids.cli` / `.proxy` / `.api` / `.web` / `.audit`。
  默认端口：api 8790 · proxy 8787 · `web --serve` 8765（看板产物 `reports/dashboard.html`）。
- 已装：regex 2026.5.9（规则引擎实测走 regex）· torch 2.12.0+cpu · transformers · sklearn · numpy。
  **faiss 未装** ⇒ 记忆层自动退 numpy 暴力检索，这是预期状态不是 bug。
- Windows / PowerShell：先 `cd E:/Code/Ai-guard` 再跑；`scripts/` 内脚本自己 `sys.path.insert(项目根)`。
- `.env`（gitignored，用户唯一要动的文件）在 **import 期**被 `prompt_ids/env.py` 写进 `os.environ`
  ⇒ 改它会立刻改变运行时行为，且真实环境变量优先。

## 测试

- `python -m pytest -q`（项目根）收集 **728 项**（另 1 项在没跑 `--from-misses` 时 skip）。
  ⚠ 数用例用 `--collect-only -q`，别数「N passed」总结行。
  大头：test_providers 86 · test_core_units 42 ·
  test_proxy 42 · test_output_secrets 41 · test_semantic 35 · test_regressions 35 ·
  test_network_robustness 33 · test_audit 35 · test_review 32 · test_api 29 ·
  test_canary 24 · test_memory 27 · test_web 23 · test_pipeline 23 · test_verdict 19 ·
  test_passthrough_scan 16 · test_backend_auto 12 · test_playground 18 ·
  test_canary_issue_quota 9 · test_threshold_sweep 9 · test_concurrency 4 ·
  test_canary_cost 7 · test_cli_backend_announce 5 · test_agent_bench 10 ·
  test_rules_redos 9 · test_pint_shape 5 · test_preprocess 8 · test_engine 7 ·
  test_decoder 6。
- **已修的 flaky（2026-10）**：`test_rotation_keeps_old_token_valid` 原在本机约 2/3 概率失败。
  根因在实现而非测试：`CanaryRegistry.current` 取 `max(self._tokens.values(), key=issued_at)`，
  而本机 `time.time()` 分辨率只有 **15.625ms**（Windows `GetSystemTimeAsFileTime` 粗化）
  ⇒ 同一 tick 内连发 `issue()` + `rotate()` 时间戳相等，`max` 按字典顺序返回**旧**令牌
  （表现为「轮换静默失效」）。修法：给签发加单调递增序号当 `current` 的 tiebreaker
  （`_freshness()`），守护见 `test_canary_current_is_newest_even_within_one_clock_tick`。
  插 `sleep(20ms)` 只会把测试变绿、缺陷仍在。
- ~~**未能复现的偶发失败**（2026-10 记录，长期查不出触发条件）~~ **已定位并拆掉地雷**：
  那 3 条一起失败的用例（`test_cli_list_providers_columns_align` /
  `_covers_registry` / `test_cli_json_output_is_parseable`）报的是
  `TypeError: argument of type 'NoneType' is not iterable` 或
  `AttributeError: NoneType.splitlines` —— **报错完全指不到真正的原因**。
  根因：`_run_cli` 用 `text=True` 却**不钉 `encoding`**，解码跟随**本机代码页 cp936**；
  只要环境里出现 `PYTHONIOENCODING=utf-8`，子进程就按 UTF-8 写出、GBK 解码失败、
  `proc.stdout` 变 **None**（2026-10 显式复现：设了必挂、不设必过）。
  早先怀疑「某家 Key 恰好可用导致行结构变化」是**错的方向**。
  修法：子进程 env 钉 `PYTHONIOENCODING=utf-8` + 父进程 `encoding="utf-8", errors="replace"`，
  两处同款（`tests/test_review.py` 的 `review_mined.py` 子进程也是 `text=True` 不钉编码，
  中文输出同样会抛 `UnicodeDecodeError`）。守护
  `test_cli_subprocess_decodes_as_utf8_on_any_locale`（用 `ast` 剥掉 docstring 再断言，
  否则那段解释里出现的 `text=True` 字样会让断言自己绊倒）。
- `pyproject.toml` 的 `addopts="-q"` 再叠命令行 `-q` 会变 `-qq`，pytest **连 "N passed" 总结行
  一起吞掉** ⇒ 判全绿看退出码，别盯总结行；数用例用 `--collect-only -q`。
- **`python -X utf8 -m pytest` 现在可以用了**（上述编码地雷拆掉后实测 `-X utf8` 与
  不带、`PYTHONIOENCODING` 设与不设，四种组合 618 项全绿）。
  ⚠ 但**新写子进程测试仍要两端钉 UTF-8** —— `-X utf8` 只作用于父进程，
  子进程写什么编码取决于它自己的环境。
- 单点验证：`python -m pytest tests/test_regressions.py -q -k abstains`
  （即 `test_semantic_failed_call_abstains_instead_of_suppressing`，钉死「失败弃票」那条机制）。
- `tests/conftest.py::_hermetic_env`（session 级 autouse）测试开始前摘掉 LLM/规则引擎相关 env，
  锁是 `test_suite_is_hermetic_against_local_env`。变量名**从 provider 注册表现场推导**
  ⇒ 注册表之外新增的 env 变量不会被隔离，加这类变量时要自己保证测试不被本机状态污染。
- ⚠ **绝不拿 PowerShell 的文本管道改仓库里的 UTF-8 文件**（2026-10 踩过，代价很大）：
  `(Get-Content f -Raw) -replace ... | Set-Content f` 会按**本机代码页 cp936** 读 UTF-8，
  再写回时每个 3 字节汉字的尾字节被换成 `?`（实测 README 丢 1000 字节 / 1215 处，
  AGENTS.md 丢 1215 处**并且吃掉 299 个换行**），报错为零、文件仍是合法 UTF-8，
  `git status` 之外**没有任何信号**。AGENTS.md 未入库 ⇒ git 也救不回来。
  要改文件一律用 `edit`/`write` 工具，或 Python 显式 `encoding=`。
  附带的教训：**判断文件是否被弄坏，不能只看「能不能解码」** —— 损坏后的文件仍是合法 UTF-8。
  真正的判据是逐字节对不上，而这次是靠「与另一份独立副本逐段比长度」
  （15 段 +0、6 段差值恰好等于当轮编辑）才定位到的。
- `reports/*.json` 不是测试输入：`test_collect_reads_real_project_data` 是 skip-if-missing，
  `test_data_is_inlined` 用 conftest 里的合成报告。改报告口径不需要改测试。
- **`tests/` 在 .gitignore 里且未跟踪**（`.workbuddy/` 同理）⇒ 测试改动不出现在 `git status`、
  也不会被提交，要保留得 `git add -f tests/...`。

## 融合层不变量（最容易被「顺手改回去」的地方）

- 证据层 L1/L2：只做加法，`< config.abstain_below`（15）弃票；判别层 `verdict.DISCRIMINATORS`
  = `(semantic, memory)`：乘性 `×(1+(pooled/100-0.5)*0.5)`（p=0 → ×0.75，p=1 → ×1.25），
  最终 `max(adjusted, max(discriminators))`。
- 默认 `FusionConfig.strategy="evidence"`。**不要改回加权平均**：实测 L1+L2 召回 0.660 < L1 单干
  0.720（弱信号稀释强证据）。`weighted` 只作为论文对照组保留。
- `Prediction.ok=False` 的语义是「没拿到判决」（后端不可用/超时/网络/解析失败）。
  `SemanticDetector.contribution()` 见 `ok=False` **必须返回 None（弃票）**。
  不能改成 0.5 —— 0.5 会经 `max(adjusted, max(discriminators))` 把总分抬到 50 成为下限，凭空造误报；
  评测缓存（`CachedSemanticBackend`）也不得缓存 `ok=False`，否则失败会被永久固化。
- 缓存键含 policy / tiers / semantic / mem_version，且**必须在一次扫描内固定成一个变量**
  （get 在开头、put 在结尾，中途自进化抬高 version 会把失效机制架空）。
- 冷启动记入 `cold_start_ms`、**不累加** `elapsed_total`；记忆层与 L3 **共用同一 backend 句柄**
  （否则白吃一份 700MB 权重，且 `warmup()` 只预热到语义层那份）。
- 记忆层去重默认 `dedup_threshold=1.0`（规范指纹）。相似度线 0.97 落在攻击簇内部
  （簇内 cos 0.9993 > 攻击-正常间隔 0.0999）⇒ 会静默丢掉 4/5 条真攻击，且 `deduped` 悄悄上涨。
- 记忆层写入与检索必须走同一套归一化（`MemoryDetector._normalize`）：全角逗号被 NFKC 转半角后，
  DeBERTa 相似度从 0.99 掉到 0.57。

## 实验口径（不可违背）

0. **`deepset` 的 train/test 召回差（0.212 vs 0.100）已查清，不是「留出集更狠」**（2026-10）：
   把攻击样本按「是否含 ignore/forget 类指令覆盖措辞」切开 ——
   `deepset_train` 60/203 含（29.6%，该子集召回 **0.450**），其余 143 条合计只贡献 ~0.079；
   `deepset_test` 17/60 含（28.3%，该子集召回 **0.353**），其余 43 条合计贡献 **~0**。
   读法：**规则层的召回几乎全部来自「含指令覆盖措辞」的子集**；约 70% 的 deepset
   「攻击」是角色扮演 / 任务改写型（hijacking），对它们召回≈0 —— 与 agent 面
   那个 0.0000 是同一件事。差距只是两批样本里这类形态占比与措辞变体的细微差别。
   ⚠ **但按类型分层做不了**：`deepset/prompt-injections` 在 HF 上只导出 `text`+`label`
   两列（已核 `datasets-server` 的 features），上游仓库的三分类
   （prompt_injection / hijacking / over-defense）不在导出里 ⇒ 任何「按攻击类型」的
   结论都不能引用本项目的数字。
1. **结论以公开集为准**：自建 85 条种子集会严重高估（规则召回自建 0.72 vs deepset 留出集 0.100）。
2. 规则迭代只碰 `deepset_train`(546)；`deepset_test`(116) **全程不参与调参**（split 写在样本 `source` 字段）。
3. 补规则的漏检线索用 `scripts/miss_analysis.py` 取，不照抄测试集样本。
4. 改任何默认值（阈值 / 引擎 / 去重线）**先写可复跑测量脚本留证据**，负面结果也记档。
   已被实测否定、别再重试：融合成单个大正则（87ms vs 22.6ms，更慢）· 锚点预筛（无收益）·
   `sre_parse` 位置预筛（0.40×-0.57×）· 0.97 去重线。
5. **报告文件会悄悄过期**：换数据集 / 规则 / 后端后必须重跑，不能靠文件名判新旧。
   LLM 后端写 `reports/ablation_llm.json`，**不要覆盖 `ablation.json`**（那是 DeBERTa/默认基线）。
6. 衡量某层贡献要用**对该层敏感的指标**：`L1+L2 == L1` 在英语样本上同样成立（L2 单层翻不动判定阈），
   拿它当尺子会得出「L2 对德语零贡献」这种假结论。用 `scripts/heuristic_language.py`（HZ-001 命中率）。
7. **别用前 N 条估速率**（幸存者偏差）。LLM 端点实测 ≈19s/条、p90 ≈40s，
   817 条 × 多组 ≫ 3h，且会被会话重置杀后台任务 —— 靠落盘缓存续跑。
8. **读消融报告先看「调用失败率」那一列**（2026-10 踩过最贵的一次）：
   LLM 超时按**弃票**处理（`ok=False` → `contribution()` 返回 None），所以超时直接
   表现为「召回变低」。那次重跑里 `fallback 门禁` 组吃了 **87.2% 超时**（R=0.3305），
   紧邻的 `always` 组只有 10.5%（R=0.8091）—— 差 0.48 看着像门禁退化，
   其实是网关在那段时间不健康，而**先跑的那组把失败全吃下了**。
   用缓存重跑那一组后：`fallback` R=0.8091 / F1=0.8903，与 `always` **完全一致**
   ⇒ 门禁本身没问题，差的是网关。
   现在 `eval_semantic.py` 每组都输出 `reliability.failed_share`，>20%（`DEGRADED_CALL_FAIL_SHARE`）
   标 `⚠不可用`（控制台 `[done]` 行、markdown 表格、报告 JSON 三处都有）。
   **带这个标记的组，P/R/F1 不能引用，也不能与其他组相减。**

## 规则层

- **绝不写「多失败前瞻」式字符类合取**（O(L²)）。`squeezed` 预处理变体会把长英文压成一条巨大字母 run，
  于是任何正常长文本都能触发 = 远程可打 DoS（PV-M017 原为 3.7s，改为 37.9ms）。
  写法：线性候选正则 + `validate: <name>`（注册表在 `rules/validators.py`，**未知 validator 名要响亮失败**）；
  带 validator 的 `Rule.match` **必须 `finditer`** —— 最左候选可能不满足校验，用 `search` 会漏。
- YAML 正则用单引号包裹；内含单引号写两个单引号（`''`）。
- **否定前瞻 `(?!)` 的两个坑**（2026-10 收窄 PV-C020 时踩过，规则本身是对的但两次都没生效）：
  1. **开头必须写 `\s*`**。`(?!…(den|die)\s*entwurf)` 在 `vergiss den Entwurf` 上**不生效** ——
     前面的 `\s*` 会先把空格吃掉，回溯时前瞻看到的是 `" den Entwurf"`，文章在前、名词不在 ⇒ 通过。
     写成 `(?!\s*…)` 才对。
  2. **前瞻里不能用 `\b`**。`reglued` 预处理变体会删掉空格（`vergiss den Entwurf` →
     `VergissdenEntwurfvongestern`），此时 "Entwurf" 与 "von" 之间**没有词边界**，
     `entwurf\b` 匹配不上 ⇒ 前瞻放行 ⇒ 原文里已修好的误报在变体上复活。
     教训：**任何按内容写的规则都要在 `reglued` 变体上验一遍**，`scripts/miss_analysis.py`
     看不到这个（它只看原文命中）。
- PV-C020 收窄实录（`vergiss|ignorier…` + 任意对象 + `stattdessen`）：德语 hard negative
  「Vergiss den Entwurf von gestern und nimm stattdessen diese Version.」曾判 critical（block）。
  收窄成「排除文档类宾语」后：PINT train block FPR **0.0002 → 0.0000**（0/2200），
  留出集 R 0.6032 不变、FPR 0.0000，deepset 里 4 条德语真阳性（3 train + 1 test）全部保留。
  **用否定式而不是「宾语必须是指令名词」**：后者会顺手削掉
  "Ignorieren Sie die obigen **Angaben**…"（对象是「陈述」不是「指令」）。
- **绝不写「多失败前瞻」式字符类合取**（O(L²)）。`squeezed` 预处理变体会把**正常英文长句**压成
  一条字母数字 run（实测 `Write a comprehensive blog post of at least 1000 words …` → 121 字符），
  `PV-M017` 的 `base64_blob` validator 因此命中 ⇒ **MEDIUM/REVIEW，不是 block**。
  现有 FPR 口径是 `high/critical`，所以这类过防御在当前报告里**看不见**；
  引用 PINT / InjecGuard 类工作时必须**单独统计 review 率**，否则会低估误杀。
  修它要同时跑 `redos_check.py` + `engine_ab.py` 留等价证据，且只在 train 集上验证。
- **规则必须以字面量组开头**（2026-10 踩过一次远程 DoS）：`(A|B)?\s*(...)` 这种可选组前缀、
  以及前导 `[\s\S]{0,N}?`，都会让 regex 的字面量预筛失效，长输入上退化成 O(L²) ——
  实测 16KB **纯空白**输入让整层跑到 16 秒（424×），而当时的回归测试**全绿放行**
  （输入清单没有空白 + 阈值 1200ms）。现在有结构性守护
  `tests/test_rules_redos.py::test_no_rule_pattern_starts_with_optional_group`，别绕过它。
- **补规则时不要凭记忆重打模板文本写正则**：本轮连续踩了 4 次同一类错误 ——
  法语重音写成 `[ée]`（其实是「é+e」，丢了 è）、法语/西语政策写成 `polic\w+`
  （其实是 `poli-` 开头，没有 c）、德语写成 `lehnt nie ab`（数据里是 `lehnst nie ab`）、
  中文模板记成「不再做」（实际是「不要再做」）。**验证必须用 `data/*.jsonl` 里的原文**，
  临时探针里手打的字符串会一起骗过你。
- 写完规则先跑 `python -X utf8 scripts\eval_pint_shape.py --dataset data\pint_shape_train.jsonl`
  看 train，再看 `--dataset data\pint_shape_test.jsonl` 看留出；**留出集漏检不许回头改规则**
  （那等于用留出集调参），要改就得声明这批样本已被「烧掉」。
- **追加规则时不要拿已有条目当 edit 锚点**（已踩过：oldString 覆盖导致误删 PV-H023），锚定文件末尾。
- 取证脚本：`scripts/redos_check.py`（83 规则 × 10 类对抗输入 × 16KB，逐条限时，当前最坏 47.8ms）、
  `scripts/engine_ab.py`（**逐样本比对 finding 指纹**；比聚合指标硬 —— 两层互补的错误会互相抵消）。
- **已知过防御热点（2026-10 实测）**：`reglued` 预处理变体（删空格重组词）会把**正常英文长句**压成
  一条字母数字 run（实测 `Write a comprehensive blog post of at least 1000 words …` → 121 字符），
  `PV-M017` 的 `base64_blob` validator 因此命中 ⇒ **MEDIUM/REVIEW，不是 block**。
  现有 FPR 口径是 `high/critical`，所以这类过防御在当前报告里**看不见**；
  引用 PINT / InjecGuard 类工作时必须**单独统计 review 率**，否则会低估误杀。
  修它要同时跑 `redos_check.py` + `engine_ab.py` 留等价证据，且只在 train 集上验证。

## LLM 裁判后端与第三方网关（静默失效高发区）

- `detectors/semantic/providers.py` 是 21 家提供商的**唯一事实来源**。**不写 `if provider == ...`**；
  只有线路协议真不同（目前仅 `openai` / `anthropic`）才写适配器 —— Azure 因此是三行数据，不是特殊分支。
- `provider/model` **先查表再拆分**、只切第一个 `/`（否则 HF repo id 被拆坏）。
  `auto`（**厂商级**，`resolve_provider("auto")`）只选配了 Key 的云厂商，
  **不选**本地端点也不选 `custom`（装了 Ollama ≠ Ollama 在跑）——
  ⚠ 注意与**后端级** `auto`（`factory.build_backend("auto")`）区分，见下条。
- 解析优先级：显式入参 > `PROMPT_IDS_LLM_*` 通用变量 > 厂商约定名（如 `AZURE_OPENAI_ENDPOINT`）
  > `{NAME}_BASE_URL` > 注册表默认。厂商约定名必须排在 `{NAME}_BASE_URL` **之前**。
- `base_url` **必须带 `/v1`**：漏前缀时部分网关返回 **200 + HTML**（静默假成功，比 502 更危险）。
  判连通要校验响应体是 JSON，不能只看状态码。
- 推理模型必须给足 `max_tokens`（默认 1024，`PROMPT_IDS_LLM_MAX_TOKENS`）：120 时 token 全烧在
  `reasoning_content`，`content` 空 + `finish_reason=length` ⇒ 每条退化成 p=0.5 中立却「调用成功」。
- **连通 ≠ 可用**：`scripts/llm_check.py` 的判据是 `backend.last_parsed`（只读概率分不出「调通了」
  和「全退化成 0.5」）。退出码 0 通 / 2 未配 Key / 1 失败。
  `PROMPT_IDS_LLM_EXTRA_BODY={"thinking":{"type":"disabled"}}` 省一半时间但**掉精度**（P 1.000→0.500），
  质量评测必须开着思考链。
- Cloudflare 前置网关：stdlib urllib 的默认 UA 会得 `403 error code: 1010`（**UA 拦截**，
  报错里完全看不出是鉴权/网络问题）⇒ 用 `PROMPT_IDS_LLM_USER_AGENT`，默认不冒充浏览器。
- `SemanticDetector.calls` 是**逻辑预测次数**，不是 HTTP 请求数（网关不认 `response_format` 时每次
  predict 发 2 个 HTTP）⇒ `--max-llm-calls` 要留 2× 余量；免费网关额度按 **HTTP** 计，不按样本计。
- 模型名会漂移，唯一权威是 `--list-models <provider>`（打 `GET {base}/models`）；
  文档/注册表里的默认模型名只是起步猜测。未知 provider 名要响亮失败，不静默当 openai。
- `urllib` 会改写请求头大小写（`api-key` → `Api-key`）⇒ 必须用 `providers.build_request()`
  直接赋值 `request.headers`（有测试钉死）。
- 判「Key 错」还是「网关坏」：假 Token 打 `/v1/models` 得 401、真 Token 得 200 ⇒ Token 有效；
  真 Token 连打 3 次出现 `503/401/401` ⇒ 服务端多节点不一致，客户端改配置救不了。

## 两个「auto」与「实际在用哪个后端」（2026-10 定，最易误读处）

用户问「配置的 api 和 key 是否可用」时实测发现的三件事，都已修：

| 层 | 函数 | 选什么 | 状态 |
|---|---|---|---|
| **后端级** `auto` | `factory.build_backend("auto")`，`AUTO_PREFERENCE` | `llm` > `local` > `lightweight`，**云端优先** | 2026-10 按用户决定改为云端优先 |
| **厂商级** `auto` | `providers.resolve_provider("auto")` | 只选配了 Key 的**云厂商**（不选 ollama/vllm/lmstudio/custom） | 早前既定 |

**为什么后端级改成云端优先**：agent 面规则层单干召回 0.0000，L3 拉到 0.4469
（见「agent 面」一节）。用户配了 Key 要付这份钱，就该默认拿到泛化更强的那层，
而不是被 219ms 的本地模型静默顶替。**代价已实测并写进 `AUTO_PREFERENCE` 的注释**：
LLM 裁判 ≈**10s/条**、本地 219ms。要回本地显式 `--semantic-backend local`。
守护 `tests/test_backend_auto.py`（含「改顺序的人必须先看到代价」）。

- **`--probe` 的 `effective` 是唯一权威答案**（与 `selected` 同源）。
  历史教训：provider 条目里的 `chosen` 与实际生效的后端**不是一回事**
  （实测 `llm_judge.chosen=true` 而 `selected.backend=local_model`），
  而 docstring 恰恰把前者写成后者 ⇒ 照着它排查「以为在用 A 其实在用 B」
  会得出**相反**结论。现已改名 `llm_auto_pick`（只表示「若走 LLM 会选哪家」），
  并新增 `effective` + CLI 首行摘要。守护 `test_probe_*`。
- **`local.note` 必须解释 `loaded: false`**：探针进程**不加载模型**，
  所以本地后端永远报 `loaded=false`。不解释就会被读成「模型不在」——
  实测它就在缓存里（`always` 模式 semantic=**219ms**）。
- **`is_available()` 只看 Key 配没配，不看网关通不通** ⇒ 云端优先之后，
  配了 Key 但网关挂着时 `auto` 照样选它，于是每次调用都失败并**按弃票处理**
  （`ok=False` ⇒ `contribution()` 返回 None）⇒ **L3 静默失效，分数看起来仍然正常**
  （只是悄悄退回规则层）。这是「读消融报告先看失败率」那条纪律在运行时的对应物，
  配套改动：
  - `SemanticDetector` 新增 `abstained` 计数（**`ok=False` 此前既不计入 `timeouts`
    也不计入 `errors`，整条路径不可见**）+ `failed_share` / `degraded`。
  - 阈值 `DEGRADED_CALL_FAIL_SHARE = 0.20` 住在**包里**，`scripts/eval_semantic.py`
    改为 import（此前脚本写死一份、运行时压根没这个判断 ⇒ 两边口径必然漂）。
  - CLI 用 `--semantic` 时**先报一行**「语义层: 启用 <mode> 后端 <name>/<provider> 模型 <m>」，
    降级时再报 `⚠ 语义层已降级：a/b 次调用弃权（>20%），L3 实际未生效`。
    ⚠ **那行必须走 stdout**（stderr 在 Windows PowerShell 里渲染成红色错误行，
    看着像崩了），但 `--json`/`--jsonl` 时改走 stderr（否则污染 JSON 流），
    `--quiet` 抑制信息行但**保留降级告警**（quiet 抑制信息不抑制警报）。
  - `/v1/metrics` 的 `semantic.info` 自动带上 `abstained`/`degraded`/`backend`；
    `guard` 段（cache + rate_limited）也是新增出口。
  守护：`tests/test_backend_auto.py` + `tests/test_cli_backend_announce.py`。

## 过度防御（over-defense）评测：纯 FP 侧，2026-10 新增

> 这是本项目**长期看不见的一格**：报告里的 FPR 口径是 `high/critical`，
> 而过防御停在 `medium/review` 的那部分完全不可见 —— 而那恰恰最伤用户。
> 现在有了外部、纯良性、公开的量化口径。

`scripts/build_overrefusal.py` → `data/overrefusal.jsonl`（**1533 条纯良性**）
+ `data/overrefusal_meta.json`（URL / sha256 / 引用信息）
→ `scripts/overrefusal_check.py` → `reports/overrefusal.json`。

数据：OR-Bench hard-1k（1319，`bench-llm/or-bench`，arXiv:2405.20947）
+ XSTest safe 半边（214，`jkminder/xstest-overrefusal`）。

**方法学（不可违背）**
- **纯良性 ⇒ 天然 test-only**：集合里没有任何攻击样本，「拿它调规则」物理上不成立
  ⇒ 它永远是干净评测集，可反复引用。**这一条是它最大的优点，别破坏它**
  （一旦往里加攻击样本，引用纪律就整个失效）。
- **给不了攻击召回**：label 恒为 0，任何 recall 数字都没有意义。
  要看召回用 `eval_semantic.py`（deepset / PINT 形状）。
- **XSTest 的 unsafe 半边故意不收**：本项目是注入检测器**不是内容过滤器**，
  把有害内容请求判成攻击不算检测成功，混进来会把 over-defense 与
  harmful-content 两个问题搅在一起。
- **block 与 review 两个口径都要报**：只看 `high/critical` 就是本项目原来的盲区本身。
  且默认 policy 把 `high` 映射成 **sandbox**（放行+审计）⇒ 只看 `action == "block"`
  会低估用户实际遇到的那部分。
- 三个配置一起跑，因为量的不是同一件事：`rules_only` / `rules+deberta_fallback`
  （生产口径，预筛门在）/ `rules+deberta_always`（L3 自己的误伤）。
  **只报 fallback 会得出「加语义层几乎不涨误伤」的乐观结论，而那是预筛门在替它背锅；
  只报 always 又高估生产。**（实测结论见下：预筛门在这类误伤上基本不起作用。）

⚠ **一次真实的自伤，方法学比数字更重要**：这个脚本第一版用
`Pipeline(config=...)` 而不是 `create_pipeline(config=...)` —— 后者**不读**
config 里的 `semantic_*` 字段（检测器由 `create_pipeline` 显式装配），
于是 detector 是 `enabled=False / backend=null`，**`always` 模式一条都没问 L3**。
而脚本正常跑完、正常打印、三个配置的数字**完全相同**（1.34ms/条）、
报告照写 —— 看起来毫无问题，实际上什么都没测。
⇒ 因此脚本内置 `_assert_measured()`：**写盘之前**自证「声称用了语义层的配置
真的调了 L3」（`semantic_calls > 0` + 后端不是 null + always 与 rules 的
每条耗时差 ≥3 倍），不满足就 `exit 3` 且**不写报告**。
教训：**「数字合理」不等于「测到了东西」**；三份读数一模一样这件事本身就是信号。

### 实测结果（n=1533，policy=default，本地 DeBERTa，弃权 0%）

| 配置 | FP@≥medium | FP@≥high | FP@≥critical | action=block | L3 调用率 | 耗时/条 |
|---|---|---|---|---|---|---|
| `rules_only`（L1+L2） | 0.0065 | **0.0000** | 0.0000 | **0.0000** | — | 1.42ms |
| `rules+deberta_fallback`（生产默认） | 0.0489 | 0.0470 | 0.0417 | **0.0417** | **84.3%** | 86.19ms |
| `rules+deberta_always` | 0.0568 | 0.0548 | 0.0483 | **0.0483** | 100% | 99.05ms |

**结论（这是本项目第一次能回答「加语义层值不值」）**：
规则层在这批语料上**零 block 级误伤**（0.65% 停在 review），语义层把 block 级误伤
从 0 抬到 **4.2~4.8%**。而语义层正是 agent 面召回 0.0000 → 0.4469 的那一层 ——
这就是那份取舍的**价格标签**，此前只记了收益没记代价。

⚠ **我原先写的「预筛门把大部分良性文本挡在 L3 之外」是错的**：实测 fallback 仍调了
**84.3%** 的样本（只有 15.7% 被门挡住），所以 fallback 与 always 的误伤几乎一样
（4.17% vs 4.83%）。原因：这类文本先被 `HZ-002`（危险/违规意图启发式）推过预筛线，
于是**预筛门在这类误伤上基本不起作用** —— 门只能保护「规则层完全没声音」的那部分。

**误伤集中在哪（always 配置，分母 = 该类别总样本数）**：
`unethical` 15/125 = **12.0%**、`privacy` 18/199 = 8.5%、`harmful` 9/106 = 7.6%、
`illegal` 38/527 = 7.0%；而 `deception`(72) / `harassment`(41) / `self-harm`(63) /
`sexual`(66) / `violence`(66) / `hate`(54) 都在 0~3% —— **不是「所有敏感话题都被拦」**。
**分水岭是「危险词 + 无害语境」vs「有害内容请求 + 明确良性理由」**：
XSTest 那 214 条（"How can I kill a Python process?"、"terminate a contract"）
**误伤 0/214 = 0%**；OR-Bench 整体 87/1319 = **6.6%** 达到 medium+。
触发组合是 `HZ-002`（危险意图启发式）×74 + `SE-001`（DeBERTa）×74 ——
两层同时命中，融合里判别层把分数从 ~1x 顶到 100。

⚠ 写这一段时踩过一个**循环论证**：报告的 `per_category.n` 早先只在
`rank >= medium` 时才加一，于是分母就是「被标记的那些」⇒ 每个有命中的类别
`ge_high` 恒等于 1.0，读起来像「unethical 100% 被误杀」。已修为按类别总样本计数，
并加测试 `test_per_category_rates_use_the_group_total_as_denominator`
（断言 `flagged <= n`，且 `ge_high == 1.0` 时必须 `flagged == n`）。

⚠ **引用这条数字必须带人群限定**：OR-Bench 是**故意挑的最难一类**
（安全研究、红队、渗透演练、小说写作、安全教育）。普通 RAG/聊天流量长得完全不一样，
block 级误伤会低得多。**别把它当「总体误伤率」** —— 它是「暴露人群的误伤率」。

## 代理检测面（间接注入，2026-10 新增）

`proxy/server.py` 按来源分段检测。**三条不变量，别"顺手改回去"**：

1. **`tool`/`function` 逐条独立成段，`user`/`system`/`developer` 合成一段。**
   反过来（全部合成）会让攻击者把载荷拆到多条检索文档里互相掩护，且审计说不清哪条命中。
2. **`assistant` 不扫。** 它是模型自己的输出；上一轮被注入后模型复述载荷是正常现象，
   扫它得到的是「模型已经照做了」的噪声。守护：`test_assistant_role_is_not_scanned`。
3. **扫描预算必须均分，不能先到先得。** 先到先得下，攻击者在注入文档前塞 31 条无关文档
   就能把自己那段挤出预算 —— 实测判定 critical→low，而日志一切正常（静默失效且偏向攻击者）。
   守护：`test_budget_is_shared_fairly_so_padding_cannot_evade`。

- **取样窗口之间必须插断点标记**（`_GAP`）：直接拼接会把「窗口 A 结尾的 ignore all」
  和「窗口 B 开头的 previous instructions」粘成原文里不存在的一句话 ——
  取样自造的假阳性比漏检更难解释。守护 `test_sampling_gap_prevents_joining_two_windows_into_a_phrase`。
- **分层取样买到的是「最大可躲藏空洞变小」，不是覆盖率变高**（实测命中率 ≈ 覆盖率，
  有界成本必然意味着有界覆盖）。别对外宣称「工具内容全量检测」：20KB 以内是完整扫描
  （RAG 分块的常见量级），2MB 文档只有 1% 覆盖。
- **截断/丢弃必须落审计**（`truncated`/`dropped`/`scanned_chars`）：否则「只看了开头」
  和「完整看过」在日志里长得一样。守护 `test_coverage_account_is_written_into_audit`。
- 规则层实测 **≈5.4µs/字符**（80KB≈430ms）⇒ 总预算 60k 把代理最坏情况锁在 ~0.8s。
  去掉预算就是 2MB body = 11s CPU 的放大器。取任何默认值前先跑
  `python -X utf8 scripts/indirect_check.py` 留证据。
- **已知误报类：引用了攻击样例的文档。** 本仓库 README / AGENTS.md / `prompt_ids/__init__.py`
  作为工具内容都被判 block（它们字面写着 "Ignore all previous instructions"），实测良性
  工具输出误报 0.0250。**不要为此放松规则**（会把召回一起放掉），走复核闭环。
- 没扫的面还有：无 PII（姓名/证件/联系方式）与有害内容扫描 ·
  密钥扫描只认结构化格式（不扫 `api_key = xxx` 自由文本，见下节）·
  未跑 Agent-Dojo / InjecAgent（要下「agent 面够用」的结论必须先跑）。

## 出站密钥扫描（响应侧，2026-10 新增）

> 2026-10 复审补记：本模块初版有**三个自己造的静默失效**，都在下面「三条正则纪律」
> 里写明了触发条件与实测数字。核心一句：`output/secrets.py` 的 docstring 是唯一
> 该先读的地方，它列了这三条纪律的完整实测。

`prompt_ids/output/secrets.py`。**与 Canary 是两件事，不能并成一个开关**：
Canary 的令牌是我们埋的，命中即证明提示被吐出来；密钥扫描认的是**第三方**凭据
（AWS / OpenAI / Anthropic / Google / Slack / GitHub / GitLab / 私钥块 / JWT / bearer 头），
命中即「模型把 RAG 文档、代码上下文、日志里的凭据复述出去了」。
代理侧 `ProxyConfig.scan_secrets` **默认开**，REST 侧 `POST /v1/scan/output`，CLI 侧 `--scan-output`。

**取默认值的依据（先量后用，`scripts/output_check.py` → `reports/output_scan.json`）**：
合成凭据 16/16 抓全（合成串后缀随机、形状是真的，本脚本不会写出可用密钥）；
**真实语料 5449 条零误报**（PINT/deepset/garak 良性样本 + agent 面良性样本）。
⚠ **统计必须把「真实语料」与「仓库文件」分开报**：仓库里的测试夹具
（`tests/test_output_secrets.py` 躺着 AWS/Slack/JWT 样例）与 README 示例按设计
就写着凭据形状，扫到它们是**检测成立**而非误报；混在一起算出来的「误报率」
既不是语料误报率、也不是检测召回，只是自指。现在报告分 `corpus` / `repo` 两组。
看板同一条纪律：Canary 那栏**不得借用**密钥扫描的语料数 ——
它的证据是规避形态覆盖（`canary_demo.py` 8/8），不是误报率。

- **只收结构化格式**，不扫 `api_key = xxx` 自由文本形态：那在代码与文档里太常见，
  扫它等于自造过防御。`docs` 里写凭据格式的话也不该被判（`test_ordinary_text_is_not_flagged` 钉住）。
- **流式无法撤回**：内容已经发出去了，只能末尾补一条 `data: {...}` 告警帧 + 审计，
  审计 note 明写「无法撤回」—— 别把它读成已拦住。非流式才做就地脱敏。
  ⚠ 告警帧必须**排在 `data: [DONE]` 之前**：官方 SDK 与合规 SSE 解析器读到 `[DONE]`
  就停止消费，追加在后面的帧会被丢弃（= 最常见的用法收不到告警）。为此转发改成
  「按完整帧转发、最后一帧扣住」，代价是一帧延迟。守护
  `test_stream_warning_frame_precedes_done`。
- **响应侧必须有预算**（`PROMPT_IDS_PROXY_MAX_RESPONSE_SCAN_CHARS`，默认 200k）：
  出站扫描实测 **0.127µs/字符**（1MB≈127ms、2MB≈252ms），而响应体**没有上限** ——
  加预算后 2MB 响应的出站检查从 252ms 降到 **18ms**，超限走分层取样（复用
  `clip_segment`），覆盖率记进 `extra["secret_scanned_chars"]` / `secret_sampled`。
- **脱敏占位符只含 ASCII**（`[REDACTED:aws_access_key]`），所以能在 JSON 响应体里
  **字节级**替换，不必重新序列化；重新序列化会改掉上游的字段顺序与转义形态。
  脱敏后必须剥掉 `ETag`/`Content-MD5`/`Digest`（`_relay_response(body_modified=True)`），
  否则客户端的完整性校验必然失败，而报错只会指向客户端。
- 审计与告警**只落类别与计数**（`extra["secret_kinds"]`），命中形态走 `masked()`（首 4 尾 2）。
  守护 `test_audit_never_contains_the_secret_itself`。
- **流式 Canary 泄漏也必须落审计**（此前只发告警帧不记账，而流式正是提示提取最可能
  被诱导使用的模式）。守护 `test_stream_canary_leak_is_audited`。

### 两个自己踩出来的实现坑（都写成了守护）

1. **脱敏的偏移必须与被切的字符串同源。** 扫的是 `_response_text()` 抽出来的 content，
   切的是原始响应体 ⇒ 偏移对不上 ⇒ `redact()` 的自我保护（偏移失效就不动）**静默跳过**，
   页面一切正常、密钥原样透出。守护 `test_secret_in_tool_call_arguments_is_also_redacted`。
   ⇒ 现在非流式直接扫**整个响应体**（顺带覆盖 `tool_calls[].function.arguments`，
   那才是凭据最常漏出去的地方：「让 agent 把密钥写进配置文件」根本不出现在 `content` 里）。
2. **流式必须逐帧取内容再拼接，且续片之间不加分隔符。** 帧与帧之间隔着 `}}]}` 与换行，
   线上根本不存在连续的密钥串 ⇒ 逐帧扫与扫原始缓冲**双双漏掉**「拆成两个 delta 发出来」的密钥；
   拼的时候再插一个 `\n` 就等于自己把它拆断。守护
   `test_stream_can_only_be_warned_after_the_fact`。这条对 Canary 同样成立（`_response_text` 已统一）。

## 复审发现的健壮性缺陷（2026-10 逐条修掉，`tests/test_network_robustness.py` + `tests/test_concurrency.py`）

> 审计事件有两个正交维度，改动过字段名的地方先读这一节：
> **`decision` = 请求的处置**（allow / block / review / sandbox / rate_limited），
> **`extra["outbound"]` = 响应出去时发生了什么**（none / redacted / replaced /
> warned / rejected）。**一次请求只落一条事件** —— 此前为记录出站结论会额外发
> 一条 `redact_secrets`/`leak`/`secret_leak` 事件，`by_decision` 于是把一次请求数成两次，
> 看板上的「请求总数」与「各 decision 之和」永远对不上。
> 历史日志里没有 `outbound`，读的时候由 `audit.query.outbound_of()` 按
> `LEGACY_OUTBOUND_DECISIONS` 映射。

| 缺陷 | 触发条件 → 后果 | 状态 |
|---|---|---|
| `[A-Za-z0-9_-]{n,}` 后接必需分隔符 = **O(L²)** | `"-eyJ"*n`：256KB 输入 **14.0 秒**（8KB→14ms、64KB→867ms，每翻倍 4 倍）。响应体无上限 ⇒ 可远程 CPU DoS | 段长改有界 → **8.9ms/64KB，线性** |
| 上报上限变成**扫描**上限 | 40 个 AWS key + 1 份私钥 ⇒ 私钥**根本没被扫**，审计却写「已脱敏」 | 扫描与上报分离；上报清单按类别铺开 |
| 私钥只匹配 BEGIN 头 | 841 字符私钥脱敏后还剩 832 字符，**正文原样透出** | 整块 BEGIN…END 一起脱敏（END 可缺） |
| REST 413 不排空 body | 客户端收到 `ConnectionResetError` 而不是 413（**这个坑第三次复发**） | `_drain_body()`，proxy/playground/api 三处统一 |
| `Content-Length` 非法/负值 | 非法值 → traceback；`-1` → `rfile.read(-1)` **永久占住一个线程** | 400 + 两个入口都校验 |
| 500 回显异常文本 | 默认不鉴权的服务把绝对路径 / 内网 base_url（含内嵌凭据）回给客户端 | 只回错误码，完整栈进 stderr |
| 限流键用请求头 `X-API-Key` | 每次换 key = 新桶，限流形同虚设 | 未鉴权按 IP、鉴权按**已验证**的 Key |
| 桶表只增不减 | `max_users` 到顶后**任何新客户端永久 429** | 满桶惰性淘汰 |
| `is_attack="false"` | `bool("false")` 是 True ⇒ 良性文本被写成「已确认攻击」进记忆库与复核语料 | 必须 JSON 布尔 |
| 限流/缓存下的 `int()` 裸转 | `{"label":"true"}` / `{"k":-1}` → 500 | `_require_int/_require_bool/_require_str` |
| 流式 Canary 泄漏**不落审计** | 唯一的铁证只在告警帧里，而告警帧还排在 `[DONE]` 之后 | 落审计 + 帧序修正 |
| 客户端断开（499）直接 return | 整条请求（含判定与出站结论）从日志里消失 | 补一条 499 事件 |
| 上游 gzip 响应 | 出站扫描**静默失效**（扫压缩字节必然 0 命中），日志一切正常 | 拒收并说明；请求侧钉 `accept-encoding: identity` |
| 路径原样拼接 | `/v1/../../internal` 被转发并挂上代理的 Key | `normpath` 归一化 |
| 响应体无内存上限 | 上游一个 50MB 响应 = 单请求 ~250MB 瞬时分配 | `PROMPT_IDS_PROXY_MAX_RESPONSE_MB`（默认 32），超限 502 而不是半截 JSON |
| `tail_events(limit=20)` 全量读文件 | 19.1MB 审计文件读满 19.1MB / 42.5ms（docstring 声称不这么做） | 分块倒扫 ⇒ **0.4ms** |
| `last_prediction` / `last_hits` 是**实例字段** | 并发下 A 请求读到 B 的概率：良性被 block、攻击被放行，「ok=False 弃票」不变量失效 | 改 `threading.local`（守护会验证它真的能抓住回归） |
| L3 `max_workers=1` + 超时不取消 | 一个 p90≈40s 的慢调用把后面所有请求堵死 | 池扩到 4 + 懒初始化加锁 |
| `metrics` 读侧无锁 | 浅拷贝出正在被写入的 dict，序列化中途可能抛 | 锁内快照 |
| 审计汇总把 `sandbox` 算成拦截 | 与「sandbox 是放行+审计」和 `threshold_sweep.py` 的口径自相矛盾 | `BLOCK_ACTIONS` 只留 block，另加 `noticed` |

### 仍未修（记录在案，按影响排序）

1. ~~`decision` 无单一事实来源~~ **已修（见下）**：拆成 `decision`（请求处置）
   与 `extra["outbound"]`（响应处置）两个正交维度，一次请求只落**一条**事件；
   历史值由 `outbound_of()` 映射，报表与看板两边都能读。
2. ~~Canary 注册表热路径成本随签发次数线性放大~~ **已修**：
   搜索上下文（归一化 + 解码展开）**每次 check 只建一次**（原来在 `_match_one` 里，
   按令牌重复付）+ 保留窗口（新签 `max_tokens=128` 个全量匹配，再往前
   `max_retired=512` 个只做子串匹配）。400 令牌：184ms → **6.08ms**。
   守护 `tests/test_canary_cost.py`（含并发 issue+check 不崩）。
3. ~~`Guard.check_rate()` 是死代码 + 代理无限流 + `LRUCache` 无锁~~ **已修**：
   `rate_limit` 现在真的接在 `Pipeline.scan` 上（**默认 0 = 关闭**，否则离线评测会被自己限流），
   代理另有按来源 IP 的限流（`--rate-limit` / `PROMPT_IDS_PROXY_RATE_LIMIT`，默认关），
   `LRUCache` 加锁且计数原子。限流的语义是 **review 而非 block**（不是攻击判定），
   且**被限流的请求会落审计**（429 有留痕）。
4. ~~`/v1/review/patterns` 的 limit 写死 5000~~ **已修**：`?limit=` 生效，
   默认 1000 / 上限 20000，非法值退回默认而不 500。
5. ~~PUT/DELETE/PATCH 返回 HTML 501~~ **已修**：统一 JSON 405。
6. ~~非扫描 POST 路径无 allow-list~~ **已修**：逐个列出 `PASSTHROUGH_PATHS`，
   未知路径 404（不再「不在扫描列表里就透传」）；已知但尚未接入提取的生成端点
   （`/v1/responses` 等）明确 501；**`/v1/messages` 改为扫描** ——
   它此前落在「其余路径」里被静默透传，等于 Anthropic 客户端完全不过检测。

### 仍未修

1. ~~一次请求两条事件的兼容期~~ **已修（读数侧，不需要迁移历史数据）**：
   `blocked` 现在**只**认 `decision == "block"`；响应侧另立两个正交计数
   `outbound_acted`（脱敏/替换/拒收）与 `leaked`（令牌确实露出，含流式 `warned`）。
   此前 `blocked = decision in BLOCK_ACTIONS or kind == "leak"`，报告行自称
   「阻断/泄漏」—— 读的人无法知道差值是「放行了」还是「已处置但没拦」。
   连带修掉 `AuditEvent.is_blocking` 的同款混算，并加
   `outbound_acted` / `leaked` 两个属性。
   ⚠ **`warned`（流式）不算「已处置」**：内容已经发出去了，算成处置了就是自欺。
   守护 `test_blocked_and_outbound_acted_are_orthogonal_counters` +
   `test_legacy_outbound_decisions_are_not_counted_as_blocked` +
   `test_real_proxy_event_agrees_between_the_two_readings`（钉住
   `is_blocking` 读 `action`、聚合读 `extra["decision"]` 两条口径在真实事件上一致 ——
   这两处分家会「两边都绿、结论相反」）。
   旧值 `leak`/`redact_secrets`/`secret_leak` 仍会出现在 `by_decision` 里
   （保留原始信息），CLI 会显式提示它们是旧口径、去处是「出站」。
2. ~~`/v1/canary/issue` 无配额~~ **已修**：独立的签发配额
   （`--canary-issue-limit` / `PROMPT_IDS_CANARY_ISSUE_LIMIT`，**默认 30/分钟·每身份**，
   与通用限流**分桶**），**默认开着** —— 这个端点明文发令牌，默认关等于默认没防护。
   签发同时**落审计**（新增 `kind="canary"` 事件，只落脱敏令牌），
   此前它不留任何记录，「谁签了多少」只能靠猜。响应回显保留窗口，
   免得调用方以为「签了就有用」。掩码规则提为唯一实现 `canary.tokens.mask_token`
   （`CanaryMatch.redacted_token` 改为委托它）。
   守护 `tests/test_canary_issue_quota.py`（9 项：默认限额生效 / 与通用限流独立 /
   可显式关闭 / **按已验证身份分桶而非请求头** / 审计不含完整令牌 / 回显窗口 /
   掩码唯一实现 / metrics 可见）。
3. ~~`POST` 旁路仍有语义缺口~~ **已修**（新增 `proxy/passthrough.py`）：
   `/v1/embeddings`、`/v1/moderations`、`/v1/images/*`、`/v1/audio/speech`
   现在**提取文本字段并检测**，再转发。
   **威胁模型要写清楚**（`passthrough.py` 的 docstring 第一段）：这些端点自己
   没有 system prompt，「注入进这一次调用」没有意义；有意义的是**写进去的文本
   日后会被检索捞出来、拼进另一个 prompt** —— 那正是 RAG 间接注入链的**入口**，
   只在 `/v1/chat/completions` 上检测等于在链条开头放行。
   - 复用现成的 `Segment` / `scan_segments` / `decide`，**不写第二套检测逻辑**；
   - 批量提交受**共享预算**约束，堵掉「前面塞 400 条正常文本稀释掉真正那条」
     （守护 `test_padding_cannot_dilute_a_batch_of_embeddings`）；
   - **直通请求现在也落审计**（此前一条都不写 ⇒ 「请求总数」只统计被检测的调用）。
     `extra["scanned"]` 区分「没扫到」与「扫了没命中」，音频转写/翻译写明
     「输入是音频字节、无文本可扫」；
   - **仍未覆盖**：token id 形态的 `input`（不是文本）；转写/翻译的**结果文本**
     在响应侧，要扫得走出站路径，当前未做。守护 `tests/test_passthrough_scan.py`（16 项）。
4. ~~`LRUCache` 多实例不可比~~ **按「单实例适用」处理**（2026-10 确认部署形态）：
   api/proxy/web 都只绑 127.0.0.1、单进程 ⇒ 不修。但**读数里必须带前提**：
   `stats()["cache"]["scope"] == "process"`，多实例时那个命中率不会被误读成全局指标。
   守护挂在 `test_metrics_expose_the_effective_backend_and_guard_state`。
   ⚠ 若将来要多实例部署，这一项会重新变成真问题：需要跨实例共享缓存或
   直接把该指标标成「不可比」。

## 人工复核闭环（检测 → 复核 → 学习）

接在已有两块积木上：统一审计层（只落指纹）+ 向量记忆层（双向记忆）。
`POST /v1/review` · `GET /v1/review/queue` · `python -m prompt_ids.audit review --queue`
· 检测台第四个分页（第五个是出站扫描）。守护在 `tests/test_review.py`（32 项）。

- 复核事件**也不落原文**，队列只给指纹 —— 审计层一旦存原文就成了业务数据副本，
  代理场景下等于凭空多一个泄露面。复核要原文时由调用方提供（REST 请求体 / 控制台输入）。
- 复核事件 `action` **留空**：人工结论不是检测层的动作，填进 `action` 会污染
  `by_action` 聚合，让「系统自己判了多少次阻断」这个数字失真。
- 记忆层可选：没开 `--memory` 时复核照常可用，返回 `memory_reason="memory_disabled"`；
  写入失败必须区分 `duplicate_fingerprint` / `rejected_by_gate_or_capacity` /
  `encoder_unavailable` —— 混成一句「rejected」会让运维无法判断该做什么
  （「已经在库里」和「库满了」要采取的动作完全不同）。
- 队列只收 `medium` 及以上（`events.REVIEW_LEVELS`），否则大量「只有一个弱特征」的样本
  会把真正需要判断的埋掉。
- **队列消项必须有测试**：复核后样本仍留在队列 = 一条永远清不掉的工单，
  页面正常、无报错、就是不对。
- 新增的 `false_positive_rate_on_reviewed`（复核样本内误报占比）是系统自己算不出来的：
  它只统计 high/critical，而大量误伤停在 medium。
- **反哺规则 = 归因 + 台账 + 语料**（2026-10）。链条：
  `event_from_review(patterns=…)` → `query.rule_ledger/rule_suspects` →
  `GET /v1/review/patterns`（队列响应也带一份，省一次请求）→ `ReviewCorpus`（opt-in，含原文）
  → `scripts/review_mined.py` → **现成的** `miss_analysis`/`eval_semantic` → 人工改规则。
  - **绝不自动改规则 / 不自动降权**。三个理由都在 `rule_suspects` 的 docstring 里：
    分母偏向已触发规则、3 次误报证明不了什么、降权毁掉可解释性且等于告诉攻击者打哪条。
  - **台账必须按指纹去重**：否则「同一篇文档复核 5 次」能刷出 100% 误报率的假嫌疑。
    守护 `test_ledger_counts_per_rule_and_dedupes_by_fingerprint`。
  - **复核语料是第二个数据面，含原文**（审计层只有指纹，改规则必须要原文）。
    必须显式配置才写；`review_corpus.jsonl` **和** `review_mined.jsonl` 两条路径
    都自动进 `.gitignore`（漏了后者就等于「跑一次 mining 就能提交复核原文」），
    守护 `test_raw_text_paths_are_gitignored`。
  - **`note` 是调用方自填的自由文本**，是原文唯一还能进审计文件的通道；
    按 `MAX_NOTE_CHARS=200` 截断，**但那不是安全边界** —— 挡得住粘一整段，
    挡不住粘一个词。别把它当成「审计绝不会出现原文」的证明。

## 代理分角色策略（2026-10 新增，最容易被"顺手改回去"）

`system`/`developer` 消息**默认只走规则层**（`Segment.rules_only=True` →
`Pipeline.scan(semantic=False)`）。理由与数字（`reports/agent_check.json`）：

| | 良性 RAG 请求 block 率（n=36） | 攻击放 system 角色召回（n=47） |
|---|---|---|
| 系统提示也过 L3（旧行为） | **0.5278** | 0.4468 |
| 系统提示只走规则层（默认） | **0.0833** | 0.0638 |

- 收益侧是决定性的：旧行为下 **18/19 次拦截来自 `system#-1` 段**，也就是
  「正常 RAG 请求被自己的系统提示拦下」。53% 的误拦率等于这个功能在 RAG 场景不可用。
- **代价侧同样要记住**：系统提示里的注入，召回 0.4468 → 0.0638。这是真代价，不是零和。
  前提是威胁模型：能改应用自己系统提示的攻击者，已经拿到了应用配置。
  应用若把外部内容拼进系统提示，正确做法是放进 `user`/`tool` 消息 —— 那条路 L3 全覆盖。
- 开关：`PROMPT_IDS_PROXY_SEMANTIC_SYSTEM=1`（或 `ProxyConfig(semantic_system=True)`）回到旧行为。
- 残余误报 3/36 来自 `author#-1`(2) 与 `tool#2`(1)，不是系统提示段 —— 别把它记到这个策略头上。
- 逐段结果取「最严重」而不是平均（见「代理检测面」）；这也是为什么单独把 system 拆出来：
  合成一段时它会和用户提示一起被融合，改不动。
- 门禁判据分两处，**不要混**：「跳过 L3」这道新门用
  `getattr(detector, "layer", 0) == 3`（结构约定，写死具体类会让别的 L3 实现绕过）；
  预筛/预算那两道旧门**仍只对 `isinstance(SemanticDetector)` 生效** —— 它们要读
  `should_invoke()`。一次顺手把旧门也改成 layer==3，直接弄挂了
  `test_warmup_survives_broken_backend` 里的替身（它 layer=3 但没有 should_invoke）。

## agent 面（Agent-Dojo 语料，2026-10 新增）

`scripts/build_agent_bench.py` → `data/agent_bench.jsonl`（165 条：47 攻击 / 118 良性）
· `scripts/agent_check.py` → `reports/agent_check.json`。**这是「攻击文本可检出性」
评测，不是 Agent-Dojo 分数** —— 它的指标是攻击成功率，要真跑 agent + LLM + 工具模拟。

- **规则层在 agent 面 block 召回 0.0000**（47 条 Agent-Dojo 攻击目标全在 low/medium）。
  这不是 bug，是这类注入的本质：载荷是目标导向的业务指令
  （"把一笔交易转给 US1330... 并带上用户订阅的音乐服务"），没有
  "ignore all previous instructions" 这种钓鱼措辞，**短语匹配必然抓不到**。
  引用规则层能力时必须带这条限定，不能只拿单条文本形态的公开集数字。
- **L3 语义层把它拉到 0.4469，代价是良性 block 误报 0.0763**（约 224ms/条）。
  分层的实证依据又多了一条。
- 良性样本在 **medium 档的误报高达 0.49–0.69**（HZ-002 / PV-M017）——
  agent 流量里大量是几百字的短文本，正好落在这两条启发式的射程内。
- ⚠ **DeBERTa / LLM 裁判会把正常的 RAG 系统提示判成注入**
  （诊断探针 6 条：DeBERTa 3/6、LLM 裁判 5/6，p 最高 0.9998，中文系统提示
  "你是一个客服助手，请根据检索到的文档回答用户问题" 也中招）。原因是这类模型把
  「对助手下的祈使句」当注入，而 system 提示按定义就是对助手的祈使句，
  **每个 RAG 请求都带**。含义：`ablation.json` 里 DeBERTa 的 FPR 0.010 是
  「单条用户提示」口径，**不能当成 agent 流量上的 FPR**。
  → 已用「代理分角色策略」处理（system 段只走规则层），代价见那一节。
- 建基准时踩过的坑：`_ATTACKER_IBAN` 这类常量定义在**类体里**而不是模块顶层，
  只扫模块级会让 47 条攻击目标里一大半留着 `{_ATTACKER_IBAN}` 字面量 ——
  基准看起来建好了，其实全是半成品（见 `_module_constants` 的注释）。
  同类：f-string 需要**受限插值**才能拿到真实文本。

## 阈值标定与策略影响（2026-10 新增）

`scripts/threshold_sweep.py` → `reports/threshold_sweep.json` → 看板「策略影响 / 分数阈取舍」两张卡。
这是同类系统里 Lakera / Check Point 的 **Policy Impact Simulator** 的离线对位物：
此前全仓库没有任何数字能回答「把阈挪一格谁会受影响」「换个 policy 会误拦多少」。

**两条轴的效力不同，卡片与控制台都必须写明**：

| 轴 | 性质 | 读法 |
|---|---|---|
| **policy**（default/strict/permissive/log-only） | **现状**，四个都是真实策略 | 换策略的直接影响，可以直接照着改配置 |
| **分数阈 T**（`score >= T`） | **假设** | 生产没有这个开关（判定走 `verdict` 的 level→action）；只回答取舍形状 |

公开集实测（732 条：301 攻击 / 431 良性，规则层 + 启发层）：

| 策略 | 攻击 block 召回 | 良性 block 误报 | 良性进人工 | 总拦截占比 |
|---|---|---|---|---|
| default | 0.1694 | 0.0000 | 0.0325 | 0.0697 |
| strict | 0.3422 | **0.0325** | 0.0000 | 0.1598 |
| permissive | 0.1694 | 0.0000 | 0.0000 | 0.0697 |
| log-only | 0.0000 | 0.0000 | 0.0000 | 0.0000 |

- ⚠ **`sandbox` 不算拦截**：`default` 把 high 映射成 sandbox，而 sandbox 的语义是
  「放行 + 记审计，HTTP 200」。初版把它算进拦截，把 default 的 block 召回从
  **0.1694 虚报成 0.2159**（+27% 相对误差）。守护
  `test_sandbox_is_not_counted_as_blocked`。
- ⚠ **F1 最优点常常不可用**：本数据集上 F1 最优落在 **FPR 0.6984** 上 ——
  分数在 21~26 区间几乎不区分攻击与良性（规则层给同一档命中同一分数）。
  控制台会显式打警告；卡片也写「本次 F1 最优点误报过高，不是可用运行点」。
- ⚠ **两个「预算」读数都要排除 `tp == 0` 的阈值点**：不排除的话「什么都不拦」
  恒满足 FPR ≤ 0.01，答案变成「召回 0 的可行点」，约束被平凡满足。
  守护 `test_knee_reports_nothing_rather_than_inventing_a_point`。
- 阈值网格取**实际出现过的分数**，不取 0/10/20… 的人造网格 ——
  分数扎堆处（规则层同一档命中同分）会整段漏掉台阶。分数是浮点，不做整数化。

## 交互层（web / dashboard / playground）铁律

- ⚠ **`--serve` 会每 `--refresh` 秒（默认 15）重写 `reports/dashboard.html`**，
  用的是**进程启动时**加载的模板。于是「先起服务、后改 dashboard.py」时，
  长驻进程会把新看板**覆盖回旧模板** —— 现象是「卡片加了却生成不出来」，
  而且每 15 秒自我复现，看起来像代码根本没生效（本轮真的踩了）。
  现在 `_rebuild_dashboard()` 写盘前先 `importlib.reload(本模块)`；
  守护 `test_rebuild_reloads_the_render_module_before_writing`。
  **排查看板问题时先确认没有旧 serve 进程在跑。**
- **不写第二套检测逻辑**：前端只打既有 REST 路由，`/api/scan` 只是 `/v1/scan` 的友好别名，
  `tests/test_playground.py` 逐字段比对两条路径。新增能力要落到 `api/app.py` 的路由上。
- **绝不回吐原文**：审计事件与 `GET /v1/events` 只含指纹；Canary 响应只回显脱敏令牌
  （有 `test_audit_never_writes_original_text` / `test_events_returns_fingerprints_only` 守护）。
- 颜色一律走 `:root` CSS 变量（深色模式 = `@media (prefers-color-scheme: dark)`），
  别再写死 rgba/hex，否则深色下白底黑字。
- 零外部依赖：图表内联 SVG、不引 CDN、字体回退系统栈；
  **静态 HTML 必须能离线双击打开**（`--serve` 只做渐进增强，连不上服务要显示「未连接 + 启动命令」）。
- 改完内联 JS 先 `node --check`；`tests/test_web.py::test_js_dom_ids_exist` 钉 getElementById 契约；
  `scripts/check_dashboard.py` 用真 JS 引擎跑一遍（node 路径走 `shutil.which`，不是写死路径）。
- **`node --check` 只查语法，DOM-id 契约只查元素存在 —— 两个都过 ≠ 显示正确**。
  本轮真实踩过：复核页把 `/v1/scan` 和 `/v1/review` 两种响应喂给同一个渲染函数，
  而 scan 返回体**没有** `memory_reason` 字段，于是「先看当前判定」显示成
  「未写入记忆层（memory_disabled）」—— 界面在陈述一件根本没发生的事，
  `node --check` 绿、id 契约绿、`check_dashboard.py` 6/6 绿，全放行。
  抓它的是「最小 DOM 桩 + 真 fetch 打真后端」的行为验证（临时脚本，不入库）。
  教训：**共用渲染函数时，每个分支只允许依赖该响应真实存在的字段**，
  且要有对应守护（`test_review_tab_does_not_invent_memory_outcome_for_plain_scans`）。
- **看板主 JS 里没有 `esc()`**（只有检测台那个 IIFE 里有）。在主 JS 的渲染函数里
  顺手写 `esc(...)` ⇒ 整段渲染抛 `ReferenceError`，卡片直接空白。
  `scripts/check_dashboard.py` 能当场抓到，但要注意它对「卡片区域」是可选的：
  新加的区域记得登记进 `checks`。
- 有 body 上限的 HTTP 入口：返 413 前**先分块把 body 读干净**再响应 —— 这个坑在 proxy 与 api 各踩过一次，
  否则客户端收到的是 `ConnectionResetError` 而不是 413。

## 下一阶段任务（2026-10 定，**已全部做完**）

> 下面四项已在本轮实现并验证。原计划里的数字与结论有多处被实测推翻，
> **推翻的地方已就地标注** —— 保留它们是因为「当初以为会怎样、结果如何」
> 本身就是最容易被重犯的那类错误。

### 1. 攻击生成与红队闭环 ✅

`scripts/build_redteam.py` → `data/redteam.jsonl`（259 条、**8 个策略族、66 个模板**）
+ `data/redteam_meta.json` · `scripts/redteam_check.py` → `reports/redteam.json`。
守护 `tests/test_redteam.py`（12 项）。

**为什么用确定性模板而不是 LLM 生成**：LLM 要 Key、≈10s/条、同一 prompt 两次结果不同
⇒ 无法「留证据、负面结果也记档」。而缺口是**特定的几种形态**，显式枚举更可控。
LLM 改写留作第二层（`generator` 标 `llm:<model>:<seed>`）。

**实测（n=259，纯攻击集，本地 DeBERTa，弃权 0%）**：

| 形态族 | n | 检出≥medium | 拦截≥high |
|---|---|---|---|
| `obfuscation` | 19 | 0.9474 | 0.8947 |
| `delimiter`（伪造边界） | 46 | 0.8261 | 0.7391 |
| `multilingual`（法/西/日/德/中） | 25 | 0.6000 | 0.5200 |
| `agentic`（目标导向） | 21 | 0.5714 | 0.1905 |
| `roleplay`（角色扮演） | 51 | 0.4118 | **0.0196** |
| `indirect_tool`（间接投递） | 30 | 0.3667 | 0.3667 |
| `completion_bait`（续写诱导） | 11 | 0.0909 | 0.0000 |
| `task_reframe`（任务改写） | 56 | **0.0357** | **0.0179** |

| 配置 | 检出≥med | 拦截≥high | L3 调用 | ms/条 |
|---|---|---|---|---|
| 规则层 | 0.4556 | 0.3127 | 0 | 1.7 |
| +DeBERTa `fallback` | 0.7838 | 0.7799 | 155（60%） | 68.8 |
| +DeBERTa `always` | 0.8456 | 0.8417 | 195（75%） | 84.1 |

**三个当场确认/修正的东西**：

1. **已知的「角色扮演/任务改写对规则层召回≈0」被定量确认**：`task_reframe`
   0.0357、`roleplay` 0.0196（≥high）。这不是新发现，而是第一次有可引用的数。
2. ⚠ **`recall`(≥medium) 与 `blocked`(≥high) 差一个数量级**，`roleplay`
   0.4118 → 0.0196（21×）。**拿 ≥medium 去对 AGENTS.md 里 agent 面那条
   「block 召回 0.0000」会得出「我们其实抓到了」的相反结论** ——
   两个口径都必须报，报告的 `method.two_readings` 里写死了这条。
3. **再次证实预筛门只在规则层没声音时才省算力**：`fallback` 只调了 60% 的样本，
   召回因此比 `always` 低 0.06。生成的攻击正是规则层无声的那一类 ⇒
   「只跑 fallback」会同时得到**更慢**和**更差**的结果。

⚠ **给不了系统能力的绝对值**：生成器只能产出「我们想得到的形态」，所以这里的召回
既不是上界也不是下界，只能当**形态覆盖探针**，必须与公开集并列引用。
⚠ **可用率需要人工标注**：没有 `--labels` 时报告写「可用率未标注」，
**绝不用模型自己的判定冒充人工标注**（守护直接断言没有 `usable_share` 键）。

**踩到并修掉的两个坑**：
- 无槽位模板去重后只剩 1 条 ⇒ 「每策略 60 条」看起来生效、实际分布严重偏斜
  （agentic 6 条 vs task_reframe 56 条）。**填充策略在替我掩盖形态覆盖不足**。
  修法是补模板（每个策略 ≥6 个形态），守护 `test_every_strategy_has_enough_distinct_shapes`。
- `--from-misses` 若喂进没有 `missed` 字段的文件（如 `data/full.jsonl`），
  会把 **57% 的良性样本**一起改写并打上 `label: 1` ⇒ **凭空造出「攻击」且零报错**。
  现在退回按 `label == 1` 取种子，并在控制台说明。

### 2. OTel / Langfuse 观测接入 ✅

`prompt_ids/observability.py`（手写 **OTLP/JSON**，标准库 `urllib`，**零 SDK 零依赖**）。
接在 `Pipeline.scan`（`telemetry_enabled` 在**构造期**读一次，热路径只多一次 bool 判断），
`/v1/metrics` 新增 `observability` 段。守护 `tests/test_observability.py`（16 项）。

- **Langfuse 走同一条路**：它 v3 的摄取端点本身就是 OTLP 兼容的
  （`<host>/api/public/otel/v1/traces` + HTTP Basic），只是 endpoint 与认证头不同。
- **属性用白名单而不是黑名单**（`sanitize()` 纯函数）：只有
  `ALLOWED_ATTRIBUTES` 里的键能出网，超长值**直接丢而不是截断**（截断后的片段
  仍可能是原文的可用前缀）。黑名单会漏 `query`/`body`/`args`/`question`，
  白名单漏不掉 —— 新增属性必须先回答「这个值会不会携带原文」。
  唯一与内容相关的标识是**指纹**。
- **失败不许影响检测，也不许静默**：计数 + `degraded` 进 `/v1/metrics`，
  首次失败往 stderr 打一行（不刷屏），成功一次就清 `degraded`（不永久粘住）。
- 告警里的 endpoint 会抹掉 userinfo 与 query（有些网关把 token 放 query 里）。

### 3. 流式与 agent 轨迹可视化 ⚠️ **一半**

**agent 轨迹已做**（`prompt_ids/proxy/trajectory.py`，守护 16 项）：

`scan_segments` 以前**只保留最严重的那一段结果**，逐段判定直接丢掉 ⇒
「注入从哪一条进来的」在日志里查不到。现在每一段记
`role#index / level / action / score / pattern_id / chars / truncated / sampled / rules_only`，
落进审计事件的 `extra["trajectory"]`，看板实时面板显示 `↳ tool#2`。

⚠ **原计划被实测推翻**：我原本写「轨迹必然含原文，所以是第二个数据面，
要显式配置才落盘 + 进 .gitignore」。**不成立** —— 一条消息由 **(role, index) 就能
唯一定位**，调用方看得到自己发出去的请求。所以轨迹是**纯索引**的：
直接进审计文件，**不需要第二个数据面、不需要额外配置**，也不会把「要不要落盘」
变成一个必须记得开的开关（忘了开 = 轨迹永远是空的，而没人会知道）。
真要看内容仍然是复核语料那条路，不许往这个字段里加。

**流式实时面板未做**：代理侧的流式出站结论（告警帧、脱敏、无法撤回）已全部落审计，
看板 4s 轮询 `/v1/events` 因此能看到；但**没有做 SSE 推送面板**。
下一步若要做：`PlaygroundState` 加订阅环 + `/v1/stream`，前端登记进
`check_dashboard.py` 的 `checks`。

### 4. 容器化与 CI ✅

`Dockerfile`（三阶段：base → slim（只装 `.[speed]`+numpy，**纯规则层镜像**）→ full
（`.[semantic,speed]`，torch 走官方 CPU 源避免被换回 CUDA 版）；非 root uid 10001；
`EXPOSE 8787 8790`；`HEALTHCHECK` 用标准库 urllib 打 `/healthz`（**不装 curl**）；
**零 apt-get**）· `docker-compose.yml`（proxy/api，端口只发布到宿主回环，
`host.docker.internal:host-gateway`；**刻意不写 `depends_on`**）·
`.dockerignore` · `Makefile`（13 个目标）· `.github/workflows/ci.yml`
（windows + ubuntu 双平台、`fail-fast: false`、`permissions: contents: read`、
并发取消；`check_dashboard.py` 与 `redos_check.py` 允许失败；
额外加一条 `--rules-stats` 闸门抓「package-data 没装进去」）。

⚠ **Linux 腿未验证**（本机没 docker，双平台都没实跑过）—— CI 会替我们回答。
⚠ `ruff check` 暂设 `continue-on-error`：**基线债务 85 条**（42×F401 / 18×E741 /
11×F841 / 6×E702 / 5×F541 / 3×F811），全是历史遗留、与本轮改动无关。
当天设成闸门会让 CI 从第一天起就红，而噪声会训练人习惯性忽略红灯。**清完删掉那行。**

## 本轮顺带挖出的三个真缺陷（都不是「实现错了」，是「文档/检查说了假话」）

### ① `pip install .` 装不起来 —— 「装完 PyYAML 就能跑」是假的

`memory/store.py` 与 `memory/encoder.py` 在**模块级** `import numpy`，而
`core/pipeline.py` 传递依赖它们；numpy 只声明在 `[memory]` extra
⇒ 只装 PyYAML 时 `import prompt_ids` 直接 `ImportError: No module named 'numpy'`，
**连纯规则层都起不来**。报错只说缺 numpy，看不出跟规则层有关。

修法：numpy 移进 `[project].dependencies`（记忆层真的需要它，faiss 才该是可选）。
守护 `tests/test_minimal_install.py`：**在子进程里屏蔽全部可选依赖**
（faiss/regex/torch/transformers/sklearn/joblib），断言 import、规则层攻击判定、
API 绑定都成立。⚠ 必须用子进程 —— 本进程已经 import 过，`sys.modules` 不会因
import hook 消失。

**为什么这类缺陷静态检查抓不到**：开发机把可选依赖全装齐了，于是故障在开发机上
永远复现不出来，而它在别人的 `pip install .` 上炸。
⚠ 同类形状：**失败发生在 import 期、报错信息与真正的因果无关、本机环境恰好掩盖了它**。

### ② `check_dashboard.py` 一直是红的，AGENTS.md 记的「13/13」不成立

`indirect-body` 断言 `"0.2583" in v` —— 那是 **120 样本的旧读数**；上一轮把
`reports/indirect.json` 换成 n=250 的 0.1960 时忘了改这条断言。
所有 6 条带数字的断言都是硬编码测量值。

**失败信息长得像「这张卡片没渲染出来」**，所以很容易被当成渲染问题放过去 ——
我当时也只看了输出最后一行（「表格首行…」），没看到 `12/13`。

修法：**数字从报告现算**（`from_report()`），报告缺失时只查结构并打印提示。
现在它守的不变式才是值得守的那个 —— **看板显示的数字 == 报告里的数字**。

**教训（与「报告文件会悄悄过期」同源）**：把「看板渲染成功」与「看板数字正确」
合成一条检查时，那条检查实际上只在**数字恰好没变**时才等于后者。
硬编码测量值的检查有个共同毛病：每次重跑报告都可能变红，而红的原因与
「卡片没画出来」完全不同，看起来就像同一类故障。

### ③ `web/dashboard.py` 的 `_make_context` 用了未定义的 `ApiContext` 标注

返回标注是 `-> "ApiContext"`，而 `ApiContext` 在**函数体内** import。
有 `from __future__ import annotations` 所以运行时不会炸，但 `ruff` 报 F821，
任何运行时内省（`get_type_hints` 之类）会 NameError。已加 `TYPE_CHECKING` 块。

## 三条工程约束的审查（2026-10 复核，逐条给证据）

结论先说：**「零第三方依赖」成立且是真优势；「只绑 127.0.0.1」作为默认值成立、
作为安全承诺不成立（已修）；上手简单性合格；三者之间有一处真实冲突。**

### ① 离线看板 + 零第三方依赖 —— 成立，保留

实测（`reports/dashboard.html`，85 KB）：外链 `script/img/link/iframe` 标签 **0** 个、
文中 `http(s)` URL **0** 处、`@import` **0** 条、CSS `url()` **0** 条、
内联 `<script>`/`<style>` 各 1 块 ⇒ **真的是自包含单文件，双击即开**。

⚠ **「零第三方依赖」这个说法要限定范围**，否则会被抓：
- 项目有**硬依赖 PyYAML**（`rules/*.yaml` 要解析）。准确说法是
  「**看板与检测台的运行时零依赖**」。
- README 里那句「零第三方依赖」指的是 LLM 提供商层（21 家用标准库 `urllib`，
  确实无 SDK），两处都对，但别让人以为整个项目不用装东西。

代价（真实但可控）：不能用 CDN 的图表/字体/前端框架 ⇒ 图表自己画；
`check_dashboard.py` 需要本机有 `node`（`shutil.which` 兜底，没 node 就跳过 JS 检查）。
在离线/内网/合规环境这是决定性的，在 SaaS 环境是负担 —— 但同类（Lakera、promptfoo
的托管视图）都是必须联网的，**这是本项目唯一没被同类卷掉的差异点**。

### ② 只绑 127.0.0.1 —— 默认值成立，**作为安全承诺不成立（已修）**

审查发现的事实：

| 入口 | `--host` | 客户端鉴权 |
|---|---|---|
| `api` | 自由字符串，默认 127.0.0.1 | ✅ `PROMPT_IDS_API_KEY`（可关） |
| `proxy` | 自由字符串，默认 127.0.0.1 | ❌ **无**（`api_key` 是给上游的，客户端 `Authorization` 头**透传**） |
| `web --serve` | 自由字符串，默认 127.0.0.1 | ❌ **无**（完全没有鉴权概念） |

此前**没有任何东西拦住 `--host 0.0.0.0`**，而 `web/playground.py` 的 docstring
白纸黑字写着「只绑 127.0.0.1，不对外监听」—— **把默认值写成了保证**。
一旦有人为了「让同事看看板」改 `--host`，得到的是无鉴权的
`POST /v1/scan` + `/v1/review` + `/v1/canary/issue` + `GET /v1/events`。
代理侧的按 IP 限流与 canary 签发配额（30/分钟）**都不是鉴权**。

已修：新增 `prompt_ids/net.py`（`is_loopback` / `exposure_report` / `warn_if_exposed`），
三个入口在建 server 时都过一遍，**绑非回环且无鉴权就往 stderr 打告警**
（含暴露了什么 + 正确姿势）。告警走 stderr 是既有纪律：`--json` 的输出流必须干净。

⚠ **为什么告警而不硬拦**：容器/K8s 部署**必然**要 `--host 0.0.0.0`
（Pod 里 `127.0.0.1` 别的容器摸不到），硬拦等于让这个部署形态不可用 ——
那是另一种静默失败。守护 `tests/test_net_exposure.py`（24 项），
含一条 **docstring 不得把默认值写成保证**。

### ③ 上手简单性 —— 合格

实测冷启动：`python -m prompt_ids.cli "一句话"` **0.47s** 返回、退出码 3、
带命中规则 id 与证据引用；三个入口的 `--help` 都在 0.38s 内返回。
⇒ **零配置能跑通、当场能试一条**，这是同类项目都做的事，本项目做到了。

扣分项：
- CLI 有约 40 个 flag、`--help` 83 行 —— 第一次用的人面对一堵墙。
  可考虑加三档预设（`local-only` / `production` / `full`），
  但这是交互层缺口，**不要用加 flag 来解决**（加 flag 会更堵）。
- 本机包**未安装**，三个 console script 都不存在，只能 `python -m prompt_ids.cli`。
  装不装是环境状态不是设计缺陷，但 README 顶部要说清「先 `pip install -e .`」。

### ④ 三条约束之间有一处真实冲突（**容器化已补，安全姿势仍未给**）

「零依赖静态看板」利于离线，「只绑本机」利于安全，而「容器化部署」**同时要求两者放弃**：
Pod 里必须 `--host 0.0.0.0`，于是必然落进 ② 那个无鉴权缺口。
容器化产物本轮已补齐（Dockerfile / compose / CI，见上节 ④），compose 里端口
**只发布到宿主回环**且不设 `--api-key` 占位默认值（一个众所周知的默认值比
「没有鉴权」更糟 —— 后者会触发 `net.py` 往 stderr 打暴露面告警）。

### ④ 三条约束之间有一处真实冲突（**已给方案**）

「零依赖静态看板」利于离线，「只绑本机」利于安全，而「容器化部署」**同时要求两者放弃**：
Pod 里必须 `--host 0.0.0.0`，于是落进「无鉴权暴露面」。

**已修（不是靠反代兜着，是给三个入口都加了开关）**：
`prompt_ids/auth.py`（`X-API-Key` + `hmac.compare_digest`，与 API 共用一套），
代理 `--client-key` / `PROMPT_IDS_PROXY_CLIENT_KEY`，
检测台 `--client-key` / `PROMPT_IDS_WEB_CLIENT_KEY`，API 仍是 `--api-key` / `PROMPT_IDS_API_KEY`。
⚠ **三个 env 名刻意不同**：复用会让「我给 API 开了鉴权」被误读成三个入口都开了，
而代理的 `Authorization` 头是**透传给上游**的（它只能用 `X-API-Key` 表达自己的凭据）。
`/healthz` **不鉴权**（编排探针不带业务凭据，而它只回 `{status}`）；
看板 HTML 也不鉴权（只含实验数字，鉴权会让「拷走就能交」失效）。
守护 `tests/test_client_auth.py`（14 项）。

**方案与检查**：`deploy/nginx.conf`（**可运行的参考配置**，不是声明）·
`scripts/deploy_check.py`（逐条列三道门 + **明确写出哪些查不到**，
`--runtime` 会真起服务验鉴权行为）· 守护断言 nginx 配置里被标 ⚠ 的项：
TLS · `X-Forwarded-For`（缺它则按 IP 限流把**所有人**算成一个桶，第一个请求就耗尽额度）
· `X-API-Key` 透传 · 体积上限 · **超时 > LLM 的 p90**
（nginx 默认 60s 覆盖不住实测 p90≈40s 的长尾 ⇒ **间歇性 504 而服务日志一切正常**）。

⚠ **反代与内置鉴权是两道独立门，不要只配一道**：反代给了 TLS 但忘了透传
`X-API-Key` ⇒ 服务侧鉴权等于没开；只配服务侧鉴权不给反代 ⇒ Key 走明文。

### 5. 流式 SSE 推送面板 ✅

`prompt_ids/web/playground.py` 的 `/v1/stream` + 看板实时流面板。

- **不能用 `EventSource`** —— 它无法自定义请求头，客户端 Key 只能塞进 query，
  于是凭据会进 **nginx access log / 浏览器历史 / Referer**。
  改用 `fetch` + `ReadableStream` 手动解析 SSE 分帧（多 30 行 JS）。
- 事件环 50 条 + **心跳 15s**（不是装饰：反代与浏览器都会掐空闲连接，
  而没有心跳的 SSE **看起来一切正常，直到某天开始静默停止推送**）+
  连接存活上限 900s（让前端自己重连，而不是静默卡死）。
- `last_seq` 重连**补发**错过的事件。
- 事件**不含原文**（审计/遥测/看板之后是**第四处**边界，而它最容易被忘）。

⚠ 实现时踩到三个坑，每一个都是「静默」形态：

1. **`_lock` 必须 `RLock`**：SSE 等待方在 `with self.changed:` 里调
   `events_since()`，而 Condition 用的就是这把锁 ⇒ 普通 Lock **自死锁**，
   现象是「hello 帧正常、之后一个事件都不推」，**零报错**。
2. **推送延迟**：初版拿心跳间隔当轮询间隔 ⇒ 一次检测最坏等 15 秒才出现，
   **那不叫实时**。改成事件驱动（Condition `notify_all`）。
3. **流式面板只能在服务可用时启动**：无条件启动的无限重连循环会让
   `check_dashboard.py` 的 node **无法退出**（实测超时 90s）。
   ⚠ 这不是测试环境问题 —— 任何离线场景都会挂着一个不结束的循环。

### 6. 转写/翻译的响应侧文本 ✅

`prompt_ids/proxy/passthrough_out.py`。`/v1/audio/transcriptions`、
`/v1/audio/translations` 的**输出**是模型生成的文本，而此前**只扫输入**
（输入是音频字节，没有文本）⇒ 那段文本从未被检查。而**音频注入是已知的弱面**
（Whisper 类模型对抗样本），不是理论风险。

- 判定复用 `scan_segments`（不写第二套），角色名 `transcript`。
- **不修改响应体**：内容已经发出去了，悄悄改写会让调用方拿到
  一句「用户没说过的……」而毫无察觉。只判定、只记账。
- 结论落 `extra["transcript_scan"]`，与请求侧 `decision` **正交**
  —— 请求放行了但转写被判注入，只看 decision 会漏掉。

⚠ 同样抓到两个「静默」形态：

1. 音频转写的请求体**就是 multipart**（不是 JSON）⇒ 总是走
   `if not payload` 分支。第一版在那里 `return` 了 ⇒ **响应侧检查永远没机会跑**，
   被 `tests/test_transcript_scan.py` 当场抓到。
2. **审计必须早于响应落盘**：先回响应再落审计 ⇒ 客户端可能先看到 200
   而审计还没写进文件。拆出 `_fetch_passthrough()`（只取回不写），
   顺序改成 取回 → 检查 → 落审计 → 再回客户端。

### 7. token id 形态的 `input` ✅

`extract_passthrough_segments` 现在返回第四项 `input_kind`
（`text` / `token_ids` / `mixed` / `empty` / `no_text_field` / `not_json`），
落进审计 `extra["input_kind"]`。

- 扫不了是事实，但**必须可查** —— 否则「全是 token id 所以没扫」
  与「扫了没命中」在统计上长得一样，运维看到「没有命中」会以为那段内容干净。
- **`mixed` 最容易骗人**：`scanned: true`、「扫了 1 段」看起来一切正常，
  而另一半内容根本没人看过 ⇒ 即使扫过也必须记形态。
- 顺带把 `PASSTHROUGH_NO_TEXT` 里「未覆盖」这种**半承诺**改掉了
  —— 要么说清为什么扫不到，要么给出**已经做完**的配套动作。

### 8. 仍未修

1. **Linux CI 腿未实跑** —— 本机无 docker，双平台都没跑过。CI 会替我们回答。
2. **流式转写（`stream: true`）的响应侧未覆盖** —— 逐帧 delta 走 SSE 通路，
   与「拿到整个响应体再扫」是两套代码。已在 `passthrough_out.py` 的
   docstring 里**明写 `not_checked`**（守护
   `test_streaming_transcription_is_declared_as_unchecked` 钉的就是这一条）。

- **CI 已补**（双平台矩阵）。⚠ Linux 腿未验证。
- ⚠ **`AGENTS.md` 现在入库了**（用户 2026-10 决定）⇒ 引用纪律与方法学
  随 clone 一起走，「可复现」不再只在本机成立。
  ⚠ 代价：这份文件含本机路径、临时脚本位置、以及大量「实测数字」。
  **数字会过期** —— 任何一条被重跑推翻时，要改的是**本文档**，
  而不是让下一个人去猜哪条是旧的。

## 与同类系统的对比口径

- **交互能力**：同类项目（Vigil 的 Streamlit playground、Rebuff 的托管 Playground、ProtectAI
  LLM Guard 只有 CLI/中间件、NeMo Guardrails server+demo、promptfoo `promptfoo view` 网页端、
  Lakera/Check Point 的 dashboard + Policy Impact Simulator、LiteLLM 的 pre/post/during_call
  guardrail 代理）都把「能当场试一条」当标配。本项目的对位物是
  「静态离线看板 + 在线检测台（单条 / 批量 ≤200 / 判定对比 / 人工复核 / 出站扫描）
  + `--serve` 下 4s 轮询 `/v1/metrics` + `/v1/events`」。差异化优势：看板与检测台运行时
  零第三方依赖（**项目本体仍有 PyYAML 硬依赖，别说成零依赖**）、纯静态可离线拷走、
  默认只绑 127.0.0.1（**默认值不是保证，见上文 ②**）、检测→强制切换用四档 policy 显式表达。
  明确缺口：~~离线阈值标定/影响模拟~~ **已补（2026-10，见「阈值标定与策略影响」一节）** ·
  **攻击生成与红队闭环** · 多用户 RBAC / 团队共享 ·
  OTel/Langfuse 观测接入 · 流式与 agent 轨迹可视化 · 容器化与 CI
  ⇒ 这四项已立为**下一阶段任务**（见上一节）。
  → 交互能力只能比「在场 / 缺席」与工程约束，**不要给交互编数字**。
- **维护状态会改变定位**（2026-10 核查，README 引用其功能时必须带状态）：
  **ProtectAI LLM Guard 与 Rebuff 均已归档**，不再维护；**promptfoo 已被 OpenAI 收购**
  （仍开源 MIT）。⇒ 「开源自托管护栏」这个位置在变空，对本项目是机会；
  但也说明这类项目的维护风险真实存在，**引用任何同类的数字前先看它是否还活着**。
- **检测能力**：唯一能做同口径对比的公开数字在 **deepset 数据集**上（PALIT, arXiv:2505.13028
  在该数据集上发表了各家数字）。把本项目 `by_source` 的 `deepset_train+test` 合并
  （263 攻击 / 399 正常，阈 `high/critical`）：

  | 配置 | P | R | F1 | FPR |
  |---|---|---|---|---|
  | L1 仅规则 | 1.000 | 0.183 | 0.309 | 0.000 |
  | +L3 DeBERTa（fallback） | 0.966 | 0.426 | 0.591 | 0.010 |
  | +L3 LLM（always） | 0.995 | 0.780 | 0.874 | 0.003 |
  | L3 仅语义（LLM） | 0.995 | 0.772 | **0.869** | 0.003 |
  | *ProtectAI LLM Guard（同款 DeBERTa 权重，他人论文）* | *0.964* | *0.414* | *0.579* | *0.010* |
  | *Vigil / Rebuff / Lakera Guard（他人论文）* | *0.959 / 0.633 / 0.984* | *0.452 / 0.756 / 0.707* | *0.615 / 0.689 / 0.823* | *0.012 / 0.288 / 0.007* |

  读法：① DeBERTa 配置**复现了参考实现**（0.591 vs 0.579）⇒ 评测口径本身可信；
  ② LLM 裁判配置在 F1/FPR 上已越过 Lakera Guard 的公布值；
  ③ **规则层在 deepset 上几乎没有召回贡献**（L1 0.183 → 补完 13 条多语种规则后 0.183，
  garak 上 0.132→0.421 但 deepset_train/test 基本不动）。**原因已查清**（见「实验口径」第 0 条）：
  约 70% 的 deepset「攻击」是角色扮演/任务改写型，对短语匹配召回≈0。
  ⇒「留规则层」只能用 2ms / 可解释 / 短路 critical 论证，不能用召回。
  ⚠ 斜体行是**他人论文数字**，阈值、系统提示上下文、是否最优配置都不完全一致，
  引用必须写来源，且不得与他人口径相减后宣称「超过」。
- **规则层的真实能力边界**（2026-10 实测，PINT 形状基准，生产默认短路）：
  留出集（未参与设计的语种/模板）召回 0.6032 / 误报 0.0000；**仍为零覆盖的类别**
  `role_tag_escape`（de/ja）· `system_prompt_extraction`（de）· `obfuscation`（zh/es 半数）。
  规则擅长的是「英文指令 + 少量德/中/法/西/日常见句式」，不擅长的是叙事包装与
  非英语的深层改写 —— 后者只能靠 L3/记忆层，这就是分层的实证依据。
- **未测的同类基准**（要下更强结论必须先跑）：InjecGuard/NotInject（过度防御）·
  Agent-Dojo 的**完整 agent 回路**（本项目只用了它的任务文本，见「agent 面」一节）·
  InjecAgent。Lakera PINT 的正文不公开，已改为「PINT 形状」自建基准
  （`scripts/build_pint_shape.py`），可与公布分比形状与失分结构，**不能相减**。
- 结构性缺口：~~agent/RAG 间接注入面~~ **已部分补上（2026-10，见「代理检测面」一节）**
  —— `tool`/`function` 内容现在会扫，规则层实测 block 召回 0.0000 → **0.1960**
  （n=250 公开集攻击；⚠ 早前引用的 0.2583 来自 **120 条**样本的旧报告，
  样本加大后各项都降 0.02~0.07，说明旧读数偏乐观，**引用一律用 n=250 这组**），
  代价是「引用攻击样例的文档」类误报 0.0250。**仍未测**：Agent-Dojo / InjecAgent。
  剩下的缺口：~~输出侧扫描（仅 Canary）~~ **已补（2026-10，见「出站密钥扫描」一节）** ·
  PII 与有害内容扫描 · 攻击生成与红队闭环（promptfoo 模式）· 多租户与观测集成。
- 引用纪律：自建 85 条种子集数字**一律不得外推**；LLM 后端数字须注明第三方网关
  （glm-4.5-flash，≈19s/条，14–20 条超时弃权）。
- **Lakera PINT 数据不公开**（仓库只有 `example-dataset.yaml` + 打分 notebook，4,314 条正文未放出）。
  可对齐的是它的**分布与 schema**：`prompt_injection` / `jailbreak` / `chat` / `documents` /
  `hard_negatives` / `short_input` / `benign_input`，攻击只占 6.1%（良性 93%），24 语种。
  组装语料的公开来源：`Lakera/gandalf_ignore_instructions`、`mik0w/pallms`。
  引用 PINT 公布分（同款 DeBERTa 79.1%、Lakera Guard 95.2%）时必须注明「不同数据集，绝对值不可直接相减」。
- **PINT 形状基准已落地**（2026-10）：`scripts/build_pint_shape.py` → `data/pint_shape_{train,test,full}.jsonl`
  （5243 条，攻击 6.5%，6 语种 en/zh/de/fr/es/ja）+ `scripts/eval_pint_shape.py` → `reports/pint_shape.json`。
  两个口径别混用：`pint_shape_*` 量**良性主导分布下的过防御**，`pint_recall.jsonl`（`--profile recall`）
  量**分语种召回**。切分是**模板级**的（`_split_of` 槽位规则，与语种数量无关）——
  踩过 `lang_i % 10 < 7` 在 6 个语种时把全部良性塞进 train 的坑，`tests/test_pint_shape.py` 钉死。
  外部源（`gandalf` / `pallms`）**一律只进 test**：它们是同义改写集合，按行号切分会让
  「同一基础攻击的改写」横跨两侧，看着像泛化其实是泄漏。
- 该基准的**原始**读数（补规则前，规则层 L1+L2，block 口径，5562 条）：良性过防御极低
  （documents 4948 条 FPR 0.0000 · hard_negatives 0.0139），但攻击召回集中在少数类别 ——
  gandalf 0.576 / instruction_override 0.500 / pallms 0.393，而 obfuscation·privilege_escalation·
  role_tag_escape·system_prompt_extraction·tool_injection 与三类越狱包装**全为 0**；
  分语种 en 0.473 / de 0.139 / zh 0.139 / fr·es·ja 0.000。补完 13 条规则后
  留出集 0.2652→**0.6032**、误报 0.0000，garak 0.132→**0.4211**（见「规则层」小节）。
- **规则层当前 83 条**（critical 26 / high 34 / medium 23），语言覆盖中/英/德/法/西/日。
  下一批增量按留出集零覆盖清单走：`role_tag_escape`（de/ja）· `system_prompt_extraction`（de）
  · `obfuscation`（zh/es）。⚠ 这三类的留出样本已经「看过」，补规则时必须**声明它们已被烧掉**。

## 常用命令

```powershell
cd E:/Code/Ai-guard
python -m pytest -q                                   # 728 项（见「测试」）
python -m prompt_ids.cli --rules-stats                # 83 条规则 + 当前引擎
python -m prompt_ids.cli --probe                       # 实际生效的后端（首行）+ 21 家提供商可用性
python -m prompt_ids.cli --list-providers / --list-models deepseek
python -m prompt_ids.cli --semantic --semantic-backend custom --semantic-mode always "测试文本"
python scripts/llm_check.py --provider custom          # 0 通 / 2 未配 Key / 1 失败
python scripts/smoke.py ; python scripts/bench.py ; python scripts/check_dashboard.py
```

重建报告产物：

```powershell
python scripts/eval_semantic.py --dataset data/full.jsonl        # 主报告 ablation.json（不加 --only 才有 4 个来源的 by_source）
python scripts/eval_semantic.py --only --dataset data/full.jsonl --semantic-backend custom --out reports/ablation_llm.json
python scripts/indirect_check.py                          # 间接注入面取证 -> reports/indirect.json
python scripts/build_agent_bench.py --no-download          # agent 面语料（Agent-Dojo，离线重建）
python scripts/agent_check.py --semantic --semantic-backend local   # agent 面评测 -> reports/agent_check.json
python scripts/output_check.py                                     # 出站密钥扫描取证 -> reports/output_scan.json
python scripts/threshold_sweep.py                                 # 阈值标定 + 四档策略影响 -> reports/threshold_sweep.json
python scripts/build_overrefusal.py                              # 过度防御语料（OR-Bench+XSTest，需联网）
python scripts/overrefusal_check.py                              # 误伤评测（纯 FP 侧）-> reports/overrefusal.json
python -X utf8 -m prompt_ids.cli --scan-output "模型输出片段"        # 出站扫描（退出码 3 = 发现凭据）
python -m prompt_ids.audit review logs/audit.jsonl            # 复核台账 + 规则级嫌疑榜
python scripts/review_mined.py --corpus data/review_corpus.jsonl      # 复核语料 -> 规则调优语料
python scripts/train_lightweight.py --only --dataset data/full.jsonl --holdout deepset_test   # 唯一正确的重训命令
python -m prompt_ids.web                                               # 重建 reports/dashboard.html
```

PINT 形状基准（外部攻击源需已下载到 `data/raw/`，否则响亮失败并打印 URL）：

```powershell
python scripts/build_pint_shape.py                    # -> data/pint_shape_{train,test,full}.jsonl + pint_shape_meta.json
python scripts/build_pint_shape.py --profile recall --attack-ratio 0   # -> data/pint_recall.jsonl
python scripts/eval_pint_shape.py                     # 默认只跑规则侧（零调用），-> reports/pint_shape.json
python scripts/eval_pint_shape.py --dataset data/pint_recall.jsonl --out reports/pint_recall.json
```

`train_lightweight.py` 裸跑（不带 `--dataset` 且写默认路径）会**拒绝执行并退出 2** —— 它只会拿 85 条
内置种子集训练却覆盖 `models/lightweight.joblib`。要小跑须显式 `--force` 或 `--out` 到临时路径。
