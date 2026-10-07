# 第三方数据集：来源与许可

本仓库在 `data/` 下**转发**了若干第三方公开数据集的原始文件（`data/raw/`
与 `data/*.parquet`），目的是让本项目的评测结果**可复现** —— 不联网也能重跑
同一批数字。

**本项目自身的代码是 MIT（见 `LICENSE`），但下面这些数据集各有自己的许可，
转发它们必须按各自的条款来。** 引用本项目的数字时可以忽略本文件；
要**再分发这些数据**（例如打进你自己的产品或再公开一次），请先读对应许可。

| 数据集 | 本仓库路径 | 上游 | 许可 |
|---|---|---|---|
| deepset Prompt Injection Collection | `data/deepset_{train,test}.parquet` | [`deepset/prompt-injections`](https://huggingface.co/datasets/deepset/prompt-injections) | Apache-2.0 |
| NVIDIA garak 提示语料 | `data/raw/garak_prompt_data.py` | [`NVIDIA/garak`](https://github.com/NVIDIA/garak) | Apache-2.0 |
| Agent-Dojo 套件与注入向量 | `data/raw/agentdojo/` | [`ethz-spylab/agentdojo`](https://github.com/ethz-spylab/agentdojo) | MIT |
| OR-Bench（过度拒答基准） | `data/raw/bench-llm__or-bench__or-bench-hard-1k.csv` | [`bench-llm/or-bench`](https://huggingface.co/datasets/bench-llm/or-bench)（arXiv:2405.20947） | CC-BY-4.0 |
| XSTest（safe 半边） | `data/raw/jkminder__xstest-overrefusal__*.parquet` | [`jkminder/xstest-overrefusal`](https://huggingface.co/datasets/jkminder/xstest-overrefusal) | CC-BY-4.0 |
| Lakera Gandalf | `data/raw/gandalf__*.parquet` | [`Lakera/gandalf_ignore_instructions`](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions) | MIT |
| palMPS | `data/raw/pallms_promptinjection.txt` | [`mik0w/pallms`](https://github.com/mik0w/pallms) | 见上游仓库 |

## 两套 CC-BY-4.0 的署名要求

OR-Bench 与 XSTest 是 **CC-BY-4.0**，除转发外还要求**署名**：

- OR-Bench：Pawel Pelka, Szymon Łucki et al., *Towards Understanding Sycophancy
  in Language Models*, arXiv:2405.20947
- XSTest: Typed LLM Testing / Röttger et al., *A Taxonomy of LLM Safety
  Vulnerabilities*（原 XSTest 套件，见该镜像的数据卡）

## 派生产物不是上游数据

下面这些是**本项目生成的**，版权归本项目（MIT），但**里面含有上游数据的
内容**，再分发时上面那些条款同样适用：

- `data/pint_shape_{train,test,full}.jsonl`（按 PINT 的**分布与类别**自建，
  外部攻击源 gandalf / palMPS 原样并入 —— 许可同上表）
- `data/overrefusal.jsonl`（OR-Bench + XSTest 归一化后的结果）
- `data/redteam.jsonl`（**本项目自写的模板生成**，不含任何第三方内容）
- `data/public_*.jsonl`、`data/full.jsonl`（上述数据集的归一化子集）
- `reports/*.json`（测量结果；`overrefusal.json` 的 `examples_fp` 字段含
  OR-Bench 的**原始提示文本**，CC-BY-4.0）

## 没被转发的

- **Lakera PINT 正文不公开**（官方只放出 `example-dataset.yaml` 与打分
  notebook）。本仓库对齐的是它的**分布与类别**，不是它的数据 —— 所以
  本项目与 PINT 的分数**不可直接相减**。
- **XSTest 的 unsafe 半边**故意不收：本项目是注入检测器、不是内容过滤器，
  把有害内容请求判成攻击不算检测成功。