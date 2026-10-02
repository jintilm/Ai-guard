# ============================================================================
# prompt-ids 容器镜像
#
# 两个 build target，用 `--target` 选：
#
#   --target full   完整镜像（GB 量级）。装了 .[semantic,speed]，
#                   能跑 L3 的**本地** DeBERTa 语义层。
#   --target slim   轻量镜像（百 MB 量级）。只装 .[speed]（PyYAML + regex + numpy），
#                   **不跑**本地语义层，纯 L1 规则 + L2 启发式，约 2ms/条。
#
#   ⚠ 上面那两个体积数字是**量级估计，不是实测值**：写这份文件时本机没装 docker。
#     真要对外报数字，请先 `docker images` 看一眼再写。
#
#   docker build -t prompt-ids:full  --target full .
#   docker build -t prompt-ids:slim  --target slim .
#   docker build -t prompt-ids .            # 不带 --target ⇒ full（最后一个 stage）
#
# ⚠ 关键取舍，别读错「轻量镜像」：
#   slim 缺的是**本地模型**（transformers/torch），**不是语义层本身**。
#   LLM 裁判后端只用标准库 urllib 调 HTTP，零额外依赖 ——
#   所以 slim 镜像里设一个 OPENAI_API_KEY，照样能 `--semantic` 打开 L3，
#   只是走云端裁判（实测 ≈10s/条）而不是本地 219ms。
#   反过来，full 镜像**不配任何 Key 时**，`auto` 会选 local（本地权重），
#   那是 2GB 镜像存在的理由。
#
# ⚠ 两个 stage 的 CMD 都是 proxy（默认端口 8787）。要跑 API：
#   docker run --rm -p 8790:8790 -e PROMPT_IDS_API_KEY=... prompt-ids \
#     prompt-ids-api --host 0.0.0.0
#   `--host 0.0.0.0` 会触发 prompt_ids/net.py 的暴露面告警（stderr）。
#   **那不是故障，是设计**：容器里必须绑 0.0.0.0（Pod 内 127.0.0.1 别的容器
#   摸不到），而 net.py 拒绝硬拦（非回环 + 无鉴权就告警，见该模块 docstring）。
#   补偿手段在宿主机侧做：只把端口发布到宿主回环（`-p 127.0.0.1:8787:8787`），
#   或者前面放一层做 TLS + 鉴权的反向代理。见 docker-compose.yml。
# ============================================================================

# --- 全局构建参数（只在第一个 FROM 之前声明的能用在 FROM 行）---------------
ARG PYTHON_VERSION=3.11
ARG BASE_IMAGE=python:${PYTHON_VERSION}-slim-bookworm


# ----------------------------------------------------------------------------
# base —— 两个运行 stage 共享的环境与用户
# 不装任何编译工具：PyYAML / regex / numpy / torch / transformers /
# scikit-learn / joblib 在 cp311 linux 上都有预编译 wheel，
# 所以**不需要** gcc（也就不需要 apt-get 装东西）。
# ----------------------------------------------------------------------------
FROM ${BASE_IMAGE} AS base

# 固定 uid/gid 而不是随机生成：K8s 里 random uid + bind mount 目录会写不进去。
ARG APP_UID=10001
ARG APP_GID=10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HOME=/home/appuser/.cache/huggingface

# HF_HOME 放在 appuser 家目录下（而不是 /root/.cache）：非 root 写不进去，
# 结果是每次启动都重新下载 700MB 权重 —— 而且不会报错，只会一直等。
WORKDIR /app

# useradd 属于基础镜像自带的 shadow-utils，不是额外装的依赖。
RUN groupadd --gid ${APP_GID} appuser \
 && useradd --uid ${APP_UID} --gid ${APP_GID} --create-home --shell /usr/sbin/nologin appuser

# 审计日志与报告目录：先建好并交给 appuser，
# 这样 compose 里挂**命名卷**（named volume）时 Docker 会把镜像内的属主复制过去，
# 非 root 进程直接就能写。换成宿主机 bind mount 就不成立（目录属主是 root），
# 需要宿主机侧 chown —— 这是 bind mount 唯一的真实成本。
RUN mkdir -p /var/log/prompt-ids /app/reports \
 && chown -R appuser:appuser /var/log/prompt-ids /app/reports

EXPOSE 8787 8790

# --- 健康检查 ---------------------------------------------------------------
# 用 python 标准库 urllib，**不装 curl**（slim 镜像没有，装它要多一个系统包）。
# 探哪个服务由 PROMPT_IDS_HEALTHCHECK_URL 决定：
#   * 默认（镜像自带 CMD 是 proxy）→ 8787/proxy 的 /healthz
#   * 跑 api 时                     → 8790 的 /healthz
# ⚠ api 的 /healthz **也要鉴权**：配了 PROMPT_IDS_API_KEY 时，
#   api/server.py 的路由分发对**所有**路由（含 /healthz）统一校验，
#   漏了 Key 会拿到 401 —— 健康检查于是永远红，而服务其实是好的。
#   所以这里按需带上 X-API-Key 头。proxy 的 /healthz 不需要鉴权（它没有鉴权概念）。
# 两个服务的 /healthz 都返回 {"status": "ok", ...}，所以下面校验响应体而不只看状态码
# —— 「返回 200 但不是健康 JSON」在网关场景里真的发生过。
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import json, os, urllib.request as u\nurl = os.environ.get('PROMPT_IDS_HEALTHCHECK_URL', 'http://127.0.0.1:8787/healthz')\nkey = os.environ.get('PROMPT_IDS_API_KEY', '')\nreq = u.Request(url)\nif key: req.add_header('X-API-Key', key)\nbody = u.urlopen(req, timeout=4).read()\nraise SystemExit(0 if json.loads(body).get('status') == 'ok' else 1)"]


# ----------------------------------------------------------------------------
# slim —— 轻量镜像：L1 规则 + L2 启发式，不带本地语义模型
# ----------------------------------------------------------------------------
FROM base AS slim

# ⚠ 这里必须显式补 numpy，**这不是加需求，是补一个 pyproject.toml 的声明漏洞**：
#   prompt_ids/memory/encoder.py 在**模块级** `import numpy`，
#   而 prompt_ids/core/pipeline.py 在模块级 `from prompt_ids.memory.detector import MemoryDetector`，
#   于是 `pip install .`（只带 PyYAML）之后 `import prompt_ids` 直接 ImportError。
#   numpy 只被声明在 [memory] extra 里，但它其实是**导入期硬依赖**。
#   正确的修法是把 numpy 挪进 `dependencies`（一行改动），这里先绕过，
#   否则轻量镜像根本起不来。修好之后这一行可以删。
#   （已实测：只装 PyYAML+regex+numpy，规则层判定正确，攻击 critical / 良性 safe。）
RUN pip install --no-cache-dir numpy

COPY pyproject.toml README.md ./
COPY prompt_ids ./prompt_ids
COPY scripts ./scripts
COPY data ./data

# speed extra = regex。对 `re` 是**纯加速**不是必需（实测中文长文本 4.8×，
# 公开集 1.15×，结果与 re 逐条一致）；不装会自动退回标准库 re，只是慢些。
# 这里仍装上：镜像大不了几百 KB，而 slim 镜像的卖点就是快。
RUN pip install --no-cache-dir -e ".[speed]"

USER appuser

# 上游地址**不写死在命令行**：`proxy/server.py` 在 --upstream 为空时按
# PROMPT_IDS_UPSTREAM → OPENAI_BASE_URL → 厂商约定名 → 注册表默认 的顺序读环境变量，
# 所以 `docker run -e PROMPT_IDS_UPSTREAM=...` 就能改，不必重建镜像。
#
# --audit 落 /var/log/prompt-ids（**只记指纹不记原文**，见 audit/logger.py），
# 容器重建后审计不会跟着丢，但要用命名卷才会真的持久化，见 docker-compose.yml。
CMD ["prompt-ids-proxy", "--host", "0.0.0.0", "--port", "8787", \
     "--audit", "/var/log/prompt-ids/proxy.jsonl"]


# ----------------------------------------------------------------------------
# full —— 完整镜像：装 .[semantic,speed]，能跑 L3 本地语义层
#
# ⚠ 放在**最后**：docker build 不带 --target 时构建最后一个 stage，
#   所以 `docker build -t prompt-ids .` 默认得到完整镜像（tag 建议也因此叫 latest）。
# ----------------------------------------------------------------------------
FROM base AS full

# torch 从官方 CPU 源装。PyPI 上的默认 torch 会拖进一整套 CUDA 依赖，
# 体积多一个量级（GB 级 vs 200MB 级），而部署侧几乎不需要 GPU 推理。
# 要 GPU 版就把这个 ARG 改成 https://pypi.org/simple（会拉 CUDA wheel）。
# 单独装一次是为了让 pip 认出 torch 已满足 —— 否则后面 `.[semantic]` 会把它换回 CUDA 版。
ARG TORCH_INDEX_URL=https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir --index-url ${TORCH_INDEX_URL} torch

COPY pyproject.toml README.md ./
COPY prompt_ids ./prompt_ids
COPY scripts ./scripts
COPY data ./data
RUN pip install --no-cache-dir -e ".[semantic,speed]"

# 可选：构建期就把本地语义权重拉进镜像。
# 默认**关**，两个理由：
#   1) 它让构建依赖 huggingface.co 可达 —— 构建失败与代码无关，不好排查；
#   2) 本地模型默认从 HF 缓存读，运行时缺权重会退回 lightweight/NullBackend，
#      而这是**静默降级**（L3 悄悄不生效，分数看起来仍然正常）。
# 生产镜像建议开（--build-arg PREFETCH_MODEL=1），把降级可能性消灭在构建期。
# HF_ENDPOINT 显式给值是为了盖掉 scripts/fetch_model.py 里的
# os.environ.setdefault("HF_ENDPOINT", "hf-mirror.com") 默认值 —— 那是给本机内网用的，
# 不该被带进镜像。
ARG SEMANTIC_MODEL=protectai/deberta-v3-base-prompt-injection-v2
ARG PREFETCH_MODEL=0
RUN if [ "${PREFETCH_MODEL}" = "1" ]; then \
        mkdir -p "${HF_HOME}" && chown -R appuser:appuser /home/appuser/.cache && \
        HF_ENDPOINT="${HF_ENDPOINT:-https://huggingface.co}" \
        HF_HUB_DISABLE_XET=1 \
        python scripts/fetch_model.py --no-verify --model "${SEMANTIC_MODEL}"; \
    fi

USER appuser

CMD ["prompt-ids-proxy", "--host", "0.0.0.0", "--port", "8787", \
     "--audit", "/var/log/prompt-ids/proxy.jsonl"]