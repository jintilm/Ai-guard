# ============================================================================
# prompt-ids 常用命令
#
#   make            # 等价于 make help
#   make test       # 跑全部单测
#   make check      # CI 在本地的那一遍（lint + test + smoke）
#
# ⚠ 本文件**不假设 make 存在**。它是给 CI（ubuntu-latest 自带 make）与
#   Linux/macOS 开发机用的便捷封装；Windows 上没装 make 时，
#   每条目标后面的注释就是可直接粘的命令。
#
# ⚠ 关于 pyproject.toml 的 addopts = "-q"：
#   **命令行不要再叠 -q**。叠了会变成 -qq，pytest 连 "N passed" 总结行一起吞掉，
#   于是「全绿」和「一个都没跑」在输出里长得一模一样。
#   判全绿看退出码，别盯总结行；数用例用 pytest --collect-only -q。
# ============================================================================

PYTHON ?= python

.DEFAULT_GOAL := help
.PHONY: help install install-dev test lint smoke check-dashboard redos \
        dashboard check docker-build docker-up docker-down clean

## ---------------------------------------------------------------- 帮助 ----
help: ## 列出所有目标
	@echo "prompt-ids —— 常用命令"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "  不装 make 的话，每条目标下方的注释就是可直接粘的命令。"

## ------------------------------------------------------------ 安装依赖 ----
install: ## 装核心依赖（PyYAML）
	$(PYTHON) -m pip install -e .

install-dev: ## 装开发依赖（pytest / ruff / regex）
	$(PYTHON) -m pip install -e ".[dev,speed]"

## ------------------------------------------------------------ 质量闸门 ----
test: ## 跑全部单测（pyproject 的 -q 已够，勿再叠 -q）
	$(PYTHON) -m pytest

lint: ## ruff 静态检查
	$(PYTHON) -m ruff check .

smoke: ## 端到端冒烟：期望「检出 10/10，误报 0/6」
	$(PYTHON) scripts/smoke.py

check-dashboard: ## 看板自检（用真 JS 引擎；本机没 node 会优雅跳过）
	$(PYTHON) scripts/check_dashboard.py

redos: ## 规则层对抗输入耗时上界（偏机器性能，CI 里允许失败）
	$(PYTHON) scripts/redos_check.py

## ------------------------------------------------------------ 产物生成 ----
dashboard: ## 生成 reports/dashboard.html（静态单文件，可离线双击打开）
	$(PYTHON) -m prompt_ids.web

## -------------------------------------------------------- 一把梭（本地）----
check: lint test smoke ## CI 在本地的那一遍：lint + test + smoke

## -------------------------------------------------------------- 容器 ----
docker-build: ## 构建两个镜像（full 默认 + slim）
	docker build -t prompt-ids:latest --target full .
	docker build -t prompt-ids:slim   --target slim .

docker-up: ## 起 proxy(8787) + api(8790)
	docker compose up -d --build

docker-down: ## 停掉（加 -v 连审计卷一起清）
	docker compose down

## -------------------------------------------------------------- 清理 ----
# ⚠ 刻意**不删** reports/ 与 logs/：
#   reports/ 是本机测量证据（本项目的结论全靠它，改默认值前要先留证据）；
#   logs/   是审计日志（只记指纹不记原文），删掉就没了。
#   想清请显式动手：rm -rf reports logs
clean: ## 清理缓存与构建残留（保留 reports/ 与 logs/）
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache .mypy_cache .coverage htmlcov
	rm -rf build dist *.egg-info
	@echo "已清理缓存。注意：reports/ 与 logs/ 刻意保留（测量证据 / 审计日志）。"