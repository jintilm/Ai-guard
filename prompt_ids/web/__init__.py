"""Web 看板子包。

    python -m prompt_ids.web                        # 生成静态快照
    python -m prompt_ids.web --serve --port 8765    # 实时刷新
"""
from prompt_ids.web.dashboard import build, collect, render_html

__all__ = ["build", "collect", "render_html"]
