"""守护：SSE 连接被客户端断开时**不得产生任何 stderr 输出**。

## 这条守护钉住的是 CI 上真实发生过的事（2026-10）

浏览器关标签页时，Windows 抛的是 **`ConnectionAbortedError`**
（WinError 10053），**不是** `ConnectionResetError`。

只捕 `(BrokenPipeError, ConnectionResetError)` 时，SSE 心跳那次 write 会把
异常抛到 `socketserver.process_request_thread`，后果有两层：

1. 每个跑过 SSE 的测试 stderr 都多出一整段 traceback —— CI 日志里刷屏的噪声；
2. 断言「stderr 为空」的守护随之失败，而它报出来的位置是
   **`test_net_exposure.py`**，完全指不到真正的原因 ——
   这正是本项目反复在修的那类「报错指不到真因」。

## 为什么必须显式列出 ConnectionAbortedError

Windows 与 POSIX 在这一处**不等价**：POSIX 抛 BrokenPipe/ConnectionReset，
Windows 额外抛 ConnectionAbortedError。只按本机（Windows）测的话，
这段代码在 Linux 上看起来是对的 —— 而 CI 有 ubuntu 腿，等它跑到时才炸。
所以这里**直接构造那个异常**去撞处理器，不依赖平台差异。
"""

def test_client_gone_covers_windows_connection_aborted():
    """`_CLIENT_GONE` 必须包含 Windows 特有的 ConnectionAbortedError。

    直接断言常量内容 —— 这是「结构约定」，靠行为测试只能覆盖当前平台。
    """
    from prompt_ids.web.playground import _CLIENT_GONE

    assert ConnectionAbortedError in _CLIENT_GONE, (
        "Windows 上客户端断开抛的是 ConnectionAbortedError（WinError 10053），"
        "漏掉它会让 SSE 心跳的 write 抛到 socketserver —— CI 上表现为"
        "每个测试 stderr 多出 traceback，并连带打挂「stderr 必须为空」的守护")
    assert BrokenPipeError in _CLIENT_GONE
    assert ConnectionResetError in _CLIENT_GONE


def test_stream_events_swallows_client_disconnect(monkeypatch):
    """`_stream_events` 遇到客户端断开必须**安静退出**（不抛、不打栈）。

    ⚠ 刻意**不**起真服务器、也不构造完整 `PlaygroundState`
    （它要 `ctx` + `dashboard_path`）：那会把这条守护变成端到端冒烟测试，
    起服务、装依赖、抢端口，任何一环出问题都会**报成与本条无关的错**
    （本项目在「报错指不到真因」上已经吃过多次亏）。

    这里只把依赖压到最小：`_write_sse` 必抛、`state` 是几行桩，
    时间上界 `STREAM_MAX_S` 调到 0 让循环立刻结束 ——
    于是**第一次 write 就抛**，正好测「异常有没有被 `_CLIENT_GONE` 吃掉」。
    """
    import urllib.parse

    from prompt_ids.web import playground
    from prompt_ids.web.playground import Handler

    class _RaisingWriter:
        def write(self, _data):
            raise ConnectionAbortedError(10053, "simulated: connection aborted")

        def flush(self):
            pass

    class _Stub:
        """够 `_stream_events` 跑起来的最小桩。"""

        seq = 0

        def __init__(self):
            import threading

            self.changed = threading.Condition()

        def events_since(self, since):
            return []

    class _H(Handler):
        def __init__(self):           # 故意不调 super()：需要真 socket
            self.wfile = _RaisingWriter()
            self.close_connection = False
            self.state = _Stub()

        def send_response(self, code, message=None):
            pass

        def send_header(self, key, value):
            pass

        def end_headers(self):
            pass

    monkeypatch.setattr(playground, "STREAM_MAX_S", 0.0)

    handler = _H()
    parsed = urllib.parse.ParseResult(
        path="/v1/stream", params="", query="", fragment="", scheme="http", netloc="x")

    # 不抛 = 被 `_CLIENT_GONE` 捕获了；抛出来则测试失败并打印真实堆栈。
    handler._stream_events(parsed)

    assert handler.close_connection is True, \
        "断开后应设置 close_connection=True（让 HTTP 层正常收尾）"


def test_client_gone_is_used_by_stream_events():
    """`_stream_events` 必须真的用 `_CLIENT_GONE`（源码级约定）。

    结构断言：防止有人后来把 except 子句改回
    `(BrokenPipeError, ConnectionResetError)` —— 那种改动**在 Windows 上
    立刻炸**，但本地若不构造断开就完全测不到。
    """
    import inspect

    from prompt_ids.web.playground import Handler

    src = inspect.getsource(Handler._stream_events)
    assert "_CLIENT_GONE" in src, (
        "_stream_events 的 except 子句必须用 _CLIENT_GONE，"
        "否则 Windows 的 ConnectionAbortedError 会逃到 socketserver")
