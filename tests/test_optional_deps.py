"""守护：可选依赖的可用性判断**不得抛异常**。

## 这条守护钉住的是 CI 上真实发生过的事（2026-10）

`local.py` / `lightweight.py` 曾用 `importlib.util.find_spec(name) is not None`
判断可选依赖。两个问题：

1. **`find_spec` 会向上传播 finder 抛出的异常**（标准库文档明列）。
   环境里有任何一个 meta_path finder 对该名字抛异常（损坏的 `.pth`、
   打包不完整的 dist、用户自装的 import hook），「依赖没装」就变成
   「异常一路抛到 CLI 顶层」⇒ 退出码 1，**而且是在做任何判定之前**。
   CI 装 `[dev,speed]`（**没有** transformers/torch）正好落在这个场景：
   `test_cli_output_scan_is_a_separate_mode_from_input_scanning` 报
   `assert 1 == 0`，而本地装全套则绿 —— **本地永远复现不了**。

2. **`find_spec` 只证明「包目录存在」**，不证明「能加载」。装了一半
   （缺 .so、缺子模块、`__init__` 抛错）会被判成可用，炸在运行时。

⇒ 改为真 `import_module` 并就地吞掉异常（`_importable`）。

## 为什么用「会抛异常的 finder」而不是「真没装」

真没装时 `find_spec` 返回 `None` 而**不抛**，所以只用真没装**测不出**
第 1 条。这里注入一个会抛异常的 finder 精确模拟那条路径 ——
这正是本项目反复在用的手法（`test_minimal_install` 用 import hook 屏蔽
可选依赖，而不是真的卸载）。

## 两个写守护时踩到的坑（都记在这里）

- **finder 不能对所有名字抛**：第一版对任何名字抛，结果连 `prompt_ids`
  自己都 import 不到，守护变成「测导入失败」。它报错时看起来像被测代码
  有问题，实际是探针写错了 —— 「测试自己先崩掉」是最危险的守护形态。
- **不要用 `dir()` + `startswith` 找被测函数**：函数改名后断言会变成
  恒真（测不到任何东西却显示通过）。本项目明令禁止恒真断言式守护，
  所以下面**逐个点名**函数名。
"""
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

#: 只列**真正可选**的依赖。
#:
#: ⚠ 不要把 numpy 加进来：`memory/encoder.py` 顶层就 `import numpy`，
#: 而 numpy 在 `pyproject.toml` 的 `[project].dependencies`（不是某个 extra），
#: 所以「numpy 不可用」时该模块**根本 import 不了** —— 把它当可选依赖测
#: 会得到「导入期就崩」，那是**测试自己写错了**，不是被测代码的缺陷。
ENTRY_POINTS = [
    ("prompt_ids.detectors.semantic.local", "_transformers_ready", "transformers"),
    ("prompt_ids.detectors.semantic.lightweight", "_sklearn_ready", "sklearn"),
]


@pytest.mark.parametrize(
    ("module_name", "entry", "dependency"),
    ENTRY_POINTS,
    ids=[f"{m.split('.')[-1]}.{e}" for m, e, _ in ENTRY_POINTS],
)
def test_availability_check_never_raises(module_name, entry, dependency):
    """可用性判断遇到「依赖不可用」必须返回 False，**不能抛**。

    注入一个对**目标包**抛 ModuleNotFoundError 的 finder，模拟
    损坏 `.pth` / 残缺 dist / 自装 import hook 这三种真实环境。
    """
    probe = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(ROOT)!r})

        class AngryFinder:
            # 只对被依赖的那个包抛，其它名字必须正常 ——
            # 第一版这里对所有名字抛，连 prompt_ids 自己都 import 不到。
            def find_spec(self, name, path=None, target=None):
                if name.split(".")[0] == {dependency!r}:
                    raise ModuleNotFoundError("simulated broken finder: " + name)
                return None

        sys.meta_path.insert(0, AngryFinder())

        import {module_name} as mod
        fn = getattr(mod, {entry!r}, None)
        if fn is None:
            print("MISSING_ENTRY_POINT")
        else:
            try:
                print("RESULT:" + repr(fn()))
            except BaseException as exc:
                print("RAISED:" + type(exc).__name__)
    """)
    proc = subprocess.run(
        [sys.executable, "-X", "utf8", "-c", probe],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=180,
    )
    assert proc.returncode == 0, (
        f"{module_name} 在导入期就崩了（可用性判断不该在 import 时抛）："
        f"\n{proc.stderr[-800:]}")
    out = proc.stdout
    assert "MISSING_ENTRY_POINT" not in out, (
        f"{module_name} 里没有 {entry}() —— 函数被改名了，"
        f"这条守护会变成恒真断言（测不到任何东西却显示通过）")
    assert "RAISED:" not in out, (
        f"{module_name}.{entry}() 抛了异常，应返回 False：\n{out}")
    assert "RESULT:False" in out, (
        f"{module_name}.{entry}() 应返回 False：\n{out}")


def test_importable_swallows_every_failure_mode():
    """`_importable` 必须对**任何**失败都返回 False。

    刻意捕获 `BaseException`：这里的用途是「这个依赖能不能用」，
    SyntaxError / SystemExit 之类也等价于「不能用」。
    """
    from prompt_ids.detectors.semantic.local import _importable

    assert _importable("json") is True, "标准库 must be usable"
    assert _importable("_definitely_not_a_module_xyz_") is False


def test_cli_works_without_semantic_dependencies():
    """端到端：**缺 transformers/torch 时 CLI 必须正常判定**，不是退出码 1。

    这正是 CI 上失败的那条断言（`assert 1 == 0`）。本地装全套依赖时永远绿，
    所以只能靠屏蔽可选依赖来复现。
    """
    text = "文档里的示例密钥 AKIAIOSFODNN7EXAMPLE 是公开的样例"
    probe = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(ROOT)!r})

        class Denier:
            def find_spec(self, name, path=None, target=None):
                if name.split(".")[0] in ("transformers", "torch"):
                    raise ModuleNotFoundError("simulated: " + name)
                return None

        sys.meta_path.insert(0, Denier())
        for m in list(sys.modules):
            if m.split(".")[0] in ("transformers", "torch"):
                del sys.modules[m]

        import runpy
        sys.argv = ["prompt_ids.cli", {text!r}]
        runpy.run_module("prompt_ids.cli", run_name="__main__")
    """)
    proc = subprocess.run(
        [sys.executable, "-X", "utf8", "-c", probe],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=180,
    )
    assert proc.returncode == 0, (
        f"缺依赖时 CLI 退出码应为 0，实际 {proc.returncode}\n{proc.stderr[-800:]}")
    assert "判定" in proc.stdout, f"应正常输出判定：\n{proc.stdout[-300:]}"


def test_numpy_is_a_hard_dependency_not_an_optional_one():
    """numpy 是**硬依赖**，`_numpy_ready()` 因此是恒真的死代码。

    钉住两件事：

    1. numpy 声明在 `[project].dependencies`，不是某个 extra ——
       2026-10 修过「只在 `[memory]` extra 里声明 ⇒ `pip install .` 后
       连纯规则层都 import 不了」。
    2. 因此 `build_encoder` 里的「numpy 缺失 ⇒ NullEncoder」分支不可达。
       这条守护防止有人照着那段死代码写出「numpy 可选」的错误逻辑。
    """
    import tomllib

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    core_deps = pyproject["project"]["dependencies"]
    assert any(d.startswith("numpy") for d in core_deps), (
        f"numpy 必须在核心依赖里，现在只有 {core_deps}")
    for extra, deps in pyproject["project"].get("optional-dependencies", {}).items():
        assert "numpy" not in str(deps), f"numpy 不该只出现在 [{extra}] extra 里"

    # 死代码性质写进了 docstring —— 防止下一个人根据返回值写逻辑
    from prompt_ids.memory import encoder

    assert encoder._numpy_ready() is True
    doc = encoder._numpy_ready.__doc__ or ""
    assert "死代码" in doc and "硬依赖" in doc, (
        "必须在 _numpy_ready 的 docstring 里写明「恒真的死代码」，"
        "否则下一个人会以为 numpy 可选")