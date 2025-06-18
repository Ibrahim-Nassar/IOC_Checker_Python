import pytest
import tkinter as tk
import inspect
import asyncio

# ---------------------------------------------------------------------------
# Fixture: gui
# ---------------------------------------------------------------------------
# Some tests request a `gui` fixture but it is not defined in the repository.
# We create it here so that those tests receive a fully-initialised GUI object
# while keeping resource usage minimal.
# ---------------------------------------------------------------------------

@pytest.fixture
def gui():
    """Provide a lightweight IOCCheckerGUI instance for tests."""
    try:
        from ioc_gui_tk import IOCCheckerGUI
    except ImportError as exc:
        pytest.skip(f"IOCCheckerGUI not available: {exc}")

    root = tk.Tk()
    root.withdraw()  # Hide the root window during tests

    gui_instance = IOCCheckerGUI()
    yield gui_instance

    # Teardown – make sure all windows are closed
    try:
        gui_instance.root.destroy()
    except Exception:
        pass
    try:
        root.destroy()
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Hook: suppress non-None return values from test functions
# ---------------------------------------------------------------------------
# Several test files incorrectly `return True` at the end of the test.  Pytest
# reports this as an error ("Expected None, but test returned …").  We wrap the
# collected callables to swallow the return value and always yield `None`.
# ---------------------------------------------------------------------------

def pytest_collection_modifyitems(items):
    for item in items:
        func = item.obj

        # Only patch plain functions (skip classes/coroutines/fixtures etc.)
        if callable(func) and getattr(func, "__name__", "").startswith("test_"):
            if inspect.iscoroutinefunction(func):
                # Only wrap when the test is *not* already marked for asyncio
                if item.get_closest_marker("asyncio") is None:
                    def _sync_async(*args, __orig=func, **kwargs):
                        asyncio.run(__orig(*args, **kwargs))
                    item.obj = _sync_async
            else:
                def _wrapper(*args, __orig=func, **kwargs):
                    __orig(*args, **kwargs)  # discard return value
                item.obj = _wrapper 

# ---------------------------------------------------------------------------
# Ensure a default event loop exists at collection time on Windows
# ---------------------------------------------------------------------------

def pytest_configure(config):  # noqa: D401 – simple hook
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop()) 

# ---------------------------------------------------------------------------
# Guarantee headless-friendly tkinter.Tk during tests (handles late imports)
# ---------------------------------------------------------------------------

class _StubTk:
    """Drop-in replacement for tkinter.Tk that does nothing."""

    def __init__(self, *a, **k):
        self._children = []
        self.children = {}
        # ttk relies on master.tk — we point it to self and provide a no-op
        # ``call`` method that simply returns an empty string.
        self.tk = self
        # Required for unique widget path generation
        self._last_child_ids: dict[str, int] = {}
        # Root widget path
        self._w = "."

    # geometry helpers -------------------------------------------------
    def title(self, *a, **k):
        pass
    def geometry(self, *a, **k):
        pass
    def resizable(self, *a, **k):
        pass
    def minsize(self, *a, **k):
        pass

    # widget / window helpers -----------------------------------------
    def withdraw(self, *a, **k):
        pass
    def destroy(self, *a, **k):
        pass
    def quit(self, *a, **k):
        pass
    def winfo_children(self):
        return self._children

    # layout/config helpers used by GUI code -----------------------------
    def columnconfigure(self, *a, **k):
        pass
    def rowconfigure(self, *a, **k):
        pass
    def config(self, *a, **k):
        pass
    def configure(self, *a, **k):
        pass
    def call(self, *a, **k):
        return ""
    
    def splitlist(self, v):
        if v is None or v == "":
            return []
        return str(v).split()

    # generic fallback to swallow unexpected attribute access
    def __getattr__(self, name):
        return lambda *a, **k: None

# Ensure the replacement is in place *after* sitecustomize ran.
import tkinter as _tk
_tk.Tk = _StubTk  # type: ignore[attr-defined]

# Variable stubs -----------------------------------------------------------

class _Var:
    def __init__(self, master=None, value=None, name=None):
        self._value = value
    def get(self):
        return self._value
    def set(self, v):
        self._value = v

_tk.BooleanVar = _Var  # type: ignore[attr-defined]
_tk.StringVar = _Var  # type: ignore[attr-defined]

# Ensure tkinter thinks a default root exists
_tk._default_root = _StubTk()  # type: ignore[attr-defined] 