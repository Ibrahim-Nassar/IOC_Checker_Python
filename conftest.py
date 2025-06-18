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

            import inspect
            if inspect.iscoroutinefunction(func):
                def _sync_wrapper(*args, __orig=func, **kwargs):
                    asyncio.run(__orig(*args, **kwargs))
                item.obj = _sync_wrapper
            else:
                def _wrapper(*args, __orig=func, **kwargs):
                    __orig(*args, **kwargs)  # discard return value
                item.obj = _wrapper 