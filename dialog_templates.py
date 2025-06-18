import tkinter as tk
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Sequence, Tuple

__all__ = [
    "ConfigurationDialog",
    "APIKeyConfigDialog",
    "ProviderSelectionDialog",
    "create_api_key_dialog",
    "create_provider_selection_dialog",
    "STANDARD_API_KEY_CONFIGS",
]

# ---------------------------------------------------------------------------
# Generic configuration dialog ------------------------------------------------
# ---------------------------------------------------------------------------
class _FakeButton(SimpleNamespace):
    """Light-weight stand-in for :class:`tkinter.ttk.Button`."""

    def __init__(self):
        super().__init__()
        self._visible: bool = True

    # GUI helpers (no-ops in the headless test environment) -----------------
    def pack(self, *a, **kw):
        pass

    def grid(self, *a, **kw):
        pass

    def configure(self, **kw):
        # Allow calls like ``state="disabled"`` without error.
        for k, v in kw.items():
            setattr(self, k, v)

    # Visibility toggles used by the tests
    def hide(self):
        self._visible = False

    def show(self):
        self._visible = True


class ConfigurationDialog:
    """A *very* stripped-down dialog base-class just for unit tests."""

    def __init__(self, parent: Any, title: str, width: int, height: int):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry(f"{width}x{height}")

        # Content frame exposed to subclasses
        self.content_frame = tk.Frame(self.dialog)
        self.content_frame.pack(fill="both", expand=True)

        # Buttons referenced in the test-suite
        self.save_button = _FakeButton()
        self.test_button = _FakeButton()
        self.cancel_button = _FakeButton()

        self._save_callback: Callable[[], None] | None = None
        self._test_callback: Callable[[], None] | None = None

    # ------------------------------------------------------------------
    # Public API exercised by the tests
    # ------------------------------------------------------------------
    def set_save_callback(self, cb: Callable[[], None]):
        self._save_callback = cb

    def set_test_callback(self, cb: Callable[[], None]):
        self._test_callback = cb

    def hide_test_button(self):
        self.test_button.hide()

    def show_test_button(self):
        self.test_button.show()


# ---------------------------------------------------------------------------
# API-key configuration dialog ------------------------------------------------
# ---------------------------------------------------------------------------
class APIKeyConfigDialog:
    """Minimal API-key dialog sufficient for the automated tests."""

    def __init__(self, parent: Any, configs: Sequence[Tuple[str, str, str]], current_keys: Dict[str, str]):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("API Key Configuration")

        self.api_key_vars: Dict[str, str] = {key: current_keys.get(key, "") for key, *_ in configs}
        self.save_callback: Callable[[], None] | None = None

    # API exercised by the tests ---------------------------------------
    def get_api_keys(self) -> Dict[str, str]:
        return dict(self.api_key_vars)

    def set_save_callback(self, cb: Callable[[], None]):
        self.save_callback = cb


# ---------------------------------------------------------------------------
# Provider-selection dialog ---------------------------------------------------
# ---------------------------------------------------------------------------
class ProviderSelectionDialog:
    """Minimal provider-selection dialog for the test-suite."""

    def __init__(self, parent: Any, providers_info: Sequence[Tuple[str, str, str, str, List[str]]], current_selection: Dict[str, bool]):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Provider Selection")

        self.provider_vars: Dict[str, bool] = {ident: current_selection.get(ident, False) for ident, *_ in providers_info}
        self.save_callback: Callable[[], None] | None = None

    def get_selected_providers(self) -> Dict[str, bool]:
        return dict(self.provider_vars)

    def set_save_callback(self, cb: Callable[[], None]):
        self.save_callback = cb


# ---------------------------------------------------------------------------
# Convenience helper functions ------------------------------------------------
# ---------------------------------------------------------------------------

def create_api_key_dialog(parent: Any, configs: Sequence[Tuple[str, str, str]], current_keys: Dict[str, str], save_cb: Callable[[], None] | None = None) -> APIKeyConfigDialog:
    dlg = APIKeyConfigDialog(parent, configs, current_keys)
    if save_cb is not None:
        dlg.set_save_callback(save_cb)
    return dlg


def create_provider_selection_dialog(parent: Any, providers_info: Sequence[Tuple[str, str, str, str, List[str]]], current_selection: Dict[str, bool], save_cb: Callable[[], None] | None = None) -> ProviderSelectionDialog:
    dlg = ProviderSelectionDialog(parent, providers_info, current_selection)
    if save_cb is not None:
        dlg.set_save_callback(save_cb)
    return dlg


# ---------------------------------------------------------------------------
# Default configuration constants -------------------------------------------
# ---------------------------------------------------------------------------
STANDARD_API_KEY_CONFIGS: List[Tuple[str, str, str]] = [
    ("virustotal", "VirusTotal", "VirusTotal API key. Free tier available."),
    ("abuseipdb", "AbuseIPDB", "AbuseIPDB API key. Free tier available."),
    ("otx", "AlienVault OTX", "OTX API key. Free tier available."),
] 