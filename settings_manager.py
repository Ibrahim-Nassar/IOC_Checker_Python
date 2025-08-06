import json
import logging
from pathlib import Path
from typing import Dict

log = logging.getLogger(__name__)

DEFAULT_SETTINGS: Dict[str, object] = {
    "provider_config": {
        "virustotal": False,
        "abuseipdb": False,
        "otx": False,
    },
    "show_threats_only": False,
    "dark_mode": False,
}


def load_settings(settings_file: Path) -> Dict[str, object]:
    """Load settings from a JSON file or return defaults."""
    if not settings_file.exists():
        save_settings(settings_file, DEFAULT_SETTINGS)
        return DEFAULT_SETTINGS.copy()

    try:
        with open(settings_file, "r") as fh:
            settings = json.load(fh)
            log.info("Loaded settings: %s", settings)
            return settings
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to load settings: %s", exc)
        return DEFAULT_SETTINGS.copy()


def save_settings(settings_file: Path, settings: Dict[str, object]) -> None:
    """Persist settings to a JSON file."""
    try:
        with open(settings_file, "w") as fh:
            json.dump(settings, fh, indent=4)
            log.info("Saved settings: %s", settings)
    except Exception as exc:  # pragma: no cover - defensive
        log.error("Failed to save settings: %s", exc)
