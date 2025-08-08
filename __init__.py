# Python IOC Checker Package
__version__ = "1.0.0"

# Ensure submodule availability for tests that patch via fully-qualified path
# This import keeps runtime behavior unchanged but exposes the attribute
from . import ioc_gui_tk as ioc_gui_tk  # noqa: F401