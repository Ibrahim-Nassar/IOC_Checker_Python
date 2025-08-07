"""Static-type stub so Pyright understands our Pydantic model."""

from __future__ import annotations
from enum import Enum
from typing import Literal, Tuple, Optional

# --------------------------------------------------------------------------- 
# Real enum – each member is an *IOCStatus*, not a str
# ---------------------------------------------------------------------------
class IOCStatus(Enum):
    SUCCESS: "IOCStatus"
    MALICIOUS: "IOCStatus"
    ERROR: "IOCStatus"
    UNSUPPORTED: "IOCStatus"
    NOT_FOUND: "IOCStatus"

# --------------------------------------------------------------------------- 
# IOCResult (runtime is a Pydantic model, but we expose the real signature)
# ---------------------------------------------------------------------------
class IOCResult:
    ioc: str
    ioc_type: Literal["ip", "domain", "url", "hash"]
    status: IOCStatus | str          # providers sometimes pass raw strings
    malicious_engines: int
    total_engines: int
    message: str

    def __init__(
        self,
        *,
        ioc: str,
        ioc_type: str,
        status: IOCStatus | str,
        malicious_engines: int = ...,
        total_engines: int = ...,
        message: str = ...
    ) -> None: ...

# --------------------------------------------------------------------------- 
# helper functions re-exported from ioc_types.py
# ---------------------------------------------------------------------------
def detect_ioc_type(value: str) -> Tuple[str, str]: ...
def validate_ioc(
    value: str,
    *,
    expected_type: Optional[str] = ...
) -> Tuple[bool, str, str, str]: ... 