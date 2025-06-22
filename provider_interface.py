"""
Unified provider protocol for IOC_Checker.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable, Any, Dict
from dataclasses import dataclass


@dataclass(frozen=True)
class IOCResult:
    status: str  # "success" or error text
    score: float | None  # 0-100 maliciousness, None if unknown
    raw: Dict[str, Any]


@runtime_checkable
class IOCProvider(Protocol):
    NAME: str
    TIMEOUT: int  # seconds

    def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCResult: ...

# --- AUTOGEN START
# (Cursor will fill in)
# --- AUTOGEN END 