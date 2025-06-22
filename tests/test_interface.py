"""tests for the unified provider interface"""

import pytest
from provider_interface import IOCResult, IOCProvider


def test_iocresult_instantiation():
    """IOCResult should accept minimal required fields."""
    res = IOCResult(status="success", score=None, raw={})
    assert res.status == "success"
    assert res.score is None
    assert res.raw == {}


def test_dummy_provider_is_instance():
    """A minimal provider implementing the protocol should be recognized via isinstance."""

    class DummyProvider:
        NAME = "Dummy"
        TIMEOUT = 5

        def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCResult:
            return IOCResult(status="success", score=0, raw={})

    dummy = DummyProvider()
    assert isinstance(dummy, IOCProvider)


# --- AUTOGEN START
# (Cursor will fill in)
# --- AUTOGEN END 