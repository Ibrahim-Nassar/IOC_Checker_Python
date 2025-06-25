import asyncio
import providers
import ioc_checker
from provider_interface import IOCResult


def test_scan_minimal(monkeypatch):
    """Ensure scan_single returns results for all providers."""

    class DummyTrue:
        NAME = "DummyTrue"
        TIMEOUT = 1

        def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCResult:
            return IOCResult(status="malicious", score=100.0, raw={})

    class DummyFalse:
        NAME = "DummyFalse"
        TIMEOUT = 1

        def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCResult:
            return IOCResult(status="clean", score=0.0, raw={})

    provs = [DummyTrue(), DummyFalse()]
    monkeypatch.setattr(providers, "PROVIDERS", provs, raising=False)
    monkeypatch.setattr(providers, "ALWAYS_ON", provs, raising=False)
    monkeypatch.setattr(ioc_checker, "ALWAYS_ON", provs, raising=False)

    res = asyncio.run(ioc_checker.scan_single("1.1.1.1", False))
    results = res["results"]
    assert results["DummyTrue"]["status"] == "malicious"
    assert results["DummyFalse"]["status"] == "clean"


def test_scan_partial_failure(monkeypatch):
    """A single failing provider must not break the whole result map."""

    class Flaky:
        NAME = "Flaky"
        TIMEOUT = 1

        def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCResult:
            raise RuntimeError("API down")

    class Good:
        NAME = "Good"
        TIMEOUT = 1

        def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCResult:
            return IOCResult(status="clean", score=0.0, raw={})

    provs = [Flaky(), Good()]
    monkeypatch.setattr(providers, "PROVIDERS", provs, raising=False)
    monkeypatch.setattr(providers, "ALWAYS_ON", provs, raising=False)
    monkeypatch.setattr(ioc_checker, "ALWAYS_ON", provs, raising=False)

    res = asyncio.run(ioc_checker.scan_single("8.8.8.8", False))
    results = res["results"]
    assert "Flaky" in results
    assert results["Flaky"]["status"] == "error"
