from ioc_types import IOCResult, IOCStatus
from ioc_checker import aggregate_verdict
import providers


def test_scan_minimal(monkeypatch):
    """Two providers, one malicious hit → overall verdict MALICIOUS."""

    class DummyTrue:
        NAME = "true"
        TIMEOUT = 1

        def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCResult:
            return IOCResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                status=IOCStatus.MALICIOUS,
                malicious_engines=1,
                total_engines=1,
            )

    class DummyFalse:
        NAME = "false"
        TIMEOUT = 1

        def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCResult:
            return IOCResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                status=IOCStatus.SUCCESS,
            )

    monkeypatch.setattr(providers, "PROVIDERS", [DummyTrue(), DummyFalse()], raising=False)

    results = [p.query_ioc("ip", "1.1.1.1") for p in providers.PROVIDERS]
    verdict = aggregate_verdict(results)

    assert verdict is IOCStatus.MALICIOUS


def test_scan_partial_failure(monkeypatch):
    """One provider errors, one succeeds → overall verdict ERROR."""

    class Flaky:
        NAME = "flaky"
        TIMEOUT = 1

        def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCResult:
            raise RuntimeError("API down")

    class Good:
        NAME = "good"
        TIMEOUT = 1

        def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCResult:
            return IOCResult(
                ioc=ioc_value,
                ioc_type=ioc_type,
                status=IOCStatus.SUCCESS,
            )

    monkeypatch.setattr(providers, "PROVIDERS", [Flaky(), Good()], raising=False)

    results = []
    for p in providers.PROVIDERS:
        try:
            results.append(p.query_ioc("ip", "8.8.8.8"))
        except RuntimeError:
            results.append(
                IOCResult(ioc="8.8.8.8", ioc_type="ip", status=IOCStatus.ERROR)
            )

    verdict = aggregate_verdict(results)
    assert verdict is IOCStatus.ERROR
