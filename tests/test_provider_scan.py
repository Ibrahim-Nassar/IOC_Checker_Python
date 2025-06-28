from ioc_types import IOCResult, IOCStatus
from ioc_checker import aggregate_verdict
import providers


def test_scan_minimal(monkeypatch):
    """Two providers, one malicious hit → overall verdict MALICIOUS."""

    class DummyTrue:
        NAME = "true"
        TIMEOUT = 1

        async def query_ioc(self, ioc: str, ioc_type: str) -> IOCResult:
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.MALICIOUS,
                malicious_engines=1,
                total_engines=1,
                message=""
            )

    class DummyFalse:
        NAME = "false"
        TIMEOUT = 1

        async def query_ioc(self, ioc: str, ioc_type: str) -> IOCResult:
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.SUCCESS,
                malicious_engines=0,
                total_engines=1,
                message=""
            )

    # Mock get_providers() to return instances instead of classes
    dummy_providers = [DummyTrue(), DummyFalse()]
    monkeypatch.setattr(providers, "get_providers", lambda: dummy_providers)

    # Use the actual scan_ioc function to test the full pipeline
    import asyncio
    from ioc_checker import scan_ioc
    
    async def run_test():
        results = await scan_ioc("1.1.1.1", "ip")
        return list(results.values())
    
    results = asyncio.run(run_test())
    verdict = aggregate_verdict(results)

    assert verdict is IOCStatus.MALICIOUS


def test_scan_partial_failure(monkeypatch):
    """One provider errors, one succeeds → overall verdict ERROR."""

    class Flaky:
        NAME = "flaky"
        TIMEOUT = 1

        async def query_ioc(self, ioc: str, ioc_type: str) -> IOCResult:
            raise RuntimeError("API down")

    class Good:
        NAME = "good"
        TIMEOUT = 1

        async def query_ioc(self, ioc: str, ioc_type: str) -> IOCResult:
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.SUCCESS,
                malicious_engines=0,
                total_engines=1,
                message=""
            )

    # Mock get_providers() to return instances instead of classes
    dummy_providers = [Flaky(), Good()]
    monkeypatch.setattr(providers, "get_providers", lambda: dummy_providers)

    # Use the actual scan_ioc function to test error handling
    import asyncio
    from ioc_checker import scan_ioc
    
    async def run_test():
        results = await scan_ioc("8.8.8.8", "ip")
        return list(results.values())
    
    results = asyncio.run(run_test())
    verdict = aggregate_verdict(results)
    assert verdict is IOCStatus.ERROR
