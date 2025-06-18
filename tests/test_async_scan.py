import pytest
import types

import asyncio

# Import the providers module from package – this exposes scan_async
from IOC_Checker_Python import providers as prov


@pytest.mark.asyncio
async def test_scan_async_mock(monkeypatch):
    """Ensure scan_async works when providers yield True/False values."""

    # Prepare dummy async provider always returning True
    async def _dummy(_ioc: str) -> bool:  # noqa: D401 – simple stub
        await asyncio.sleep(0)  # allow event-loop switch
        return True

    # Inject dummy provider
    monkeypatch.setitem(prov.PROVIDERS_ASYNC, "Dummy", _dummy)

    # Run scan
    verdicts = await prov.scan_async("1.2.3.4")

    assert verdicts["Dummy"] is True
    # Original providers may or may not be present – ensure no exceptions.
    assert isinstance(verdicts, dict)
    assert all(isinstance(v, bool) for v in verdicts.values()) 