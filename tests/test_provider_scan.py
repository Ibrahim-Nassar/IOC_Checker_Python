import importlib, types, builtins
import providers


def test_scan_happy(monkeypatch):
    # Inject two dummy providers so the test is deterministic
    monkeypatch.setitem(providers.PROVIDERS, "DummyGood", lambda i: True)
    monkeypatch.setitem(providers.PROVIDERS, "DummyBad",  lambda i: False)

    res = providers.scan("1.1.1.1")
    assert res["DummyGood"] is True
    assert res["DummyBad"]  is False
    # Ensure original providers still present
    for name in ("VirusTotal", "AbuseIPDB"):
        assert name in res 