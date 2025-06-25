import importlib, types
import providers


def test_scan_minimal(monkeypatch):
    """Ensure scan() returns a deterministic provider map."""
    # Inject two dummy providers so we control the outcome
    monkeypatch.setitem(providers.PROVIDERS, "DummyTrue",  lambda i: True)
    monkeypatch.setitem(providers.PROVIDERS, "DummyFalse", lambda i: False)

    res = providers.scan("1.1.1.1")
    assert res["DummyTrue"] is True
    assert res["DummyFalse"] is False
    assert set(res.keys()) == {"DummyTrue", "DummyFalse"}


def test_scan_partial_failure(monkeypatch):
    """A single failing provider must not break the whole dict."""
    def boom(_: str) -> bool:
        raise RuntimeError("API down")
    monkeypatch.setitem(providers.PROVIDERS, "Flaky", boom)

    res = providers.scan("8.8.8.8")   # should complete
    assert "Flaky" in res             # key present
    assert res["Flaky"] is False      # failure coerced to False 