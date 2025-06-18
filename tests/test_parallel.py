from providers import scan

def test_parallel_mock(monkeypatch):
    # Inject a dummy provider that always returns True
    monkeypatch.setitem(scan.__globals__["PROVIDERS"], "Dummy", lambda i: True)
    res = scan("x")
    assert res["Dummy"] is True 