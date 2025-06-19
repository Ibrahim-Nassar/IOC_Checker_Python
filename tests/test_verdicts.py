import providers, pytest


def test_google_dns_clean(monkeypatch):
    """8.8.8.8 must be clean with real thresholds."""
    monkeypatch.setattr(providers, "vt", lambda i: {"positives": 1, "total": 72})
    monkeypatch.setattr(providers, "abuse", lambda i: {"confidence": 0, "reports": 20})
    monkeypatch.setattr(providers, "otx", lambda i: False)
    monkeypatch.setattr(providers, "tfox", lambda i: False)
    monkeypatch.setattr(providers, "gnoise", lambda i: "benign")
    # Ensure the PROV dict does not call real ThreatFox API
    monkeypatch.setitem(providers.PROVIDERS, "ThreatFox", lambda i: False)

    res = providers.scan("8.8.8.8")
    assert res["verdict"] == "clean"


def test_malicious_with_two_hits(monkeypatch):
    """At least two malicious signals should flip the verdict to malicious."""
    monkeypatch.setattr(providers, "vt", lambda i: {"positives": 10, "total": 70})
    monkeypatch.setattr(providers, "abuse", lambda i: {"confidence": 80, "reports": 50})
    monkeypatch.setattr(providers, "otx", lambda i: False)
    monkeypatch.setattr(providers, "tfox", lambda i: False)
    monkeypatch.setattr(providers, "gnoise", lambda i: "unknown")
    # Override ThreatFox provider entry to avoid network and keep verdict stable
    monkeypatch.setitem(providers.PROVIDERS, "ThreatFox", lambda i: False)

    res = providers.scan("bad.io")

    assert res["verdict"] == "malicious"
    assert sorted(res["flagged_by"]) == ["AbuseIPDB", "VirusTotal"]

    monkeypatch.setitem(providers.PROVIDERS, "ThreatFox", lambda i: False) 