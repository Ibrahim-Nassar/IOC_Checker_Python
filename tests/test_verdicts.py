import asyncio
import providers
import ioc_checker
from provider_interface import IOCResult


def test_google_dns_clean(monkeypatch):
    """8.8.8.8 must be considered clean with sample provider data."""

    class Prov:
        def __init__(self, name: str, status: str) -> None:
            self.NAME = name
            self.TIMEOUT = 1
            self._status = status

        def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCResult:
            return IOCResult(status=self._status, score=0.0, raw={})

    providers_list = [
        Prov("VirusTotal", "clean"),
        Prov("AbuseIPDB", "clean"),
        Prov("OTX", "clean"),
        Prov("ThreatFox", "clean"),
        Prov("GreyNoise", "clean"),
    ]

    monkeypatch.setattr(providers, "PROVIDERS", providers_list, raising=False)
    monkeypatch.setattr(providers, "ALWAYS_ON", providers_list, raising=False)
    monkeypatch.setattr(ioc_checker, "ALWAYS_ON", providers_list, raising=False)

    res = asyncio.run(ioc_checker.scan_single("8.8.8.8", False))
    verdict = ioc_checker._aggregate_verdict(res["results"])
    assert verdict == "clean"


def test_malicious_with_two_hits(monkeypatch):
    """At least two malicious signals should flip the verdict to malicious."""

    class Prov:
        def __init__(self, name: str, status: str) -> None:
            self.NAME = name
            self.TIMEOUT = 1
            self._status = status

        def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCResult:
            return IOCResult(status=self._status, score=100.0 if self._status == "malicious" else 0.0, raw={})

    providers_list = [
        Prov("VirusTotal", "malicious"),
        Prov("AbuseIPDB", "malicious"),
        Prov("OTX", "clean"),
        Prov("ThreatFox", "clean"),
        Prov("GreyNoise", "clean"),
    ]

    monkeypatch.setattr(providers, "PROVIDERS", providers_list, raising=False)
    monkeypatch.setattr(providers, "ALWAYS_ON", providers_list, raising=False)
    monkeypatch.setattr(ioc_checker, "ALWAYS_ON", providers_list, raising=False)

    res = asyncio.run(ioc_checker.scan_single("bad.io", False))
    verdict = ioc_checker._aggregate_verdict(res["results"])
    flagged = ioc_checker._flagged_by(res["results"]).split(",")

    assert verdict == "malicious"
    assert sorted(flagged) == ["AbuseIPDB", "VirusTotal"]
