from ioc_types import IOCResult, IOCStatus
from ioc_checker import aggregate_verdict
import providers


def test_google_dns_clean(monkeypatch):
    class Prov:
        def __init__(self, name: str, status: IOCStatus):
            self.NAME = name
            self.TIMEOUT = 1
            self._status = status

        def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCResult:
            return IOCResult(ioc=ioc_value, ioc_type=ioc_type, status=self._status)

    providers_list = [Prov(n, IOCStatus.SUCCESS) for n in "ABCDE"]
    monkeypatch.setattr(providers, "PROVIDERS", providers_list, raising=False)

    results = [p.query_ioc("ip", "8.8.8.8") for p in providers.PROVIDERS]
    verdict = aggregate_verdict(results)
    assert verdict is IOCStatus.SUCCESS


def test_malicious_with_two_hits(monkeypatch):
    class Prov:
        def __init__(self, name: str, status: IOCStatus):
            self.NAME = name
            self.TIMEOUT = 1
            self._status = status

        def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCResult:
            return IOCResult(ioc=ioc_value, ioc_type=ioc_type, status=self._status)

    providers_list = [
        Prov("vt", IOCStatus.MALICIOUS),
        Prov("abuse", IOCStatus.MALICIOUS),
        Prov("otx", IOCStatus.SUCCESS),
        Prov("tf", IOCStatus.SUCCESS),
    ]
    monkeypatch.setattr(providers, "PROVIDERS", providers_list, raising=False)

    results = [p.query_ioc("domain", "bad.io") for p in providers.PROVIDERS]
    verdict = aggregate_verdict(results)
    assert verdict is IOCStatus.MALICIOUS
