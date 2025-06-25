import ioc_checker


def test_aggregate_verdict_clean():
    data = {
        "A": {"status": "clean", "score": 0, "raw": {}},
        "B": {"status": "clean", "score": 0, "raw": {}},
    }
    assert ioc_checker._aggregate_verdict(data) == "clean"
    assert ioc_checker._flagged_by(data) == ""


def test_aggregate_verdict_malicious():
    data = {
        "A": {"status": "malicious", "score": 80, "raw": {}},
        "B": {"status": "malicious", "score": 90, "raw": {}},
    }
    assert ioc_checker._aggregate_verdict(data) == "malicious"
    assert ioc_checker._flagged_by(data) == "A,B"
