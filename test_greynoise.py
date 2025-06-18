import greynoise_api as g
from unittest.mock import patch

def test_greynoise_malicious():
    data = {"classification": "malicious"}
    with patch("requests.get") as m:
        m.return_value.status_code = 200
        m.return_value.json.return_value = data
        assert g.check("1.1.1.1") is True

def test_greynoise_clean():
    data = {"classification": "benign"}
    with patch("requests.get") as m:
        m.return_value.status_code = 200
        m.return_value.json.return_value = data
        assert g.check("1.1.1.1") is False