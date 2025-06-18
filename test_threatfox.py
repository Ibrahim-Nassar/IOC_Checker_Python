import sys
sys.path.append('..')
from unittest.mock import patch
import threatfox_api as tfx


def test_hit():
    with patch("cache.session.post") as p:
        p.return_value.ok = True
        p.return_value.json.return_value = {"data": [{"ioc": "evil.com"}]}
        assert tfx.check("evil.com") is True


def test_miss():
    with patch("cache.session.post") as p:
        p.return_value.ok = True
        p.return_value.json.return_value = {"data": []}
        assert tfx.check("good.com") is False 