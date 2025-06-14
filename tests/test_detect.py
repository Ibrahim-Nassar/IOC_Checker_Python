from ioc_types import detect_ioc_type

def test_hash(): assert detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e")[0]=="hash"
def test_url():
    t,v=detect_ioc_type("https://example.com/page?utm_source=x")
    assert t=="url" and "utm_source" not in v
