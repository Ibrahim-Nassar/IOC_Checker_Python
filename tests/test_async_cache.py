import asyncio
import pytest
import async_cache

pytestmark = pytest.mark.asyncio


async def test_cache_roundtrip(monkeypatch):
    """aget should mark second response as coming from cache."""
    async def _fake_get(url, *, timeout=5.0, ttl=900, api_key=None, headers=None):
        class _Resp:
            status_code = 200
            from_cache = getattr(_fake_get, "_hit", False)
        _fake_get._hit = True
        return _Resp()

    monkeypatch.setattr(async_cache, "aget", _fake_get, raising=True)

    url = "https://example.com/dummy"
    r1 = await async_cache.aget(url)
    r2 = await async_cache.aget(url)
    assert r1.status_code == 200
    assert r2.from_cache is True


if __name__ == "__main__":
    asyncio.run(test_cache_roundtrip()) 