import cache
from datetime import timedelta


def test_ttl_setting():
    """Ensure the cache TTL is set to 24 h (86 400 s)."""
    exp = cache.session.expire_after
    if isinstance(exp, timedelta):
        assert exp.total_seconds() == 86400
    else:
        # Some versions return raw seconds (int | float)
        assert exp == 86400


def test_clear_cache():
    """Verify that cache.clear() removes cached responses."""
    # Ensure cache is clean at the start
    cache.clear()

    # Access size of cache safely across backend types
    if hasattr(cache.session.cache, "responses"):
        assert len(cache.session.cache.responses) == 0
    else:
        # Fallback: use __len__ implemented by backend
        assert len(cache.session.cache) == 0

    # The backend should remain empty after another clear call (idempotent)
    cache.clear()
    if hasattr(cache.session.cache, "responses"):
        assert len(cache.session.cache.responses) == 0
    else:
        assert len(cache.session.cache) == 0 