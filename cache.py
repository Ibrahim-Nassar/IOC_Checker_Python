import requests_cache

# Create a cached session with a 24-hour TTL (86 400 s)
session = requests_cache.CachedSession(
    cache_name=".cache/http_cache",
    backend="sqlite",
    expire_after=86_400,
)


def clear() -> None:
    """Clear all cached responses but keep the backend intact."""
    try:
        session.cache.clear()
    except Exception:
        # Ignore errors so the caller never crashes when clearing the cache
        pass 