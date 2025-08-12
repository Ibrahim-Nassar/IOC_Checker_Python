from IOC_Checker_Python.settings import settings


def test_http_defaults_present():
    # Minimal assertions so behavior is untouched but configuration exists
    assert settings.HTTP_DEFAULT_TIMEOUT > 0
    assert settings.HTTP_MAX_RETRIES >= 0
    assert settings.HTTP_BACKOFF_BASE > 0
    assert settings.HTTP_BACKOFF_CAP >= settings.HTTP_BACKOFF_BASE


