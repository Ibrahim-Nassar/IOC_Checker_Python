import requests, threading

_session = requests.Session()
_lock    = threading.Lock()


def get(url: str, headers=None, params=None, timeout=10):
    with _lock:
        return _session.get(url, headers=headers, params=params, timeout=timeout)


def post(url: str, headers=None, data=None, timeout=15):
    with _lock:
        return _session.post(url, headers=headers, data=data, timeout=timeout) 