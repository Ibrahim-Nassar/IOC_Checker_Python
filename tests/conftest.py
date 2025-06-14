# tests/conftest.py
"""Pytest configuration and shared fixtures for IOC checker tests."""
import pytest
import asyncio
import tempfile
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
import aiohttp

@pytest.fixture
def temp_env(monkeypatch):
    """Temporary environment with clean API keys."""
    with tempfile.TemporaryDirectory() as tmpdir:
        env_file = Path(tmpdir) / ".env"
        env_file.write_text("ABUSEIPDB_API_KEY=test_key\nVIRUSTOTAL_API_KEY=vt_key\n")
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "test_key")
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt_key")
        yield tmpdir

@pytest.fixture
def mock_session():
    """Mock aiohttp session with configurable responses."""
    session = AsyncMock(spec=aiohttp.ClientSession)
    
    async def mock_get(*args, **kwargs):
        response = AsyncMock()
        response.text.return_value = '{"data": {"abuseConfidenceScore": 0}}'
        response.status = 200
        return response
    
    async def mock_post(*args, **kwargs):
        response = AsyncMock()
        response.text.return_value = '{"query_status": "no_result"}'
        response.status = 200
        return response
    
    session.get = mock_get
    session.post = mock_post
    return session

@pytest.fixture
def csv_data():
    """Sample CSV data for batch testing."""
    return [
        ("ip,domain,url", "8.8.8.8,google.com,https://example.com"),
        ("ip;domain;url", "1.1.1.1;cloudflare.com;https://test.com"),
        ("ip|domain|url", "9.9.9.9|quad9.com|https://demo.com"),
        ("ip\tdomain\turl", "208.67.222.222\topendns.com\thttps://cisco.com"),
    ]
