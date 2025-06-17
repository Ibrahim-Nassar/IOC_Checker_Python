"""
Pytest configuration and shared fixtures for IOC Checker tests.
"""
import pytest
import asyncio
import tempfile
import pathlib
from unittest.mock import AsyncMock
import aiohttp
from aiohttp import web


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield pathlib.Path(tmpdir)


@pytest.fixture
def sample_iocs():
    """Sample IOC data for testing."""
    return {
        "valid_ip": "8.8.8.8",
        "valid_ip_with_port": "8.8.8.8:53",
        "valid_ipv6": "2001:db8::1",
        "valid_domain": "example.com", 
        "valid_url": "https://example.com/path",
        "valid_hash_md5": "d41d8cd98f00b204e9800998ecf8427e",
        "valid_hash_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "valid_email": "test@example.com",
        "invalid_ip": "999.999.999.999",
        "invalid_domain": "not_a_domain",
        "invalid_url": "not_a_url",
        "invalid_hash": "not_a_hash"
    }


@pytest.fixture
def mock_aiohttp_session():
    """Mock aiohttp ClientSession for testing."""
    session = AsyncMock(spec=aiohttp.ClientSession)
    
    # Mock response object
    response = AsyncMock()
    response.status = 200
    response.text = AsyncMock(return_value='{"data": {"test": "response"}}')
    response.json = AsyncMock(return_value={"data": {"test": "response"}})
    
    # Create a proper async context manager mock
    context_manager = AsyncMock()
    context_manager.__aenter__ = AsyncMock(return_value=response)
    context_manager.__aexit__ = AsyncMock(return_value=None)
    
    # Configure session methods to return the context manager
    session.get.return_value = context_manager
    session.post.return_value = context_manager
    session.request.return_value = context_manager
    
    return session


@pytest.fixture
def mock_provider_responses():
    """Mock responses from various threat intelligence providers."""
    return {
        "abuseipdb": {
            "data": {
                "abuseConfidenceScore": 0,
                "isWhitelisted": False,
                "isPublic": True
            }
        },
        "virustotal": {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 5,
                        "undetected": 3
                    }
                }
            }
        },
        "otx": {
            "pulse_info": {
                "count": 0
            }
        },
        "threatfox": {
            "query_status": "no_result"
        }
    }


@pytest.fixture
def sample_csv_content():
    """Sample CSV content for testing batch processing."""
    return """ioc_type,ioc_value,description
ip,8.8.8.8,Google DNS
domain,example.com,Test domain
url,https://example.com,Test URL
hash,d41d8cd98f00b204e9800998ecf8427e,Test MD5 hash"""


@pytest.fixture  
def sample_csv_file(temp_dir, sample_csv_content):
    """Create a temporary CSV file with sample IOC data."""
    csv_file = temp_dir / "test_iocs.csv"
    csv_file.write_text(sample_csv_content, encoding="utf-8")
    return csv_file


@pytest.fixture
def mock_env_vars(monkeypatch):
    """Mock environment variables for API keys."""
    test_keys = {
        "ABUSEIPDB_API_KEY": "test_abuseipdb_key",
        "VIRUSTOTAL_API_KEY": "test_virustotal_key", 
        "OTX_API_KEY": "test_otx_key",
        "THREATFOX_API_KEY": "test_threatfox_key",
        "GREYNOISE_API_KEY": "test_greynoise_key",
        "PULSEDIVE_API_KEY": "test_pulsedive_key",
        "SHODAN_API_KEY": "test_shodan_key"
    }
    
    for key, value in test_keys.items():
        monkeypatch.setenv(key, value)
    
    return test_keys


@pytest.fixture
async def mock_aiohttp_server():
    """Create a mock HTTP server for testing provider interactions."""
    async def handler(request):
        # Simple mock responses based on path
        if "abuseipdb" in request.url.path:
            return web.json_response({
                "data": {"abuseConfidenceScore": 0, "isWhitelisted": False}
            })
        elif "virustotal" in request.url.path:
            return web.json_response({
                "data": {"attributes": {"last_analysis_stats": {
                    "malicious": 0, "suspicious": 0, "harmless": 5
                }}}
            })
        elif "otx" in request.url.path:
            return web.json_response({"pulse_info": {"count": 0}})
        else:
            return web.json_response({"query_status": "no_result"})
    
    app = web.Application()
    app.router.add_route('*', '/{path:.*}', handler)
    
    return app


@pytest.fixture
def mock_csv_data():
    """Mock CSV data with various IOC types."""
    return [
        {"ioc_type": "ip", "ioc_value": "8.8.8.8", "description": "Google DNS"},
        {"ioc_type": "domain", "ioc_value": "example.com", "description": "Test domain"},
        {"ioc_type": "url", "ioc_value": "https://example.com", "description": "Test URL"},
        {"ioc_type": "hash", "ioc_value": "d41d8cd98f00b204e9800998ecf8427e", "description": "Test hash"}
    ]