"""
Comprehensive tests for providers.py module.
Tests all provider classes, rate limiting, and async functionality.
"""
import pytest
import asyncio
import aiohttp
import datetime
from unittest.mock import AsyncMock, Mock, patch
from providers import (
    TokenBucket, Provider, AbuseIPDB, OTX, ThreatFox, URLHaus, 
    MalwareBazaar, VirusTotal, GreyNoise, Pulsedive, Shodan,
    ALWAYS_ON, RATE_LIMIT, _key, _extract_ip
)


class TestTokenBucket:
    """Test token bucket rate limiting implementation."""
    
    def test_token_bucket_init(self):
        """Test token bucket initialization."""
        bucket = TokenBucket(cap=10, interval=60)
        assert bucket.cap == 10
        assert bucket.tok == 10
        assert bucket.int == 60
        assert isinstance(bucket.upd, datetime.datetime)
        assert bucket.lock is not None
    
    @pytest.mark.asyncio
    async def test_token_bucket_acquire(self):
        """Test token acquisition."""
        bucket = TokenBucket(cap=5, interval=1)
        
        # Should acquire tokens immediately when available
        await bucket.acquire()
        assert bucket.tok == 4
        
        await bucket.acquire()
        assert bucket.tok == 3
    
    @pytest.mark.asyncio
    async def test_token_bucket_refill(self):
        """Test token bucket refill mechanism."""
        bucket = TokenBucket(cap=5, interval=1)
        
        # Consume all tokens
        for _ in range(5):
            await bucket.acquire()
        assert bucket.tok == 0
        
        # Manually advance time and test refill
        bucket.upd = datetime.datetime.utcnow() - datetime.timedelta(seconds=2)
        bucket._refill()
        assert bucket.tok >= 1  # Should have refilled at least 1 token
    
    @pytest.mark.asyncio
    async def test_token_bucket_waiting(self):
        """Test token bucket waiting behavior."""
        bucket = TokenBucket(cap=1, interval=1)
        
        # Consume the only token
        await bucket.acquire()
        assert bucket.tok == 0
        
        # Mock datetime to control time flow
        start_time = datetime.datetime.utcnow()
        with patch('providers.datetime') as mock_datetime:
            mock_datetime.datetime.utcnow.return_value = start_time
            
            # This should wait and then acquire
            task = asyncio.create_task(bucket.acquire())
            await asyncio.sleep(0.01)  # Let it start waiting
            
            # Advance time to allow refill
            mock_datetime.datetime.utcnow.return_value = start_time + datetime.timedelta(seconds=2)
            await task
            
            assert bucket.tok == 0  # Token was consumed


class TestProviderBase:
    """Test base Provider class."""
    
    def test_provider_base_class(self):
        """Test Provider base class properties."""
        class TestProvider(Provider):
            name = "test"
            ioc_kinds = ("ip", "domain")
            
            async def query(self, s, t, v):
                return f"test response for {t}:{v}"
        
        provider = TestProvider()
        assert provider.name == "test"
        assert provider.ioc_kinds == ("ip", "domain")
        assert provider.bucket is None


class TestUtilityFunctions:
    """Test utility functions."""
    
    def test_key_function(self):
        """Test environment variable extraction."""
        with patch.dict('os.environ', {'TEST_KEY': 'test_value'}):
            assert _key('TEST_KEY') == 'test_value'
        
        # Test non-existent key
        assert _key('NON_EXISTENT_KEY') == ''
        
        # Test key with whitespace
        with patch.dict('os.environ', {'WHITESPACE_KEY': '  test_value  '}):
            assert _key('WHITESPACE_KEY') == 'test_value'
    
    def test_extract_ip_function(self):
        """Test IP extraction function."""
        assert _extract_ip("8.8.8.8:53") == "8.8.8.8"
        assert _extract_ip("[2001:db8::1]:8080") == "2001:db8::1"
        assert _extract_ip("8.8.8.8") == "8.8.8.8"


class TestAbuseIPDB:
    """Test AbuseIPDB provider."""
    
    def test_abuseipdb_init(self):
        """Test AbuseIPDB initialization."""
        provider = AbuseIPDB()
        assert provider.name == "abuseipdb"
        assert "ip" in provider.ioc_kinds
        assert provider.bucket is None
    
    @pytest.mark.asyncio
    async def test_abuseipdb_query_success(self, mock_aiohttp_session, mock_env_vars):
        """Test successful AbuseIPDB query."""
        provider = AbuseIPDB()
        
        # Mock successful response
        mock_response = '{"data": {"abuseConfidenceScore": 0, "isWhitelisted": false}}'
        mock_aiohttp_session.get.return_value.__aenter__.return_value.text.return_value = mock_response
        
        result = await provider.query(mock_aiohttp_session, "ip", "8.8.8.8")
        assert result == mock_response
        
        # Verify correct API call
        mock_aiohttp_session.get.assert_called_once()
        call_args = mock_aiohttp_session.get.call_args
        assert "api.abuseipdb.com" in call_args[0][0]
    
    @pytest.mark.asyncio
    async def test_abuseipdb_query_no_key(self, mock_aiohttp_session):
        """Test AbuseIPDB query without API key."""
        provider = AbuseIPDB()
        provider.key = ""  # Override key
        
        result = await provider.query(mock_aiohttp_session, "ip", "8.8.8.8")
        assert result == "nokey"
    
    @pytest.mark.asyncio
    async def test_abuseipdb_query_with_port(self, mock_aiohttp_session, mock_env_vars):
        """Test AbuseIPDB query with IP:port format."""
        provider = AbuseIPDB()
        
        mock_response = '{"data": {"abuseConfidenceScore": 0}}'
        mock_aiohttp_session.get.return_value.__aenter__.return_value.text.return_value = mock_response
        
        result = await provider.query(mock_aiohttp_session, "ip", "8.8.8.8:53")
        assert result == mock_response
        
        # Verify IP was extracted from IP:port
        call_args = mock_aiohttp_session.get.call_args
        assert "8.8.8.8" in str(call_args[1]['params']['ipAddress'])
    
    @pytest.mark.asyncio
    async def test_abuseipdb_query_error(self, mock_aiohttp_session, mock_env_vars):
        """Test AbuseIPDB query error handling."""
        provider = AbuseIPDB()
        
        # Mock exception
        mock_aiohttp_session.get.side_effect = Exception("Network error")
        
        result = await provider.query(mock_aiohttp_session, "ip", "8.8.8.8")
        assert result.startswith("error:")
        assert "Network error" in result


class TestOTX:
    """Test AlienVault OTX provider."""
    
    def test_otx_init(self):
        """Test OTX initialization."""
        provider = OTX()
        assert provider.name == "otx"
        assert set(provider.ioc_kinds) == {"ip", "domain", "url", "hash"}
    
    @pytest.mark.asyncio
    async def test_otx_query_ip(self, mock_aiohttp_session, mock_env_vars):
        """Test OTX IP query."""
        provider = OTX()
        
        mock_response = '{"pulse_info": {"count": 0}}'
        mock_aiohttp_session.get.return_value.__aenter__.return_value.text.return_value = mock_response
        
        result = await provider.query(mock_aiohttp_session, "ip", "8.8.8.8")
        assert result == mock_response
        
        # Verify correct endpoint
        call_args = mock_aiohttp_session.get.call_args
        assert "IPv4" in call_args[0][0]
    
    @pytest.mark.asyncio
    async def test_otx_query_domain(self, mock_aiohttp_session, mock_env_vars):
        """Test OTX domain query."""
        provider = OTX()
        
        mock_response = '{"pulse_info": {"count": 1}}'
        mock_aiohttp_session.get.return_value.__aenter__.return_value.text.return_value = mock_response
        
        result = await provider.query(mock_aiohttp_session, "domain", "example.com")
        assert result == mock_response
        
        # Verify correct endpoint
        call_args = mock_aiohttp_session.get.call_args
        assert "domain" in call_args[0][0]
    
    @pytest.mark.asyncio
    async def test_otx_query_no_key(self, mock_aiohttp_session):
        """Test OTX query without API key."""
        provider = OTX()
        provider.key = ""
        
        result = await provider.query(mock_aiohttp_session, "ip", "8.8.8.8")
        assert result == "nokey"


class TestThreatFox:
    """Test ThreatFox provider."""
    
    def test_threatfox_init(self):
        """Test ThreatFox initialization."""
        provider = ThreatFox()
        assert provider.name == "threatfox"
        assert set(provider.ioc_kinds) == {"ip", "domain", "url", "hash"}
    
    @pytest.mark.asyncio
    async def test_threatfox_query_success(self, mock_aiohttp_session):
        """Test successful ThreatFox query."""
        provider = ThreatFox()
        
        mock_response = '{"query_status": "no_result"}'
        mock_aiohttp_session.post.return_value.__aenter__.return_value.text.return_value = mock_response
        
        result = await provider.query(mock_aiohttp_session, "hash", "test_hash")
        assert result == mock_response
        
        # Verify POST request
        mock_aiohttp_session.post.assert_called_once()
        call_args = mock_aiohttp_session.post.call_args
        assert "threatfox-api.abuse.ch" in call_args[0][0]
    
    @pytest.mark.asyncio
    async def test_threatfox_query_with_key(self, mock_aiohttp_session, mock_env_vars):
        """Test ThreatFox query with API key."""
        provider = ThreatFox()
        
        mock_response = '{"query_status": "ok"}'
        mock_aiohttp_session.post.return_value.__aenter__.return_value.text.return_value = mock_response
        
        result = await provider.query(mock_aiohttp_session, "hash", "test_hash")
        assert result == mock_response
        
        # Verify API key in headers
        call_args = mock_aiohttp_session.post.call_args
        assert "Auth-Key" in call_args[1]["headers"]


class TestURLHaus:
    """Test URLhaus provider."""
    
    def test_urlhaus_init(self):
        """Test URLhaus initialization."""
        provider = URLHaus()
        assert provider.name == "urlhaus"
        assert provider.ioc_kinds == ("url",)
    
    @pytest.mark.asyncio
    async def test_urlhaus_query(self, mock_aiohttp_session):
        """Test URLhaus query."""
        provider = URLHaus()
        
        mock_response = '{"query_status": "no_result"}'
        mock_aiohttp_session.post.return_value.__aenter__.return_value.text.return_value = mock_response
        
        result = await provider.query(mock_aiohttp_session, "url", "https://example.com")
        assert result == mock_response
        
        # Verify POST with form data
        call_args = mock_aiohttp_session.post.call_args
        assert "urlhaus-api.abuse.ch" in call_args[0][0]
        assert call_args[1]["data"]["url"] == "https://example.com"


class TestMalwareBazaar:
    """Test MalwareBazaar provider."""
    
    def test_malwarebazaar_init(self):
        """Test MalwareBazaar initialization."""
        provider = MalwareBazaar()
        assert provider.name == "malwarebazaar"
        assert provider.ioc_kinds == ("hash",)
    
    @pytest.mark.asyncio
    async def test_malwarebazaar_query(self, mock_aiohttp_session):
        """Test MalwareBazaar query."""
        provider = MalwareBazaar()
        
        mock_response = '{"query_status": "hash_not_found"}'
        mock_aiohttp_session.post.return_value.__aenter__.return_value.text.return_value = mock_response
        
        result = await provider.query(mock_aiohttp_session, "hash", "test_hash")
        assert result == mock_response


class TestVirusTotal:
    """Test VirusTotal provider."""
    
    def test_virustotal_init(self):
        """Test VirusTotal initialization."""
        provider = VirusTotal()
        assert provider.name == "virustotal"
        assert set(provider.ioc_kinds) == {"ip", "domain", "url", "hash"}
        assert provider.bucket is not None
        assert provider.bucket.cap == 4
        assert provider.bucket.int == 60
    
    @pytest.mark.asyncio
    async def test_virustotal_query_ip(self, mock_aiohttp_session, mock_env_vars):
        """Test VirusTotal IP query."""
        provider = VirusTotal()
        
        mock_response = '{"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}'
        mock_aiohttp_session.get.return_value.__aenter__.return_value.text.return_value = mock_response
        
        result = await provider.query(mock_aiohttp_session, "ip", "8.8.8.8")
        assert result == mock_response
        
        # Verify correct endpoint
        call_args = mock_aiohttp_session.get.call_args
        assert "ip_addresses" in call_args[0][0]
    
    @pytest.mark.asyncio
    async def test_virustotal_query_url(self, mock_aiohttp_session, mock_env_vars):
        """Test VirusTotal URL query."""
        provider = VirusTotal()
        
        mock_response = '{"data": {"attributes": {"last_analysis_stats": {"malicious": 1}}}}'
        mock_aiohttp_session.get.return_value.__aenter__.return_value.text.return_value = mock_response
        
        result = await provider.query(mock_aiohttp_session, "url", "https://example.com")
        assert result == mock_response
        
        # Verify URL encoding
        call_args = mock_aiohttp_session.get.call_args
        assert "urls/" in call_args[0][0]
    
    @pytest.mark.asyncio
    async def test_virustotal_query_no_key(self, mock_aiohttp_session):
        """Test VirusTotal query without API key."""
        provider = VirusTotal()
        provider.key = ""
        
        result = await provider.query(mock_aiohttp_session, "ip", "8.8.8.8")
        assert result == "nokey"


class TestGreyNoise:
    """Test GreyNoise provider."""
    
    def test_greynoise_init(self):
        """Test GreyNoise initialization."""
        provider = GreyNoise()
        assert provider.name == "greynoise"
        assert provider.ioc_kinds == ("ip",)
        assert provider.bucket is not None
    
    @pytest.mark.asyncio
    async def test_greynoise_query(self, mock_aiohttp_session, mock_env_vars):
        """Test GreyNoise query."""
        provider = GreyNoise()
        
        mock_response = '{"noise": false, "riot": false}'
        mock_aiohttp_session.get.return_value.__aenter__.return_value.text.return_value = mock_response
        
        result = await provider.query(mock_aiohttp_session, "ip", "8.8.8.8")
        assert result == mock_response


class TestPulsedive:
    """Test Pulsedive provider."""
    
    def test_pulsedive_init(self):
        """Test Pulsedive initialization."""
        provider = Pulsedive()
        assert provider.name == "pulsedive"
        assert set(provider.ioc_kinds) == {"ip", "domain", "url"}
        assert provider.bucket is not None
    
    @pytest.mark.asyncio
    async def test_pulsedive_query(self, mock_aiohttp_session, mock_env_vars):
        """Test Pulsedive query."""
        provider = Pulsedive()
        
        # Set the key directly since environment mocking might not work
        provider.key = "test_pulsedive_key"
        
        mock_response = '{"indicator": "8.8.8.8", "threats": []}'
        mock_aiohttp_session.get.return_value.__aenter__.return_value.text.return_value = mock_response
        
        result = await provider.query(mock_aiohttp_session, "ip", "8.8.8.8")
        assert result == mock_response


class TestShodan:
    """Test Shodan provider."""
    
    def test_shodan_init(self):
        """Test Shodan initialization."""
        provider = Shodan()
        assert provider.name == "shodan"
        assert provider.ioc_kinds == ("ip",)
        assert provider.bucket is not None
    
    @pytest.mark.asyncio
    async def test_shodan_query(self, mock_aiohttp_session, mock_env_vars):
        """Test Shodan query."""
        provider = Shodan()
        
        # Set the key directly since environment mocking might not work
        provider.key = "test_shodan_key"
        
        mock_response = '{"ip_str": "8.8.8.8", "ports": [53]}'
        mock_aiohttp_session.get.return_value.__aenter__.return_value.text.return_value = mock_response
        
        result = await provider.query(mock_aiohttp_session, "ip", "8.8.8.8")
        assert result == mock_response


class TestProviderGroups:
    """Test provider groupings."""
    
    def test_always_on_providers(self):
        """Test ALWAYS_ON provider group."""
        assert len(ALWAYS_ON) == 5
        provider_names = {p.name for p in ALWAYS_ON}
        expected = {"abuseipdb", "otx", "threatfox", "urlhaus", "malwarebazaar"}
        assert provider_names == expected
        
        # Verify none have rate limiting buckets
        for provider in ALWAYS_ON:
            if hasattr(provider, 'bucket'):
                assert provider.bucket is None
    
    def test_rate_limit_providers(self):
        """Test RATE_LIMIT provider group."""
        assert len(RATE_LIMIT) == 4
        provider_names = {p.name for p in RATE_LIMIT}
        expected = {"virustotal", "greynoise", "pulsedive", "shodan"}
        assert provider_names == expected
        
        # Verify all have rate limiting buckets
        for provider in RATE_LIMIT:
            assert hasattr(provider, 'bucket')
            assert provider.bucket is not None
    
    def test_all_providers_unique(self):
        """Test that all providers have unique names."""
        all_providers = list(ALWAYS_ON) + list(RATE_LIMIT)
        names = [p.name for p in all_providers]
        assert len(names) == len(set(names))  # No duplicates
    
    def test_provider_ioc_kinds(self):
        """Test that all providers specify IOC kinds."""
        all_providers = list(ALWAYS_ON) + list(RATE_LIMIT)
        for provider in all_providers:
            assert hasattr(provider, 'ioc_kinds')
            assert isinstance(provider.ioc_kinds, tuple)
            assert len(provider.ioc_kinds) > 0


class TestProviderErrorHandling:
    """Test error handling across providers."""
    
    @pytest.mark.asyncio
    async def test_provider_network_error(self, mock_aiohttp_session, mock_env_vars):
        """Test provider behavior on network errors."""
        providers_to_test = [AbuseIPDB(), OTX(), ThreatFox()]
        
        for provider in providers_to_test:
            # Mock network error
            mock_aiohttp_session.get.side_effect = aiohttp.ClientError("Connection failed")
            mock_aiohttp_session.post.side_effect = aiohttp.ClientError("Connection failed")
            
            result = await provider.query(mock_aiohttp_session, "ip", "8.8.8.8")
            assert result.startswith("error:")
            assert "Connection failed" in result
    
    @pytest.mark.asyncio
    async def test_provider_timeout_error(self, mock_aiohttp_session, mock_env_vars):
        """Test provider behavior on timeout errors."""
        provider = AbuseIPDB()
        
        # Mock timeout error
        mock_aiohttp_session.get.side_effect = asyncio.TimeoutError("Request timeout")
        
        result = await provider.query(mock_aiohttp_session, "ip", "8.8.8.8")
        assert result.startswith("error:")


class TestProviderIntegration:
    """Integration tests for provider functionality."""
    
    @pytest.mark.asyncio
    async def test_provider_with_real_session(self):
        """Test providers with real aiohttp session (no actual requests)."""
        connector = aiohttp.TCPConnector(limit=1)
        async with aiohttp.ClientSession(connector=connector) as session:
            provider = AbuseIPDB()
            provider.key = ""  # No key to avoid actual request
            
            result = await provider.query(session, "ip", "8.8.8.8")
            assert result == "nokey"
    
    def test_provider_inheritance(self):
        """Test that all providers inherit from Provider base class."""
        all_providers = list(ALWAYS_ON) + list(RATE_LIMIT)
        for provider in all_providers:
            assert isinstance(provider, Provider)
            assert hasattr(provider, 'name')
            assert hasattr(provider, 'ioc_kinds')
            assert hasattr(provider, 'query')
            assert callable(provider.query)