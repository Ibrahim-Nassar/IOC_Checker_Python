"""Base provider class for IOC Checker with shared functionality."""
from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Literal

import httpx
from ioc_types import IOCResult, IOCStatus


class BaseProvider(ABC):
    """Base provider class with shared functionality."""
    
    NAME: str = ""  # Should be overridden by subclasses
    SUPPORTED_TYPES: set[str] = set()  # Should be overridden by subclasses
    
    def __init__(self, api_key: str | None = None, timeout: float = 15.0) -> None:
        self._key = api_key
        self.timeout = timeout
        if not self._key:
            raise RuntimeError(f"{self.NAME} API key not found")
    
    @abstractmethod
    async def query_ioc(self, ioc: str, ioc_type: Literal["ip", "domain", "url", "hash"]) -> IOCResult:
        """Query the provider for IOC information. Must be implemented by subclasses."""
        pass
    
    async def _safe_request(self, url: str, method: str = "GET", json_data: Dict[str, Any] = None, 
                           headers: Dict[str, str] = None, max_retries: int = 3) -> Dict[str, Any]:
        """
        Perform a safe HTTP request with retries, status checking, and JSON parsing.
        
        Args:
            url: The URL to request
            method: HTTP method ('GET' or 'POST')
            json_data: JSON data for POST requests
            headers: HTTP headers
            max_retries: Maximum number of retry attempts
            
        Returns:
            Parsed JSON response
            
        Raises:
            Exception: If request fails after all retries
        """
        last_exception = None
        
        for attempt in range(max_retries):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    if method.upper() == "GET":
                        resp = await client.get(url, headers=headers)
                    elif method.upper() == "POST":
                        resp = await client.post(url, json=json_data or {}, headers=headers)
                    else:
                        raise ValueError(f"Unsupported HTTP method: {method}")
                
                # Check status code
                if resp.status_code == 200:
                    return resp.json()
                elif resp.status_code == 429:  # Rate limited
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt  # Exponential backoff
                        logging.warning(f"{self.NAME}: Rate limited, waiting {wait_time}s before retry")
                        await asyncio.sleep(wait_time)
                        continue
                    else:
                        raise Exception(f"Rate limited after {max_retries} retries")
                elif resp.status_code == 403:
                    raise Exception("API key invalid or insufficient permissions")
                elif resp.status_code == 404:
                    raise Exception("Resource not found")
                elif resp.status_code >= 500:
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt
                        logging.warning(f"{self.NAME}: Server error {resp.status_code}, retrying in {wait_time}s")
                        await asyncio.sleep(wait_time)
                        continue
                    else:
                        raise Exception(f"Server error {resp.status_code} after {max_retries} retries")
                else:
                    raise Exception(f"HTTP {resp.status_code}")
                    
            except Exception as e:
                last_exception = e
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt
                    logging.warning(f"{self.NAME}: Request failed ({e}), retrying in {wait_time}s")
                    await asyncio.sleep(wait_time)
                else:
                    break
        
        # If we get here, all retries failed
        raise last_exception or Exception("Request failed after all retries")
    
    def _create_error_result(self, ioc: str, ioc_type: str, message: str) -> IOCResult:
        """Create a standardized error result."""
        return IOCResult(
            ioc=ioc,
            ioc_type=ioc_type,
            status=IOCStatus.ERROR,
            malicious_engines=0,
            total_engines=0,
            message=message
        )
    
    def _create_success_result(self, ioc: str, ioc_type: str, malicious_engines: int, 
                              total_engines: int, message: str = "") -> IOCResult:
        """Create a standardized success result."""
        status = IOCStatus.MALICIOUS if malicious_engines > 0 else IOCStatus.SUCCESS
        return IOCResult(
            ioc=ioc,
            ioc_type=ioc_type,
            status=status,
            malicious_engines=malicious_engines,
            total_engines=total_engines,
            message=message
        )
    
    def _create_unsupported_result(self, ioc: str, ioc_type: str, message: str = None) -> IOCResult:
        """Create a standardized unsupported result."""
        return IOCResult(
            ioc=ioc,
            ioc_type=ioc_type,
            status=IOCStatus.UNSUPPORTED,
            malicious_engines=0,
            total_engines=0,
            message=message or f"{ioc_type} not supported by {self.NAME}"
        )


__all__ = ["BaseProvider"] 