#!/usr/bin/env python3
"""Debug VirusTotal response for 8.8.8.8"""
import asyncio
import aiohttp
import json
from providers import VirusTotal

async def test_vt():
    vt = VirusTotal()
    if not vt.key:
        print("No VirusTotal API key configured")
        return
    
    async with aiohttp.ClientSession() as session:
        result = await vt.query(session, 'ip', '1.1.1.1')
        print("Raw VirusTotal response for 1.1.1.1:")
        try:
            data = json.loads(result) if isinstance(result, str) else result
            print(json.dumps(data, indent=2))
        except:
            print(f"Non-JSON response: {result}")

if __name__ == "__main__":
    asyncio.run(test_vt())
