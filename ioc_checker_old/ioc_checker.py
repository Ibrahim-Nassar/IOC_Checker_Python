#!/usr/bin/env python3
import os, sys, re, ipaddress, base64, asyncio, logging, json, csv, urllib.parse
from datetime import datetime, timedelta
from typing import Dict, Any, List
import aiohttp
from dotenv import load_dotenv
import argparse

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

BASE_DIR = getattr(sys, "_MEIPASS", os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

API_KEYS = {
    "abuseipdb": os.getenv("ABUSEIPDB_API_KEY", "").strip(),
    "virustotal": os.getenv("VIRUSTOTAL_API_KEY", "").strip(),
    "otx":        os.getenv("OTX_API_KEY", "").strip(),
    "threatfox":  os.getenv("THREATFOX_API_KEY", "").strip(),
}

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%H:%M:%S", level=logging.INFO)
log = logging.getLogger("ioc_checker")

DOMAIN_RX = re.compile(r"^(?=.{4,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                       r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,}$")
HASH_RX   = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")

class TokenBucket:
    def __init__(self, capacity: int, interval: int):
        self.capacity = capacity
        self.tokens = capacity
        self.interval = interval
        self.updated = datetime.utcnow()
        self._lock = asyncio.Lock()
        self._wait = asyncio.Event(); self._wait.set()

    async def acquire(self):
        async with self._lock:
            self._refill()
            while not self.tokens:
                self._wait.clear()
                await self._wait.wait()
            self.tokens -= 1

    def _refill(self):
        gained = int((datetime.utcnow() - self.updated).total_seconds() // self.interval)
        if gained:
            self.tokens = min(self.capacity, self.tokens + gained)
            self.updated += timedelta(seconds=gained * self.interval)
            self._wait.set()

VT_BUCKET = TokenBucket(4, 60)

def _extract_ip(v: str) -> str:
    if v.startswith('[') and ']:' in v: return v.split(']:')[0][1:]
    if v.count(':') == 1: return v.split(':')[0]
    return v

def _valid_ip(v: str) -> bool:
    try: ipaddress.ip_address(_extract_ip(v)); return True
    except ValueError: return False

def _valid_domain(v: str) -> bool: return bool(DOMAIN_RX.fullmatch(v))
def _valid_url(v: str) -> bool:
    p = urllib.parse.urlparse(v); return p.scheme in ("http", "https") and bool(p.netloc)
def _valid_hash(v: str) -> bool: return bool(HASH_RX.fullmatch(v))

VALIDATORS = {"ip": _valid_ip, "domain": _valid_domain, "url": _valid_url, "hash": _valid_hash}

HEADERS = {"User-Agent": "ioc-checker/0.6"}

async def api_request(s: aiohttp.ClientSession, method: str, url: str, *,
                      hdr: Dict = None, **kw) -> Any:
    h = HEADERS | (hdr or {})
    try:
        async with s.request(method, url, headers=h,
                             timeout=kw.pop("timeout", aiohttp.ClientTimeout(total=15)), **kw) as r:
            if r.status != 200:
                return {"error": f"{r.status} {r.reason}", "body": (await r.text())[:120]}
            try:
                return await r.json()
            except json.JSONDecodeError:
                return {"error": "non-JSON", "body": (await r.text())[:120]}
    except Exception as e:
        return {"error": str(e)}

async def _abuseipdb_ip(s, ip):
    if not API_KEYS["abuseipdb"]: return {"error": "No key"}
    return await api_request(s, "GET",
        "https://api.abuseipdb.com/api/v2/check",
        hdr={"Key": API_KEYS["abuseipdb"], "Accept": "application/json"},
        params={"ipAddress": _extract_ip(ip), "maxAgeInDays": 30})

async def _vt_req(s, path):
    if not API_KEYS["virustotal"]: return {"error": "No key"}
    await VT_BUCKET.acquire()
    return await api_request(s, "GET", f"https://www.virustotal.com/api/v3/{path}",
                             hdr={"x-apikey": API_KEYS["virustotal"]})

async def _virustotal_ip(s, ip):      return await _vt_req(s, f"ip_addresses/{_extract_ip(ip)}")
async def _virustotal_domain(s, d):   return await _vt_req(s, f"domains/{d}")
async def _virustotal_url(s, u):
    enc = base64.urlsafe_b64encode(u.encode()).decode().strip("=")
    return await _vt_req(s, f"urls/{enc}")
async def _virustotal_hash(s, h):     return await _vt_req(s, f"files/{h}")

async def _otx(s, kind, value):
    if not API_KEYS["otx"]: return {"error": "No key"}
    hdr = {"X-OTX-API-KEY": API_KEYS["otx"]}
    return await api_request(s, "GET", f"https://otx.alienvault.com/api/v1/indicators/{kind}/{value}/general",
                             hdr=hdr)

async def _otx_ip(s, ip):
    ip_clean=_extract_ip(ip)
    kind="IPv4" if ipaddress.ip_address(ip_clean).version==4 else "IPv6"
    return await _otx(s, kind, ip_clean)
async def _otx_domain(s,d): return await _otx(s,"domain",d)
async def _otx_hash(s,h):   return await _otx(s,"file",h)
async def _otx_url(s,u):
    hdr={"X-OTX-API-KEY":API_KEYS["otx"],"Content-Type":"application/json"}
    return await api_request(s,"POST",
        "https://otx.alienvault.com/api/v1/indicators/url/general",
        hdr=hdr,json={"indicator":u})

async def _threatfox(s, indicator):
    hdr={"Content-Type":"application/json"}
    if API_KEYS["threatfox"]: hdr["Auth-Key"]=API_KEYS["threatfox"]
    res=await api_request(s,"POST","https://threatfox-api.abuse.ch/api/v1/",
                          hdr=hdr,json={"query":"search_ioc","search_term":indicator,"exact_match":True})
    if res.get("query_status")=="no_result" and ':' in indicator and indicator.count(':')==1:
        res=await api_request(s,"POST","https://threatfox-api.abuse.ch/api/v1/",
                              hdr=hdr,json={"query":"search_ioc","search_term":_extract_ip(indicator),"exact_match":True})
    return res

async def _urlhaus_url(s,u):
    return await api_request(s,"POST","https://urlhaus-api.abuse.ch/v1/url/",data={"url":u})

async def _malwarebazaar_hash(s,h):
    return await api_request(s,"POST","https://mb-api.abuse.ch/api/v1/",data={"query":"get_info","hash":h})

FETCHERS = {
    "ip":    {"abuseipdb": _abuseipdb_ip, "virustotal": _virustotal_ip,
              "otx": _otx_ip, "threatfox": _threatfox},
    "domain":{"virustotal": _virustotal_domain, "otx": _otx_domain,
              "threatfox": _threatfox},
    "url":   {"virustotal": _virustotal_url, "otx": _otx_url,
              "urlhaus": _urlhaus_url, "threatfox": _threatfox},
    "hash":  {"virustotal": _virustotal_hash, "otx": _otx_hash,
              "malwarebazaar": _malwarebazaar_hash, "threatfox": _threatfox},
}

def _status_icon(ok: bool) -> str: return "🚨" if ok else "✅"

def parse_result(svc: str, r: Dict) -> str:
    if "error" in r: return f"❌ {r['error']}"
    if svc=="virustotal":
        st=r.get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
        mal, sus = st.get("malicious",0), st.get("suspicious",0)
        return f"{_status_icon(mal or sus)} Malicious:{mal} Suspicious:{sus}"
    if svc=="abuseipdb":
        c=r.get("data",{}).get("abuseConfidencePercentage",0)
        if r.get("data",{}).get("isWhitelisted"): return "✅ Whitelisted"
        if not r.get("data",{}).get("isPublic",True): return "ℹ️ Private/Local"
        if c>75: return f"🚨 Abuse {c}%"
        if c>25: return f"⚠️ Abuse {c}%"
        return f"✅ Abuse {c}%"
    if svc=="otx":
        p=r.get("pulse_info",{}).get("count",0)
        return f"{_status_icon(p)} Found in {p} pulse(s)" if p else "✅ Not found"
    if svc=="threatfox":
        ok = r.get("query_status")=="ok" and r.get("data")
        n  = len(r.get("data",[]))
        return f"{_status_icon(ok)} ThreatFox {n}" if ok else "✅ ThreatFox none"
    if svc=="urlhaus":
        return "🚨 URLhaus hit" if r.get("query_status")=="ok" else "✅ URLhaus none"
    if svc=="malwarebazaar":
        return "🚨 MalwareBazaar hit" if r.get("query_status")=="ok" else "✅ MalwareBazaar none"
    return "ℹ️ Unparsed"

async def _check_one(ioc_type:str, value:str, session:aiohttp.ClientSession, no_virustotal:bool=False):
    fetchers = FETCHERS[ioc_type].copy()
    if no_virustotal and "virustotal" in fetchers:
        del fetchers["virustotal"]
    
    coros=[f(session,value) for f in fetchers.values()]
    names=list(fetchers)
    outs={}
    for name,res in zip(names, await asyncio.gather(*coros,return_exceptions=True)):
        if isinstance(res,Exception): res={"error":str(res)}
        txt=parse_result(name,res)
        log.info("[%s] %s",name,txt)
        outs[name]={"formatted":txt,"is_threat":"🚨" in txt}
    return outs

async def run_checks(ioc_type:str, value:str, session:aiohttp.ClientSession, no_virustotal:bool=False):
    if not VALIDATORS[ioc_type](value):
        log.error("Invalid %s: %s",ioc_type,value); return
    log.info("Checking %s %s",ioc_type,value)
    res=await _check_one(ioc_type,value,session,no_virustotal)
    log.info("Completed %s → %s",ioc_type,value)
    return res

def detect_ioc_type(v:str)->str:
    v=v.strip()
    if _valid_hash(v): return "hash"
    if _valid_url(v):  return "url"
    if _valid_ip(v):   return "ip"
    if _valid_domain(v):return "domain"
    return "unknown"

async def test_suite(session, no_virustotal:bool=False):  # unchanged functional output
    cases = {"ip":["8.8.8.8","1.1.1.1","8.8.8.8:53"],
             "domain":["example.com","google.com"],
             "url":["https://google.com"],
             "hash":["d41d8cd98f00b204e9800998ecf8427e"]}
    for t,vals in cases.items():
        for v in vals: await run_checks(t,v,session,no_virustotal)

def _csv_map(fields:List[str])->Dict[str,str]:
    f=[x.lower().strip() for x in fields]
    m={}
    for v in ('ioc_type','type','category'):  # simple
        if v in f: m['type']=fields[f.index(v)]; break
    for v in ('ioc_value','value','indicator','url','domain','ip','hash'):
        if v in f: m['value']=fields[f.index(v)]; break
    return m

async def _process_csv(path:str,out:str,session,no_virustotal:bool=False):
    with open(path,encoding='utf-8') as fh:
        buf=fh.read(2048); fh.seek(0)
        delim=csv.Sniffer().sniff(buf).delimiter
        rdr=csv.DictReader(fh,delimiter=delim)
        rows=list(rdr)
    log.info("Found %d IOCs",len(rows))
    mp=_csv_map(rdr.fieldnames)
    if 'value' not in mp:
        log.error("No IOC column"); return
    results=[]
    for i,row in enumerate(rows,1):
        t=row.get(mp.get('type',''), '').lower().strip()
        v=row.get(mp['value'],'').strip()
        if not v: continue
        if t not in VALIDATORS: t=detect_ioc_type(v)
        if t=="unknown": continue
        r=await _check_one(t,v,session,no_virustotal)
        result_row={'ioc_type':t,'ioc_value':v}
        result_row.update({k:r[k]['formatted'] for k in r})
        results.append(result_row)
        if i%25==0: log.info("Processed %d/%d",i,len(rows))
    if results:
        with open(out,'w',encoding='utf-8',newline='') as fh:
            w=csv.DictWriter(fh,fieldnames=results[0].keys()); w.writeheader(); w.writerows(results)
        log.info("Results → %s",out)
    else:
        log.info("No valid results to save")

def _args():
    p=argparse.ArgumentParser()
    p.add_argument("ioc_type", nargs="?", choices=list(VALIDATORS))
    p.add_argument("value", nargs="?")
    p.add_argument("--file")
    p.add_argument("--csv")
    p.add_argument("--output")
    p.add_argument("--test", action="store_true")
    p.add_argument("--no-virustotal", action="store_true", help="Skip VirusTotal checks")
    return p.parse_args()

async def main():
    a=_args()
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit_per_host=10,ssl=False,
                              force_close=True)) as s:
        if a.test: await test_suite(s,a.no_virustotal); return
        if a.csv:
            out=a.output or f"{os.path.splitext(a.csv)[0]}_results.csv"
            await _process_csv(a.csv,out,s,a.no_virustotal); return
        if a.file:
            if not a.ioc_type: log.error("--file needs type"); return
            for ln in open(a.file,encoding='utf-8'):
                if ln.strip(): await run_checks(a.ioc_type,ln.strip(),s,a.no_virustotal)
            return
        if a.ioc_type and a.value:
            await run_checks(a.ioc_type,a.value,s,a.no_virustotal); return
        tp=input("IOC type: ").strip().lower()
        val=input("Value: ").strip()
        await run_checks(tp,val,s)

if __name__=="__main__":
    asyncio.run(main())
    print("[DONE]")
