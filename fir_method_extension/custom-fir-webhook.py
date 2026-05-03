#!/usr/bin/env python3

import sys, json, requests, os, logging, re
from pathlib import Path
from datetime import datetime, timedelta


FIR_URL = os.getenv("FIR_API_URL", "http://localhost/api/v1/siem-ingest/")
FIR_TOKEN = os.getenv("FIR_SIEM_TOKEN", "dev-token-change-me-in-production")

CACHE_DIR = Path(os.getenv("IOC_CACHE_DIR", "/var/ossec/integrations/.ioc_cache"))
CACHE_TTL_HOURS = int(os.getenv("IOC_CACHE_TTL_HOURS", "6"))
FETCH_TIMEOUT = int(os.getenv("IOC_FETCH_TIMEOUT", "10"))


IOC_SOURCES = [
    ("ipsum_level1", "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt", "ip"),
    ("ipsum_level2", "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt", "ip"),
    ("firehol_level1", "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "ip"),
    ("blocklist_de_all", "https://lists.blocklist.de/lists/all.txt", "ip"),
    ("phishing_army", "https://phishing.army/download/phishing_army_blocklist.txt", "domain"),
]

PLAYBOOK_NAME_MAP = {
    "bruteforce": "Brute Force with Successful Login",
    "authentication_failed": "Brute Force with Successful Login",
    "port-forwarding": "Port Forwarding / Tunneling Detection",
    "tunneling": "Port Forwarding / Tunneling Detection",
    "remote-admin": "Remote Administration Tool Detection",
    "rat": "Remote Administration Tool Detection",
    "rmm": "Remote Administration Tool Detection",
    "bad-reputation": "Bad Reputation IOC Connection",
    "threat-intel": "Bad Reputation IOC Connection",
    "recon": "System Reconnaissance via CLI",
    "reconnaissance": "System Reconnaissance via CLI"
}

CATEGORY_PRIORITY_MAP = [
    (["bruteforce", "authentication_failed"], 12),      
    (["remote-admin", "rat", "rmm"], 4),                
    (["port-forwarding", "tunneling"], 21),             
    (["recon", "reconnaissance"], 14),                  
    (["bad-reputation", "threat-intel"], 18),           
    (["phishing"], 1),
    (["web-attack", "web-exploit"], 3),
    (["malware", "virus", "trojan", "ransomware"], 4),
    (["dataleak", "data-leak", "exfiltration"], 5),
    (["compromise", "breach", "unauthorized-access"], 12),
    (["vulnerability", "CVE", "exploit"], 14),
    (["dos", "ddos", "flood"], 21),
]
DEFAULT_CATEGORY_ID = 18  


logging.basicConfig(
    filename='/var/ossec/logs/integrations.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)
logger = logging.getLogger("fir_webhook")


def get_playbook_name(groups):
    if not groups:
        return None
    groups_lower = [g.lower().replace("_", "-") for g in groups]
    # 1. Точное совпадение
    for group in groups_lower:
        if group in PLAYBOOK_NAME_MAP:
            return PLAYBOOK_NAME_MAP[group]
    # 2. Частичное совпадение
    for group in groups_lower:
        for key, name in PLAYBOOK_NAME_MAP.items():
            if key in group or group in key:
                return name
    return None

def get_category_id(groups):
    if not groups:
        return DEFAULT_CATEGORY_ID
    groups_lower = [g.lower().replace("_", "-").replace(" ", "-") for g in groups]
    # 1. Точное совпадение (приоритет)
    for group_keys, cat_id in CATEGORY_PRIORITY_MAP:
        for group in groups_lower:
            if group in group_keys:
                return cat_id
    # 2. Частичное совпадение
    for group_keys, cat_id in CATEGORY_PRIORITY_MAP:
        for group in groups_lower:
            for key in group_keys:
                if key in group or group in key:
                    return cat_id
    return DEFAULT_CATEGORY_ID


def _ensure_cache_dir():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

def _cache_path(name):
    return CACHE_DIR / f"{name}.cache"

def _is_fresh(path):
    if not path.exists():
        return False
    age = datetime.now() - datetime.fromtimestamp(path.stat().st_mtime)
    return age < timedelta(hours=CACHE_TTL_HOURS)

def _parse_list(text):
    indicators = set()
    for line in text.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        if " " in line:
            line = line.split()[0]
        indicators.add(line)
    return indicators

def _fetch_list(url):
    try:
        resp = requests.get(url, timeout=FETCH_TIMEOUT)
        resp.raise_for_status()
        return _parse_list(resp.text)
    except Exception as e:
        logger.warning(f"Failed to fetch {url}: {e}")
        return set()

def _load_or_cache(name, url):
    path = _cache_path(name)
    if _is_fresh(path):
        try:
            with open(path, "r") as f:
                return set(json.load(f))
        except:
            pass
    data = _fetch_list(url)
    if data:
        try:
            with open(path, "w") as f:
                json.dump(list(data), f)
        except:
            pass
    return data

def _is_ip(s):
    return bool(re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', s))

def _is_domain(s):
    return bool(re.match(r'^[a-z0-9.-]+\.[a-z]{2,}$', s.lower()))

def _load_ioc_indices():

    _ensure_cache_dir()
    ip_idx, domain_idx = {}, {}
    for name, url, ioc_type in IOC_SOURCES:
        indicators = _load_or_cache(name, url)
        for ind in indicators:
            if ioc_type == "ip" or _is_ip(ind):
                ip_idx.setdefault(ind, []).append(name)
            if ioc_type == "domain" or _is_domain(ind):
                domain_idx.setdefault(ind, []).append(name)
    return {"ip": ip_idx, "domain": domain_idx}

_IOC_INDICES = None
def _get_ioc_indices():
    global _IOC_INDICES
    if _IOC_INDICES is None:
        _IOC_INDICES = _load_ioc_indices()
    return _IOC_INDICES

def extract_iocs(alert):
    iocs = []
    data = alert.get("data", {})
    if data.get("srcip"): iocs.append(data["srcip"])
    if data.get("dstip"): iocs.append(data["dstip"])
    if data.get("url"): iocs.append(data["url"])
    if data.get("domain"): iocs.append(data["domain"])
    
    log = alert.get("full_log", "")
    iocs.extend(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', log)) 
    iocs.extend(re.findall(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', log)) 
    
    return list(set(i for i in iocs if i and not i.startswith("127.") and i not in ["localhost", "0.0.0.0"]))

def enrich_iocs(iocs):

    try:
        indices = _get_ioc_indices()
        matches = {}
        for ioc in iocs:
            ioc_l = ioc.lower()
            if _is_ip(ioc_l) and ioc_l in indices["ip"]:
                matches[ioc] = {"sources": indices["ip"][ioc_l], "type": "ip"}
            elif _is_domain(ioc_l) and ioc_l in indices["domain"]:
                matches[ioc] = {"sources": indices["domain"][ioc_l], "type": "domain"}
        
        if not matches:
            return None
        
        parts = []
        for ioc, info in matches.items():
            src = ", ".join(info["sources"][:2])
            if len(info["sources"]) > 2:
                src += f" +{len(info['sources'])-2}"
            parts.append(f"{ioc} ({info['type']}) в {src}")
        return "[THREAT-INTEL] Совпадения: " + " | ".join(parts)
    except Exception as e:
        logger.warning(f"IOC enrichment failed: {e}")
        return None

def main():
    if len(sys.argv) < 2:
        logger.error("No alert file provided")
        sys.exit(1)
    
    alert_path = sys.argv[1]
    try:
        with open(alert_path, 'r') as f:
            alert = json.load(f)
    except Exception as e:
        logger.error(f"Failed to read alert: {e}")
        sys.exit(1)

    rule = alert.get("rule", {})
    level = rule.get("level", 0)
    groups = rule.get("groups", [])
    
    
    if level >= 10: severity = "critical"
    elif level >= 7: severity = "high"
    elif level >= 5: severity = "medium"
    else: severity = "low"

   
    playbook_name = get_playbook_name(groups)
    category_id = get_category_id(groups)
    
    
    iocs = extract_iocs(alert)
    threat_note = enrich_iocs(iocs) if iocs else None
    
    
    base_desc = f"Rule ID: {rule.get('id', 'N/A')} | Groups: {groups} | Agent: {alert.get('agent', {}).get('name', 'N/A')}\n\nLog: {alert.get('full_log', '')}"
    if threat_note:
        base_desc += f"\n\n{threat_note}"

    payload = {
        "source": "wazuh",
        "title": rule.get("description", "Wazuh Security Alert"),
        "severity": severity,
        "description": base_desc,
        "category_id": category_id,
        "playbook_name": playbook_name
    }

    headers = {"Content-Type": "application/json", "X-FIR-API-Token": FIR_TOKEN}
    try:
        resp = requests.post(FIR_URL, json=payload, headers=headers, timeout=10)
        if resp.status_code == 201:
            logger.info(f"Incident created in FIR: {resp.text}")
            sys.exit(0)
        else:
            logger.error(f"FIR returned {resp.status_code}: {resp.text}")
            sys.exit(1)
    except Exception as e:
        logger.error(f"Request to FIR failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
