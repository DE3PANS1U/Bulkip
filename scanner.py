import time
import threading
import requests
import itertools
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{}"

# Global job store
_jobs = {}
_jobs_lock = threading.Lock()

# Per-key exhaustion tracker: { key -> {"exhausted": bool, "exhausted_at": datetime|None, "used": int} }
_key_states = {}
_key_states_lock = threading.Lock()


def _utc_today():
    return datetime.now(timezone.utc).date()


def init_key_states(keys):
    with _key_states_lock:
        for key in keys:
            if key not in _key_states:
                _key_states[key] = {"exhausted": False, "exhausted_at": None, "used": 0}


def _mark_exhausted(key):
    with _key_states_lock:
        if key in _key_states:
            _key_states[key]["exhausted"] = True
            _key_states[key]["exhausted_at"] = datetime.now(timezone.utc)


def _increment_used(key):
    with _key_states_lock:
        if key in _key_states:
            _key_states[key]["used"] += 1


def _is_exhausted(key):
    with _key_states_lock:
        state = _key_states.get(key)
        if not state or not state["exhausted"]:
            return False
        # Auto-reset if the exhausted_at date is before today (VT resets at midnight UTC)
        exhausted_date = state["exhausted_at"].date() if state["exhausted_at"] else None
        if exhausted_date and exhausted_date < _utc_today():
            state["exhausted"] = False
            state["exhausted_at"] = None
            state["used"] = 0
            return False
        return True


def get_key_status():
    with _key_states_lock:
        return {
            k[-8:]: {  # show only last 8 chars for display
                "exhausted": v["exhausted"],
                "used": v["used"],
            }
            for k, v in _key_states.items()
        }


def all_keys_exhausted(keys):
    return all(_is_exhausted(k) for k in keys)


def _get_next_key(keys):
    """Return the next non-exhausted key, or None if all are exhausted."""
    for key in keys:
        if not _is_exhausted(key):
            return key
    return None


def _new_job(job_id, ips, api_keys, workers):
    job = {
        "id": job_id,
        "status": "queued",
        "total": len(ips),
        "done": 0,
        "results": [],
        "cancelled": False,
        "started_at": datetime.utcnow().isoformat(),
        "finished_at": None,
        "ips": ips,
        "api_keys": api_keys,
        "workers": workers,
        "keys_exhausted": False,
    }
    with _jobs_lock:
        _jobs[job_id] = job
    return job


def get_job(job_id):
    with _jobs_lock:
        return _jobs.get(job_id)


def cancel_job(job_id):
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job and job["status"] == "running":
            job["cancelled"] = True
            return True
    return False


def _classify(stats):
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    if mal > 0:
        return "malicious"
    if sus > 0:
        return "suspicious"
    return "clean"


def _scan_ip(ip, key, timeout):
    headers = {"x-apikey": key}
    try:
        r = requests.get(VT_URL.format(ip), headers=headers, timeout=timeout)
        if r.status_code == 200:
            _increment_used(key)
            data = r.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "ip": ip,
                "verdict": _classify(stats),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "country": attrs.get("country", "—"),
                "owner": attrs.get("as_owner", "—"),
                "asn": attrs.get("asn", "—"),
                "error": None,
                "key_suffix": key[-8:],
            }
        elif r.status_code == 403:
            # Quota exceeded — mark this key as exhausted
            _mark_exhausted(key)
            return {"ip": ip, "verdict": "error", "malicious": 0, "suspicious": 0,
                    "harmless": 0, "undetected": 0, "country": "—", "owner": "—", "asn": "—",
                    "error": "Key quota exceeded (403)", "key_suffix": key[-8:]}
        elif r.status_code == 404:
            _increment_used(key)
            return {"ip": ip, "verdict": "not_found", "malicious": 0, "suspicious": 0,
                    "harmless": 0, "undetected": 0, "country": "—", "owner": "—", "asn": "—",
                    "error": "Not found in VT", "key_suffix": key[-8:]}
        elif r.status_code == 429:
            return {"ip": ip, "verdict": "error", "malicious": 0, "suspicious": 0,
                    "harmless": 0, "undetected": 0, "country": "—", "owner": "—", "asn": "—",
                    "error": "Rate limited (429)", "key_suffix": key[-8:]}
        else:
            return {"ip": ip, "verdict": "error", "malicious": 0, "suspicious": 0,
                    "harmless": 0, "undetected": 0, "country": "—", "owner": "—", "asn": "—",
                    "error": f"HTTP {r.status_code}", "key_suffix": key[-8:]}
    except requests.exceptions.Timeout:
        return {"ip": ip, "verdict": "error", "malicious": 0, "suspicious": 0,
                "harmless": 0, "undetected": 0, "country": "—", "owner": "—", "asn": "—",
                "error": "Timeout", "key_suffix": key[-8:]}
    except Exception as e:
        return {"ip": ip, "verdict": "error", "malicious": 0, "suspicious": 0,
                "harmless": 0, "undetected": 0, "country": "—", "owner": "—", "asn": "—",
                "error": str(e), "key_suffix": key[-8:]}


def _run_scan(job_id):
    job = get_job(job_id)
    if not job:
        return

    job["status"] = "running"
    ips = job["ips"]
    keys = job["api_keys"]
    workers = job["workers"]
    timeout = 30

    init_key_states(keys)

    # Use a cycling index for round-robin but skip exhausted keys
    key_cycle = itertools.cycle(keys)
    key_lock = threading.Lock()
    results = []

    def pick_key():
        # Try up to len(keys) times to find a non-exhausted key
        with key_lock:
            for _ in range(len(keys)):
                k = next(key_cycle)
                if not _is_exhausted(k):
                    return k
            return None  # all exhausted

    def scan_one(ip):
        key = pick_key()
        if key is None:
            return {"ip": ip, "verdict": "error", "malicious": 0, "suspicious": 0,
                    "harmless": 0, "undetected": 0, "country": "—", "owner": "—", "asn": "—",
                    "error": "All API keys exhausted for today", "key_suffix": "—"}
        result = _scan_ip(ip, key, timeout)
        # If this key just got exhausted, retry once with a different key
        if result.get("error") == "Key quota exceeded (403)":
            key2 = pick_key()
            if key2 and key2 != key:
                result = _scan_ip(ip, key2, timeout)
        return result

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_one, ip): ip for ip in ips}
        for future in as_completed(futures):
            if job["cancelled"]:
                executor.shutdown(wait=False, cancel_futures=True)
                break
            result = future.result()
            results.append(result)
            job["done"] += 1
            job["results"] = results
            # Flag if all keys are now exhausted
            if all_keys_exhausted(keys):
                job["keys_exhausted"] = True

    if job["cancelled"]:
        job["status"] = "cancelled"
    else:
        job["status"] = "complete"
    job["finished_at"] = datetime.utcnow().isoformat()


def start_scan(job_id, ips, api_keys, workers=10):
    _new_job(job_id, ips, api_keys, workers)
    t = threading.Thread(target=_run_scan, args=(job_id,), daemon=True)
    t.start()


def parse_ips(text):
    seen = set()
    valid = []
    for token in text.replace(",", "\n").replace(";", "\n").split():
        token = token.strip()
        if not token:
            continue
        try:
            ipaddress.ip_address(token)
            if token not in seen:
                seen.add(token)
                valid.append(token)
        except ValueError:
            pass
    return valid
