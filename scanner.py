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

# Per-key state: exhausted (daily quota), invalid (401), rate_limited (per-minute), used count
# { key -> {"exhausted": bool, "invalid": bool, "exhausted_at": dt|None, "rate_limited_until": dt|None, "used": int} }
_key_states = {}
_key_states_lock = threading.Lock()

RATE_LIMIT_COOLDOWN = 60  # seconds to cool down after a 429


def _utc_now():
    return datetime.now(timezone.utc)


def _utc_today():
    return _utc_now().date()


def init_key_states(keys):
    with _key_states_lock:
        for key in keys:
            if key not in _key_states:
                _key_states[key] = {
                    "exhausted": False,
                    "invalid": False,
                    "exhausted_at": None,
                    "rate_limited_until": None,
                    "used": 0,
                }


def _mark_exhausted(key):
    with _key_states_lock:
        if key in _key_states:
            _key_states[key]["exhausted"] = True
            _key_states[key]["exhausted_at"] = _utc_now()


def _mark_invalid(key):
    with _key_states_lock:
        if key in _key_states:
            _key_states[key]["invalid"] = True


def _mark_rate_limited(key):
    with _key_states_lock:
        if key in _key_states:
            _key_states[key]["rate_limited_until"] = _utc_now().replace(
                microsecond=0
            ).__class__.fromtimestamp(
                _utc_now().timestamp() + RATE_LIMIT_COOLDOWN, tz=timezone.utc
            )


def _increment_used(key):
    with _key_states_lock:
        if key in _key_states:
            _key_states[key]["used"] += 1


def _is_unavailable(key):
    """Returns True if key is invalid, exhausted (daily), or rate-limited (cooldown not expired)."""
    with _key_states_lock:
        state = _key_states.get(key)
        if not state:
            return False
        if state.get("invalid"):
            return True
        # Daily quota exhausted — auto-reset at UTC midnight
        if state["exhausted"]:
            exhausted_date = state["exhausted_at"].date() if state["exhausted_at"] else None
            if exhausted_date and exhausted_date < _utc_today():
                state["exhausted"] = False
                state["exhausted_at"] = None
                state["used"] = 0
            else:
                return True
        # Per-minute rate limit cooldown
        if state["rate_limited_until"] and _utc_now() < state["rate_limited_until"]:
            return True
        elif state["rate_limited_until"] and _utc_now() >= state["rate_limited_until"]:
            state["rate_limited_until"] = None  # cooldown expired
        return False


def get_key_status():
    with _key_states_lock:
        result = {}
        for k, v in _key_states.items():
            if v.get("invalid"):
                status = "invalid"
            elif v["exhausted"]:
                status = "exhausted"
            elif v["rate_limited_until"] and _utc_now() < v["rate_limited_until"]:
                status = "rate_limited"
            else:
                status = "active"
            result[k[-8:]] = {"status": status, "used": v["used"]}
        return result


def all_keys_exhausted(keys):
    """True only if ALL keys have hit the daily quota (not just rate-limited)."""
    with _key_states_lock:
        for key in keys:
            state = _key_states.get(key)
            if not state or not state["exhausted"]:
                return False
        return True


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
                "country": attrs.get("country", "-"),
                "owner": attrs.get("as_owner", "-"),
                "asn": attrs.get("asn", "-"),
                "error": None,
                "key_suffix": key[-8:],
            }
        elif r.status_code == 429:
            # Rate limited — put this key on cooldown, caller will retry with another key
            _mark_rate_limited(key)
            return None  # signal: retry with different key
        elif r.status_code == 403:
            _mark_exhausted(key)
            return None  # signal: retry with different key
        elif r.status_code == 401:
            _mark_invalid(key)
            return None  # signal: retry with different key
        elif r.status_code == 404:
            _increment_used(key)
            return {"ip": ip, "verdict": "not_found", "malicious": 0, "suspicious": 0,
                    "harmless": 0, "undetected": 0, "country": "-", "owner": "-", "asn": "-",
                    "error": "Not found in VT", "key_suffix": key[-8:]}
        else:
            return {"ip": ip, "verdict": "error", "malicious": 0, "suspicious": 0,
                    "harmless": 0, "undetected": 0, "country": "-", "owner": "-", "asn": "-",
                    "error": f"HTTP {r.status_code}", "key_suffix": key[-8:]}
    except requests.exceptions.Timeout:
        return {"ip": ip, "verdict": "error", "malicious": 0, "suspicious": 0,
                "harmless": 0, "undetected": 0, "country": "-", "owner": "-", "asn": "-",
                "error": "Timeout", "key_suffix": key[-8:]}
    except Exception as e:
        return {"ip": ip, "verdict": "error", "malicious": 0, "suspicious": 0,
                "harmless": 0, "undetected": 0, "country": "-", "owner": "-", "asn": "-",
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

    def pick_key(exclude=None):
        """Return next available key, skipping unavailable and optionally excluded ones."""
        with key_lock:
            for _ in range(len(keys) * 2):
                k = next(key_cycle)
                if k != exclude and not _is_unavailable(k):
                    return k
            return None

    def scan_one(ip):
        attempts = 0
        max_attempts = max(len(keys) * 4, 8)
        while attempts < max_attempts:
            key = pick_key()
            if key is None:
                time.sleep(5)
                attempts += 1
                continue
            result = _scan_ip(ip, key, timeout)
            if result is not None:
                return result
            attempts += 1
        return {"ip": ip, "verdict": "error", "malicious": 0, "suspicious": 0,
                "harmless": 0, "undetected": 0, "country": "-", "owner": "-", "asn": "-",
                "error": "All keys unavailable (invalid, rate-limited, or exhausted)", "key_suffix": "-"}

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
