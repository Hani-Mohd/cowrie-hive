"""Reads Cowrie JSON logs (plain or .gz) and builds the dashboard summary."""
import glob
import gzip
import json
import os
import threading
import time
from collections import Counter, deque
from functools import lru_cache

try:
    import maxminddb
except ImportError:  # dashboard still works, the map just stays empty
    maxminddb = None

LOG_DIR = os.environ.get("COWRIE_LOG_DIR", "/home/cowrie/cowrie/var/log/cowrie")
GEOIP_DB = os.environ.get("GEOIP_DB", "/var/lib/cowrie-dashboard/dbip-country-lite.mmdb")
TTL = 15  # seconds before the merged result is rebuilt

try:
    _geo = maxminddb.open_database(GEOIP_DB) if maxminddb else None
except (OSError, ValueError):
    _geo = None


@lru_cache(maxsize=None)
def country_of(ip):
    """Two-letter country code for an IP, or None if unknown. Fully local."""
    if _geo is None:
        return None
    try:
        rec = _geo.get(ip) or {}
    except ValueError:  # not a valid IP string
        return None
    c = rec.get("country") or rec.get("registered_country") or {}
    return c.get("iso_code")

_lock = threading.Lock()
_file_cache = {}                       # path -> (signature, parsed file)
_result = {"time": 0.0, "data": None}  # last merged result


def parse_file(path):
    """Summarize one log file."""
    ips, users, pw, days = {}, Counter(), Counter(), Counter()
    cmds, events = Counter(), deque(maxlen=200)
    n = bad = 0
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except ValueError:
                bad += 1
                continue
            n += 1
            ip, ts = e.get("src_ip"), e.get("timestamp")
            if not ip or not ts:
                continue
            r = ips.get(ip)
            if r is None:
                r = ips[ip] = {"ip": ip, "sess": 0, "fail": 0, "ok": 0,
                               "cmds": 0, "first": ts, "last": ts}
            r["first"] = min(r["first"], ts)
            r["last"] = max(r["last"], ts)
            ev = e.get("eventid")
            if ev == "cowrie.session.connect":
                r["sess"] += 1
                days[ts[:10]] += 1
            elif ev in ("cowrie.login.failed", "cowrie.login.success"):
                r["fail" if ev.endswith("failed") else "ok"] += 1
                users[e.get("username", "")] += 1
                pw[e.get("password", "")] += 1
            elif ev == "cowrie.command.input":
                r["cmds"] += 1
                cmds[e.get("input", "")] += 1
                events.append([ts, ip, "cmd", e.get("input", "")])
            elif ev == "cowrie.session.file_download":
                events.append([ts, ip, "download", e.get("url") or e.get("outfile", "")])
    return {"ips": ips, "users": users, "pw": pw, "days": days,
            "cmds": cmds, "events": list(events), "n": n, "bad": bad}


def snapshot():
    """Merge all log files into one summary dict (cached for TTL seconds)."""
    with _lock:
        if _result["data"] and time.time() - _result["time"] < TTL:
            return _result["data"]
        paths = sorted(glob.glob(os.path.join(LOG_DIR, "cowrie.json*")))
        ips, users, pw, days = {}, Counter(), Counter(), Counter()
        cmds, events = Counter(), []
        n = bad = 0
        for p in paths:
            try:
                st = os.stat(p)
                sig = (st.st_mtime_ns, st.st_size)
                cached = _file_cache.get(p)
                if not cached or cached[0] != sig:  # rotated files parse once
                    cached = _file_cache[p] = (sig, parse_file(p))
            except OSError:
                continue  # file rotated away mid-read
            a = cached[1]
            n += a["n"]
            bad += a["bad"]
            users.update(a["users"])
            pw.update(a["pw"])
            days.update(a["days"])
            cmds.update(a["cmds"])
            events.extend(a["events"])
            for ip, r in a["ips"].items():
                m = ips.get(ip)
                if m is None:
                    ips[ip] = dict(r)
                    continue
                for k in ("sess", "fail", "ok", "cmds"):
                    m[k] += r[k]
                m["first"] = min(m["first"], r["first"])
                m["last"] = max(m["last"], r["last"])
        for p in list(_file_cache):
            if p not in paths:
                del _file_cache[p]
        geo = {}  # country code -> [sessions, unique IPs]; "??" = unknown
        for r in ips.values():
            g = geo.setdefault(country_of(r["ip"]) or "??", [0, 0])
            g[0] += r["sess"]
            g[1] += 1
        data = {
            "geo": sorted(([cc, s, n] for cc, (s, n) in geo.items()),
                          key=lambda x: -x[1]),
            "geo_ok": _geo is not None,
            "ips": sorted(ips.values(), key=lambda r: -r["sess"]),
            "users": users.most_common(10),
            "pw": pw.most_common(10),
            "cmds": cmds.most_common(10),
            "events": sorted(events)[-150:][::-1],
            "days": sorted(days.items()),
            "n": n, "bad": bad, "files": len(paths),
            "updated": time.strftime("%H:%M:%S", time.gmtime()),
        }
        _result["time"], _result["data"] = time.time(), data
        return data
