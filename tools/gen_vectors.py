#!/usr/bin/env python3
"""Generate Mirage golden vectors (spec/golden-vectors/vectors.json) and the
hand-computed derivation document.

Two sources of truth cross-check each other:

  1. The expectations below are HAND-COMPUTED from spec/SIGNALS.md v1.1.0
     (the arithmetic is written out in each case's `notes`).
  2. The reference engine in this file implements the spec independently.

If they disagree, the script exits 1 and prints the mismatch. No vector is
emitted that both hands have not agreed on.

Run:  python3 tools/gen_vectors.py   (from the repo root)
"""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SPEC_VERSION = "1.1.0"
PROTOCOL_VERSION = "1"

# ---------------------------------------------------------------------------
# Shared policy (mirrors data/*.txt and spec/decoy-catalog/catalog.yaml)
# ---------------------------------------------------------------------------

PROTECTED_ROUTES = ["/wp-login.php", "/wp-admin/", "/checkout", "/cart", "/api/"]

SCANNER_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.git/config", "/.git/HEAD",
    "/.git/index", "/.aws/credentials", "/.ssh/id_rsa", "/.ssh/authorized_keys",
    "/.DS_Store", "/.svn/entries", "/.svn/wc.db", "/.htaccess.bak",
    "/.htpasswd", "/.bash_history", "/.mysql_history", "/wp-config.php.bak",
    "/wp-config.php.save", "/wp-config.php.old", "/phpmyadmin-old/",
    "/pma-old/", "/administrator/backups/", "/backup.sql", "/backup.zip",
    "/backup.tar.gz", "/db.sql", "/dump.sql", "/database.sql",
    "/database.sql.gz", "/site-backup.zip", "/web.config.bak",
    "/server-backup.tar.gz", "/.elastic/config/elasticsearch.yml",
    "/.docker/config.json", "/composer.lock.bak", "/package.json.bak",
    "/ids.sql", "/data.sql",
]

UA_SUSPICIOUS = [
    "sqlmap/", "nikto", "nuclei", "masscan", "zgrab", "nmap scripting engine",
    "python-requests/", "python-urllib/", "go-http-client/", "wget/",
    "libwww-perl", "acunetix", "dirbuster", "dirb", "gobuster", "ffuf/",
    "httpx/", "wpscan", "arachni", "wfuzz/", "havij", "hydra", "metasploit",
    "burpsuite", "sqlninja", "zap", "w3af",
]

UA_VERIFIED_BOTS = ["googlebot", "bingbot", "duckduckbot", "baiduspider",
                    "yandexbot", "slurp"]

# Decoy catalog, loaded from the real YAML so the vectors can never drift
# from the catalog file.
import yaml  # noqa: E402

CATALOG = yaml.safe_load((ROOT / "spec/decoy-catalog/catalog.yaml").read_text())
DECOY_PATHS = {e["path"]: e for e in CATALOG["entries"]}
ALL_LEADS = {lead for e in CATALOG["entries"] for lead in e["leads"]}

SIGNAL_WEIGHTS = {
    "scanner_path": (25, "high", "SIG-101"),
    "decoy_hit": (30, "high", "SIG-102"),
    "decoy_lead_follow": (40, "high", "SIG-103"),
    "honeytoken_use": (50, "high", "SIG-104"),
    "path_enumeration": (25, "high", "SIG-105"),
    "ua_suspicious": (15, "medium", "SIG-106"),
    "ua_rotation": (20, "medium", "SIG-107"),
    "no_cookie_persistence": (15, "medium", "SIG-108"),
    "headers_sparse": (10, "medium", "SIG-109"),
    "ua_missing": (10, "medium", "SIG-110"),
    "tooling_curl": (15, "medium", "SIG-111"),
}
EVAL_ORDER = list(SIGNAL_WEIGHTS)          # table order 1..11
UNGATING = {"scanner_path", "decoy_hit", "decoy_lead_follow",
            "honeytoken_use", "path_enumeration"}   # signals 1-5
CLASS_RANK = {"medium": 1, "high": 2}

SESSION_TTL_MS = 30 * 60 * 1000
UA_WINDOW_MS = 300_000
ENUM_WINDOW_MS = 60_000
ENUM_THRESHOLD = 8
UA_ROTATION_THRESHOLD = 4
BAN_TTL_MS = 1_800_000

# ---------------------------------------------------------------------------
# Reference engine (spec/SIGNALS.md v1.1.0)
# ---------------------------------------------------------------------------

def session_key(ip: str) -> str:
    return hashlib.sha256(ip.encode()).hexdigest()[:32]

def normalize(path: str):
    """Query-strip + dot-segment resolution. Returns (path, dot_escape)."""
    p = path.split("?", 1)[0]
    stack, dot_escape = [], False
    for seg in p.split("/"):
        if seg == "." or seg == "":
            continue
        if seg == "..":
            if stack:
                stack.pop()
            else:
                dot_escape = True
        else:
            stack.append(seg)
    return ("/" + "/".join(stack)) if stack else "/", dot_escape

def _strip_slash(p: str) -> str:
    return p.rstrip("/") or "/"

def is_scanner(path: str) -> bool:
    return any(_strip_slash(path) == _strip_slash(e) for e in SCANNER_PATHS)

def is_protected(path: str) -> bool:
    return any(path == p or path.startswith(p) for p in PROTECTED_ROUTES)

def is_decoy(path: str) -> bool:
    return path in DECOY_PATHS

def is_unknown(path: str) -> bool:
    """SIGNALS section 4.5: unknown for enumeration purposes."""
    return (path != "/" and not is_protected(path) and not is_scanner(path)
            and not is_decoy(path) and path not in ALL_LEADS)

def mint_token(skey: str, entry_id: str, token_id: str) -> str:
    """token_alnum_24 format (data/token-formats.md): mrg_live_ + 24 alnum."""
    h = hashlib.sha256(f"{skey}:{entry_id}:{token_id}".encode()).hexdigest()
    return "mrg_live_" + h[:24]

class Session:
    def __init__(self):
        self.last_ts = None
        self.request_count = 0
        self.cumulative = 0
        self.cookie_ever = False
        self.ua_seen = []        # (ua, ts) non-empty only
        self.unknown_paths = []  # (path, ts)
        self.leads_known = set()
        self.tokens_minted = []

    def expired(self, ts: int) -> bool:
        return (self.last_ts is not None
                and ts - self.last_ts > SESSION_TTL_MS)

def decide(session: Session, req: dict, allowlisted: bool) -> dict:
    """Score one request against/into one session. Never-scored requests
    return observe and leave the session untouched."""
    ip = req["client_ip"]
    ua = req.get("user_agent", "") or ""
    ts = req["ts_ms"]

    if allowlisted:
        return _observe(ip)
    if any(h in ua.lower() for h in UA_VERIFIED_BOTS):
        return _observe(ip)

    if session.expired(ts):
        fresh = Session()
        session.__dict__.update(fresh.__dict__)

    path, dot_escape = normalize(req["path"])
    cum_before = session.cumulative

    fired = []  # ids in eval order

    # 1 scanner_path
    if is_scanner(path) or dot_escape:
        fired.append("scanner_path")
    # 2 decoy_hit (suppressed by scanner_path)
    if is_decoy(path) and "scanner_path" not in fired:
        fired.append("decoy_hit")
    # 3 decoy_lead_follow
    if path in session.leads_known:
        fired.append("decoy_lead_follow")
    # 4 honeytoken_use
    hint = req.get("auth_hint")
    if hint and any(t and (t == hint or t in hint)
                    for t in session.tokens_minted):
        fired.append("honeytoken_use")
    # 5 path_enumeration (trailing 60 s window, distinct unknown paths)
    window = [p for (p, t) in session.unknown_paths if ts - t <= ENUM_WINDOW_MS]
    if is_unknown(path):
        window.append(path)
    if len(set(window)) >= ENUM_THRESHOLD:
        fired.append("path_enumeration")
    # 6 ua_suspicious
    if any(p in ua.lower() for p in UA_SUSPICIOUS):
        fired.append("ua_suspicious")
    # 7 ua_rotation (gated by signals 1-5)
    ua_window = {u for (u, t) in session.ua_seen
                 if ts - t <= UA_WINDOW_MS and u}
    if ua:
        ua_window.add(ua)
    if (len(ua_window) >= UA_ROTATION_THRESHOLD
            and UNGATING.intersection(fired)):
        fired.append("ua_rotation")
    # 8 no_cookie_persistence (gated: otherwise-clean request and session)
    count_incl = session.request_count + 1
    if (count_incl >= 5 and not session.cookie_ever and cum_before == 0
            and not fired):
        fired.append("no_cookie_persistence")
    # 9 headers_sparse
    if req.get("header_count", 99) < 4:
        fired.append("headers_sparse")
    # 10 ua_missing
    if not ua:
        fired.append("ua_missing")
    # 11 tooling_curl (gated by signals 1-5)
    if ua.lower().startswith("curl/") and UNGATING.intersection(fired):
        fired.append("tooling_curl")

    request_score = sum(SIGNAL_WEIGHTS[s][0] for s in fired)
    request_class = "high" if any(SIGNAL_WEIGHTS[s][1] == "high"
                                  for s in fired) else (
        "medium" if fired else None)

    verdict = "observe"
    if request_score >= 15 or cum_before >= 25:
        verdict = "tag"
    if (request_score >= 25 and request_class == "high" and is_decoy(path)
            and not is_protected(path)):
        verdict = "decoy_route"
    if request_score >= 40:
        verdict = "throttle"
    if ("honeytoken_use" in fired
            or ("decoy_lead_follow" in fired and not is_protected(path))
            or (request_score >= 60 and request_class == "high")):
        verdict = "ban"

    if is_protected(path) and "honeytoken_use" not in fired:
        verdict = "tag"

    # session update
    session.request_count += 1
    session.last_ts = ts
    session.cookie_ever = session.cookie_ever or bool(req.get("has_cookie"))
    session.cumulative = cum_before + request_score
    if ua:
        session.ua_seen.append((ua, ts))
    session.ua_seen = [(u, t) for (u, t) in session.ua_seen
                       if ts - t <= UA_WINDOW_MS]
    if is_unknown(path):
        session.unknown_paths.append((path, ts))
    session.unknown_paths = [(p, t) for (p, t) in session.unknown_paths
                             if ts - t <= ENUM_WINDOW_MS]
    if verdict == "decoy_route":
        entry = DECOY_PATHS[path]
        session.leads_known.update(entry["leads"])
        for tok in entry["honeytokens"]:
            session.tokens_minted.append(
                mint_token(session_key(ip), entry["id"], tok["id"]))

    reason = ""
    if fired:
        best = max(fired, key=lambda s: (SIGNAL_WEIGHTS[s][0],
                                         -EVAL_ORDER.index(s)))
        reason = SIGNAL_WEIGHTS[best][2]

    return {
        "session_key": session_key(ip),
        "signals": fired,
        "request_score": request_score,
        "score": session.cumulative,
        "verdict": verdict,
        "reason_code": reason or "SIG-000",
        "ban_ttl_ms": BAN_TTL_MS if verdict == "ban" else None,
    }

def _observe(ip: str) -> dict:
    return {"session_key": session_key(ip), "signals": [], "request_score": 0,
            "score": 0, "verdict": "observe", "reason_code": "SIG-000",
            "ban_ttl_ms": None}

# ---------------------------------------------------------------------------
# Cases: requests + HAND-COMPUTED expectations and notes
# ---------------------------------------------------------------------------

T0 = 1_780_000_000_000
BROWSER = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
SQLMAP = "sqlmap/1.8.2#stable (http://sqlmap.org)"
CURL = "curl/8.5.0"

def R(method, path, ts, ua=BROWSER, headers=8, cookie=False, auth=None, ip=None):
    r = {"method": method, "path": path, "ts_ms": ts, "user_agent": ua,
         "header_count": headers, "has_cookie": cookie}
    if auth is not None:
        r["auth_hint"] = auth
    if ip is not None:
        r["x_forwarded_for"] = ip   # informational: harness ignores it (I6)
    return r

def E(signals, verdict, score, reason):
    return {"signals": signals, "verdict": verdict, "score": score,
            "reason_code": reason}

CASES = []
def case(cid, ip, note, reqs, expected, allowlisted=None):
    CASES.append({"id": cid, "client_ip": ip, "note": note,
                  "requests": reqs, "expected": expected,
                  "allowlisted_ips": allowlisted or []})

case("v01-clean-browsing", "203.0.113.20",
     "Five ordinary browser requests with cookies and a full header set. No "
     "signal can fire: paths are real or harmless unknowns (only 4 distinct "
     "unknowns, below the enumeration threshold of 8), headers are full, a "
     "cookie is sent, the UA is a browser. Verdicts observe, cumulative 0.",
     [R("GET", p, T0 + i * 1000, headers=9, cookie=True)
      for i, p in enumerate(["/", "/about", "/pricing", "/blog", "/contact"])],
     [E([], "observe", 0, "SIG-000") for _ in range(5)])

case("v02-scanner-path", "203.0.113.7",
     "Worked example W1. GET /.env with a plain browser UA: scanner_path "
     "25 (high); decoy_hit is suppressed by SIGNALS 4.2. request 25 >= 25 "
     "with high class on a decoyable path -> decoy_route. Cumulative 25. "
     "Session key is the sha256 anchor: fec52565aa0cf18f57d7cf5b3ac72850.",
     [R("GET", "/.env", T0, headers=8, cookie=False)],
     [E(["scanner_path"], "decoy_route", 25, "SIG-101")])

case("v03-decoy-hit", "203.0.113.8",
     "GET /admin/login (admin-panel-legacy decoy, not on the scanner list). "
     "decoy_hit 30, high, decoyable -> decoy_route. Cumulative 30.",
     [R("GET", "/admin/login", T0, headers=8)],
     [E(["decoy_hit"], "decoy_route", 30, "SIG-102")])

case("v04-decoy-lead-follow", "203.0.113.9",
     "req1: GET /.env -> scanner_path 25 -> decoy_route; the decoy is "
     "served, so its lead /storage/logs/laravel-staging.log becomes known "
     "to the session. req2 follows the lead: decoy_lead_follow 40 "
     "(near-certain), path not protected -> ban. Cumulative 25 + 40 = 65.",
     [R("GET", "/.env", T0),
      R("GET", "/storage/logs/laravel-staging.log", T0 + 1000)],
     [E(["scanner_path"], "decoy_route", 25, "SIG-101"),
      E(["decoy_lead_follow"], "ban", 65, "SIG-103")])

case("v05-honeytoken-protected", "203.0.113.10",
     "req1: GET /.env -> decoy_route; the env decoy mints the db_password "
     "honeytoken for this session. req2 uses that exact token as a bearer "
     "credential on /api/v1/auth (protected prefix). honeytoken_use 50 "
     "survives the protected-route cap (SIGNALS section 5, R3 exception) "
     "-> ban. Cumulative 25 + 50 = 75.",
     [R("GET", "/.env", T0),
      R("POST", "/api/v1/auth", T0 + 1000,
        auth="PLACEHOLDER_BEARER_TOKEN")],
     [E(["scanner_path"], "decoy_route", 25, "SIG-101"),
      E(["honeytoken_use"], "ban", 75, "SIG-104")])

case("v06-structure-only", "203.0.113.11",
     "req1: browser-like GET /products (9 headers, cookie) -> observe; "
     "/products is an unknown path (count 1). reqs 2-8: scripted GETs "
     "/nope1../nope7, empty UA, 2 headers -> headers_sparse 10 + "
     "ua_missing 10 = 20 per request -> tag (20 >= 15). Cumulative after "
     "req7: 6 x 20 = 120. req8 (/nope7): distinct unknown paths in the "
     "trailing 60 s reach 8 (/products + /nope1-7) -> path_enumeration 25 "
     "joins: request 25 + 10 + 10 = 45 -> throttle, cumulative 165. req9 "
     "(/nope8): 9 distinct unknowns, same 45 -> throttle, cumulative 210. "
     "Never ban: no near-certain signal and request score 45 < 60.",
     [R("GET", "/products", T0, headers=9, cookie=True)]
     + [R("GET", f"/nope{i}", T0 + i * 1000, ua="", headers=2)
        for i in range(1, 8)]
     + [R("GET", "/nope8", T0 + 8000, ua="", headers=2)],
     [E([], "observe", 0, "SIG-000")]
     + [E(["headers_sparse", "ua_missing"], "tag", 20 * i, "SIG-109")
        for i in range(1, 7)]
     + [E(["path_enumeration", "headers_sparse", "ua_missing"],
          "throttle", 165, "SIG-105"),
      E(["path_enumeration", "headers_sparse", "ua_missing"],
          "throttle", 210, "SIG-105")])

case("v07-verified-bot", "203.0.113.12",
     "Googlebot UA hits /.env. Verified-bot hint (case-insensitive "
     "substring) -> never scored, observe, no session state (I12: bots "
     "never meet a trap).",
     [R("GET", "/.env", T0, ua=GOOGLEBOT, headers=8)],
     [E([], "observe", 0, "SIG-000")])

case("v08-allowlist-ip", "192.0.2.50",
     "The owner's own IP (allowlisted in the case config) hits a decoy "
     "path. Never scored, observe, no session state.",
     [R("GET", "/admin/login", T0, headers=8)],
     [E([], "observe", 0, "SIG-000")],
     allowlisted=["192.0.2.50/32"])

case("v09-protected-route", "203.0.113.13",
     "Worked examples W2/W3. req1: GET /wp-login.php with sqlmap UA (4 "
     "headers, above the sparse threshold): ua_suspicious 15 -> tag; the "
     "path is protected so the verdict caps at tag anyway. req2: GET /.env "
     "with sqlmap UA: scanner_path 25 + ua_suspicious 15 = 40 -> throttle. "
     "Cumulative 15 then 55.",
     [R("GET", "/wp-login.php", T0, ua=SQLMAP, headers=4),
      R("GET", "/.env", T0 + 1000, ua=SQLMAP, headers=4)],
     [E(["ua_suspicious"], "tag", 15, "SIG-106"),
      E(["scanner_path", "ua_suspicious"], "throttle", 55, "SIG-101")])

case("v10-curl-gating", "203.0.113.14",
     "SIGNALS section 6.1. req1: GET /products with curl UA and 3 headers: "
     "headers_sparse 10 fires, but tooling_curl does NOT (no signal from "
     "the ungating set 1-5 fired this request; headers_sparse does not "
     "ungate). request 10 < 15 -> observe, cumulative 10. req2: GET /.env "
     "with curl UA: scanner_path 25 fires first and ungates tooling_curl "
     "15; headers_sparse 10 also fires: 25 + 15 + 10 = 50 -> throttle. "
     "Cumulative 60.",
     [R("GET", "/products", T0, ua=CURL, headers=3),
      R("GET", "/.env", T0 + 1000, ua=CURL, headers=3)],
     [E(["headers_sparse"], "observe", 10, "SIG-109"),
      E(["scanner_path", "headers_sparse", "tooling_curl"],
        "throttle", 60, "SIG-101")])

case("v11-ua-rotation-gated", "203.0.113.15",
     "SIGNALS section 6.2. reqs 1-4: four distinct non-empty UAs on "
     "/products with full headers: at req4 the count reaches 4 but NO "
     "other signal fired this request -> ua_rotation must NOT fire "
     "(observe). req5: fifth UA on /.env: scanner_path 25 fires and "
     "ungates ua_rotation 20 -> 45 -> throttle. Cumulative 45.",
     [R("GET", "/products", T0, ua="UA-A/1.0", headers=7, cookie=True),
      R("GET", "/products", T0 + 1000, ua="UA-B/1.0", headers=7, cookie=True),
      R("GET", "/products", T0 + 2000, ua="UA-C/1.0", headers=7, cookie=True),
      R("GET", "/products", T0 + 3000, ua="UA-D/1.0", headers=7, cookie=True),
      R("GET", "/.env", T0 + 4000, ua="UA-E/1.0", headers=7)],
     [E([], "observe", 0, "SIG-000") for _ in range(4)]
     + [E(["scanner_path", "ua_rotation"], "throttle", 45, "SIG-101")])

case("v12-no-cookie-persistence", "203.0.113.16",
     "SIGNALS section 6.3. Five requests to the same unknown path with a "
     "full header set and never a cookie. reqs 1-4: no signal (1 distinct "
     "unknown, full headers, normal UA). req5: request count reaches 5, "
     "cookie_ever false, cumulative 0 before, no other signal this request "
     "-> no_cookie_persistence 15 -> tag. Cumulative 15.",
     [R("GET", "/products", T0 + i * 1000,
        ua="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", headers=8)
      for i in range(5)],
     [E([], "observe", 0, "SIG-000") for _ in range(4)]
     + [E(["no_cookie_persistence"], "tag", 15, "SIG-108")])

case("v13-no-cookie-gated", "203.0.113.17",
     "Same as v12, but the fifth request hits /.env. scanner_path fires, "
     "so no_cookie_persistence is suppressed (the request is no longer "
     "otherwise-clean): only scanner_path 25, high, decoyable -> "
     "decoy_route. Cumulative 25.",
     [R("GET", "/products", T0 + i * 1000,
        ua="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", headers=8)
      for i in range(4)]
     + [R("GET", "/.env", T0 + 4000,
           ua="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", headers=8)],
     [E([], "observe", 0, "SIG-000") for _ in range(4)]
     + [E(["scanner_path"], "decoy_route", 25, "SIG-101")])

case("v14-session-expiry", "203.0.113.18",
     "SIGNALS section 7. req1: GET /.env -> scanner_path 25 -> "
     "decoy_route, cumulative 25. req2 arrives 31 minutes later "
     "(1 860 000 ms > 30 min TTL): the session resets first, so a clean "
     "GET /about is observe with cumulative 0. req3: GET /.env one second "
     "later in the fresh epoch: scanner_path 25 -> decoy_route, "
     "cumulative 25.",
     [R("GET", "/.env", T0),
      R("GET", "/about", T0 + 1_860_000, headers=9, cookie=True),
      R("GET", "/.env", T0 + 1_861_000)],
     [E(["scanner_path"], "decoy_route", 25, "SIG-101"),
      E([], "observe", 0, "SIG-000"),
      E(["scanner_path"], "decoy_route", 25, "SIG-101")])

case("v15-normalization", "203.0.113.19",
     "SIGNALS section 3. req1: /shop/../wp-config.php.bak?debug=1 -> "
     "query stripped, /shop/.. pops shop -> /wp-config.php.bak, a scanner "
     "path -> scanner_path 25. The path is NOT a catalog decoy, so the "
     "decoy_route rung does not hold -> tag. req2: /../../.env clamps at "
     "the root and resolves to /.env -> scanner_path 25, decoyable -> "
     "decoy_route. req3: /a/../../.. pops 'a', then '..' at the root "
     "clamps (dot_escape) -> scanner_path fires per 4.1; resolved path / "
     "is not decoyable -> tag. Cumulative 25, 50, 75.",
     [R("GET", "/shop/../wp-config.php.bak?debug=1", T0),
      R("GET", "/../../.env", T0 + 1000),
      R("GET", "/a/../../..", T0 + 2000)],
     [E(["scanner_path"], "tag", 25, "SIG-101"),
      E(["scanner_path"], "decoy_route", 50, "SIG-101"),
      E(["scanner_path"], "tag", 75, "SIG-101")])

case("v16-ua-rotation-plus", "203.0.113.21",
     "Rotation gate plus history-tagging. reqs 1-3: three distinct UAs on "
     "/products, full headers -> observe (3 < 4; rotation must NOT fire at "
     "req3). req4: fourth distinct UA, but no other signal this request -> "
     "rotation still NOT fired -> observe. req5: GET /admin/login with a "
     "fifth UA: decoy_hit 30 ungates ua_rotation 20 -> 50 -> throttle "
     "(cumulative 50). req6: clean request, but cumulative 50 >= 25 -> tag "
     "via history (verdict rungs use the request's own score except the "
     "tag rung, SIGNALS section 5.1). req7: 2 headers -> headers_sparse "
     "10; rotation stays gated (headers_sparse is not in the ungating set "
     "1-5): request 10, tag via history. Cumulative 60.",
     [R("GET", "/products", T0, ua="Rot-A/1.0", headers=7, cookie=True),
      R("GET", "/products", T0 + 1000, ua="Rot-B/1.0", headers=7, cookie=True),
      R("GET", "/products", T0 + 2000, ua="Rot-C/1.0", headers=7, cookie=True),
      R("GET", "/products", T0 + 3000, ua="Rot-D/1.0", headers=7, cookie=True),
      R("GET", "/admin/login", T0 + 4000, ua="Rot-E/1.0", headers=7),
      R("GET", "/products", T0 + 5000, ua="Rot-F/1.0", headers=7, cookie=True),
      R("GET", "/products", T0 + 6000, ua="Rot-G/1.0", headers=2)],
     [E([], "observe", 0, "SIG-000"),
      E([], "observe", 0, "SIG-000"),
      E([], "observe", 0, "SIG-000"),
      E([], "observe", 0, "SIG-000"),
      E(["decoy_hit", "ua_rotation"], "throttle", 50, "SIG-102"),
      E([], "tag", 50, "SIG-000"),
      E(["headers_sparse"], "tag", 60, "SIG-109")])

case("v17-combination-ban", "203.0.113.22",
     "Ban through a strong combination (SIGNALS section 5.4c) without any "
     "near-certain signal. reqs 1-7: scripted GETs /u1../u7, empty UA, 2 "
     "headers: 20 each -> tag, cumulative 140. req8: /u8 -> 8 distinct "
     "unknown paths in 60 s -> path_enumeration 25 + 10 + 10 = 45 -> "
     "throttle, cumulative 185. req9: GET /.env: scanner_path 25 + "
     "path_enumeration 25 (unknowns u1-u8 still in window) + "
     "headers_sparse 10 + ua_missing 10 = 70 >= 60 with high class -> "
     "BAN. Cumulative 255.",
     [R("GET", f"/u{i}", T0 + i * 1000, ua="", headers=2)
      for i in range(1, 9)]
     + [R("GET", "/.env", T0 + 8000, ua="", headers=2)],
     [E(["headers_sparse", "ua_missing"], "tag", 20 * i, "SIG-109")
      for i in range(1, 8)]
     + [E(["path_enumeration", "headers_sparse", "ua_missing"],
          "throttle", 185, "SIG-105"),
        E(["scanner_path", "path_enumeration", "headers_sparse",
           "ua_missing"], "ban", 255, "SIG-101")])

case("v18-query-and-slash", "203.0.113.23",
     "req1: GET /.env?token=abc123 -> the query is stripped before "
     "matching -> scanner_path 25 -> decoy_route. req2: GET /phpmyadmin-old "
     "-> loader normalization (SIGNALS 3.3): the list entry /phpmyadmin-old/ "
     "matches the slashless path -> scanner_path 25; not a decoy -> tag. "
     "Cumulative 25, 50.",
     [R("GET", "/.env?token=abc123", T0),
      R("GET", "/phpmyadmin-old", T0 + 1000)],
     [E(["scanner_path"], "decoy_route", 25, "SIG-101"),
      E(["scanner_path"], "tag", 50, "SIG-101")])

case("v19-honeytoken-reuse", "203.0.113.24",
     "req1: GET /.env -> decoy_route; the env decoy mints db_password. "
     "req2 uses the minted token inside a fake postgres URL carried as "
     "credential material on /api/v2/users (protected): honeytoken_use 50 "
     "-> ban despite the cap. Cumulative 75.",
     [R("GET", "/.env", T0),
      R("POST", "/api/v2/users", T0 + 1000,
        auth="PLACEHOLDER_DB_URL")],
     [E(["scanner_path"], "decoy_route", 25, "SIG-101"),
      E(["honeytoken_use"], "ban", 75, "SIG-104")])

case("v20-ip-spoof-rejected", "198.51.100.5",
     "Invariant I6. The request carries X-Forwarded-For: 203.0.113.99, but "
     "the peer is not a trusted proxy, so the client IP stays the socket "
     "address 198.51.100.5 and the session key is "
     "sha256('198.51.100.5')[:32] = 8959edf6884f2c2e223a9319e83a6982. "
     "The attacker cannot frame the innocent 203.0.113.99. Clean request "
     "-> observe.",
     [R("GET", "/about", T0, headers=9, cookie=True, ip="203.0.113.99")],
     [E([], "observe", 0, "SIG-000")])

# ---------------------------------------------------------------------------
# Cross-check reference engine against the hand-computed expectations
# ---------------------------------------------------------------------------

def resolve_placeholders():
    """v05/v19 carry placeholder auth hints whose real value depends on the
    deterministic mint. Resolve them with the reference minter and patch the
    expectations' notes stay as written (the mint is deterministic)."""
    for c in CASES:
        if c["id"] == "v05-honeytoken-protected":
            tok = mint_token(session_key(c["client_ip"]),
                             "env-file-staging", "db_password")
            c["requests"][1]["auth_hint"] = f"Bearer {tok}"
        if c["id"] == "v19-honeytoken-reuse":
            tok = mint_token(session_key(c["client_ip"]),
                             "env-file-staging", "db_password")
            c["requests"][1]["auth_hint"] = (
                f"postgres://deploy:{tok}@db.test:5432/staging")

def run() -> int:
    resolve_placeholders()
    failures = 0
    total = 0
    for c in CASES:
        allow = any(ip.split("/")[0] == c["client_ip"]
                    for ip in c["allowlisted_ips"])
        sess = Session()
        for i, (req, exp) in enumerate(zip(c["requests"], c["expected"])):
            req = dict(req, client_ip=c["client_ip"])
            got = decide(sess, req, allowlisted=allow)
            total += 1
            for field in ("signals", "verdict", "score", "reason_code"):
                if got[field] != exp[field]:
                    failures += 1
                    print(f"MISMATCH {c['id']} req{i+1} {field}: "
                          f"expected {exp[field]!r}, engine {got[field]!r}")
            if got["ban_ttl_ms"] is not None and got["verdict"] != "ban":
                failures += 1
                print(f"MISMATCH {c['id']} req{i+1}: ttl without ban")
            if got["verdict"] == "ban" and got["ban_ttl_ms"] != BAN_TTL_MS:
                failures += 1
                print(f"MISMATCH {c['id']} req{i+1}: ban ttl")
    if failures:
        print(f"\n{failures} mismatch(es) across {total} requests — "
              "NOT emitting vectors.")
        return 1

    out = {
        "spec_version": SPEC_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "policy": {
            "protected_routes": PROTECTED_ROUTES,
            "session_ttl_ms": SESSION_TTL_MS,
            "ua_window_ms": UA_WINDOW_MS,
            "enum_window_ms": ENUM_WINDOW_MS,
            "enum_threshold": ENUM_THRESHOLD,
            "ua_rotation_threshold": UA_ROTATION_THRESHOLD,
            "ban_ttl_ms": BAN_TTL_MS,
        },
        "cases": [
            {
                "id": c["id"],
                "client_ip": c["client_ip"],
                "allowlisted_ips": c["allowlisted_ips"],
                "requests": c["requests"],
                "expected": c["expected"],
            }
            for c in CASES
        ],
    }
    vec_dir = ROOT / "spec/golden-vectors"
    vec_dir.mkdir(parents=True, exist_ok=True)
    (vec_dir / "vectors.json").write_text(
        json.dumps(out, indent=1) + "\n")

    lines = [
        "# Golden vectors — hand-computed derivations",
        "",
        f"Spec `{SPEC_VERSION}`, protocol `{PROTOCOL_VERSION}`, "
        f"{len(CASES)} cases, {total} requests. Every expectation below is "
        "hand-computed from `spec/SIGNALS.md` and cross-checked by the "
        "reference engine in `tools/gen_vectors.py`; the generator exits 1 "
        "on any disagreement. All client IPs are RFC 5737 documentation "
        "addresses; all hostnames in payloads are RFC 2606 reserved.",
        "",
    ]
    for c in CASES:
        lines += [f"## {c['id']} — {c['client_ip']}", "", c["note"], ""]
        lines += ["| # | request | signals | verdict | score |", ]
        lines += ["| --- | --- | --- | --- | --- |"]
        for i, (req, exp) in enumerate(zip(c["requests"], c["expected"])):
            lines.append(
                f"| {i+1} | {req['method']} {req['path']} | "
                f"{', '.join(exp['signals']) or '—'} | {exp['verdict']} | "
                f"{exp['score']} |")
        lines.append("")
    lines += [
        "## Canon decisions (recorded to keep implementations honest)",
        "",
        "1. The ungating set for `tooling_curl` and `ua_rotation` is "
        "signals 1-5 (`scanner_path`, `decoy_hit`, `decoy_lead_follow`, "
        "`honeytoken_use`, `path_enumeration`). `headers_sparse` and other "
        "medium signals never ungate (mirrors SIGNALS 6.1 for curl; applied "
        "consistently to rotation).",
        "2. `no_cookie_persistence` gates on signals 1-7 (its predecessors "
        "in evaluation order); `headers_sparse` / `ua_missing` / "
        "`tooling_curl` may co-fire with it.",
        "3. A weight tie for `reason_code` resolves to the earliest signal "
        "in evaluation order (e.g. v17 req9: scanner_path over "
        "path_enumeration, both 25).",
        "4. Unknown-path counting for enumeration excludes ALL catalog "
        "lead paths (not only served ones); a lead is Mirage's territory.",
        "5. `request_count` for the no-cookie gate includes the current "
        "request (fires on the 5th at the earliest).",
        "6. Decoy serving (and therefore lead registration and honeytoken "
        "minting) happens only on verdict `decoy_route`; `throttle` and "
        "`ban` do not serve.",
        "",
    ]
    (vec_dir / "HAND-COMPUTED.md").write_text("\n".join(lines))

    print(f"OK: {len(CASES)} cases, {total} requests, "
          "engine == hand-computed. vectors.json + HAND-COMPUTED.md written.")
    return 0

if __name__ == "__main__":
    sys.exit(run())
