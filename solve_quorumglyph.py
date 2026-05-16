import struct
from pathlib import Path

import lief
from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
from unicorn.x86_const import (
    UC_X86_REG_RAX,
    UC_X86_REG_RBP,
    UC_X86_REG_RBX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDI,
    UC_X86_REG_RDX,
    UC_X86_REG_RSI,
    UC_X86_REG_RSP,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_R10,
    UC_X86_REG_R11,
    UC_X86_REG_R12,
    UC_X86_REG_R13,
)
from elftools.elf.elffile import ELFFile


MASK64 = (1 << 64) - 1
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
TARGET_HASH = 0xE04CF5339F776142
FINAL_FLAG = "ISCC{QRM_FE6V6_3_w1tness_no_single_path!!}"


def mix64(x: int) -> int:
    x &= MASK64
    x ^= x >> 30
    x = (x * 0xBF58476D1CE4E5B9) & MASK64
    x ^= x >> 27
    x = (x * 0x94D049BB133111EB) & MASK64
    x ^= x >> 31
    return x & MASK64


def pack_token(token: str) -> int:
    acc = 0
    for ch in token:
        acc = (acc << 5) | ALPHABET.index(ch)
    return acc


def stage3_seed(acc: int) -> int:
    return (0x989B19BD * ((acc - 0x00B3EF33) & 0xFFFFFFFF)) & 0xFFFFFF


def emulate_heavy_hash(binary_path: Path, seed: int) -> int:
    with binary_path.open("rb") as f:
        elf = ELFFile(f)
        text = elf.get_section_by_name(".text")
        text_addr = text["sh_addr"]
        code = text.data()

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    base = 0x400000
    mu.mem_map(base, 0x100000)
    mu.mem_write(text_addr, code)

    stack = 0x70000000
    mu.mem_map(stack, 0x40000)
    rsp = stack + 0x30000
    ret_addr = 0x401EE2
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.mem_write(rsp, struct.pack("<Q", ret_addr))

    for reg in [
        UC_X86_REG_RAX,
        UC_X86_REG_RBX,
        UC_X86_REG_RCX,
        UC_X86_REG_RDX,
        UC_X86_REG_RSI,
        UC_X86_REG_R8,
        UC_X86_REG_R9,
        UC_X86_REG_R10,
        UC_X86_REG_R11,
        UC_X86_REG_R12,
        UC_X86_REG_R13,
        UC_X86_REG_RBP,
    ]:
        mu.reg_write(reg, 0)

    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.mem_write(rsp, struct.pack("<Q", ret_addr))
    mu.reg_write(UC_X86_REG_RDI, seed)
    mu.emu_start(0x401CA0, ret_addr)
    return mu.reg_read(UC_X86_REG_RAX)


def recover_stage2_prefix(flag: str) -> bytes:
    buf = bytearray(64)
    raw = flag.encode()
    buf[:42] = raw
    buf[9:14] = b"\x00" * 5

    acc = 0x51554F52554D474C
    delta = 0
    for b in buf[:42]:
        acc = mix64((b + delta) ^ acc)
        delta += 0x9E37

    buf[42:50] = struct.pack("<Q", acc)

    rolling = acc ^ 0x123456789ABCDEF0
    addend = 0
    for i, ecx in enumerate(range(0, 98, 7)):
        idx = ecx % 42
        rolling = mix64((buf[idx] + addend + rolling) & MASK64)
        buf[50 + i] = rolling & 0xFF
        addend += 0x10001

    return bytes(buf[:42])


def main() -> None:
    binary_path = Path(r"D:\CTF\powershell\tmp_quorumglyph\QuorumGlyph")
    if not binary_path.exists():
        raise SystemExit(f"missing sample: {binary_path}")

    token = "FE6V6"
    acc = pack_token(token)
    seed = stage3_seed(acc)
    heavy_hash = emulate_heavy_hash(binary_path, seed)
    stage2 = recover_stage2_prefix(FINAL_FLAG).decode("ascii", errors="replace")

    print(f"sample: {binary_path}")
    print(f"stage2: {stage2}")
    print(f"token: {token}")
    print(f"packed_acc: 0x{acc:06x}")
    print(f"stage3_seed: 0x{seed:06x}")
    print(f"heavy_hash: 0x{heavy_hash:016x}")
    print(f"target_hash: 0x{TARGET_HASH:016x}")
    print(f"flag: {FINAL_FLAG}")
    print(f"hash_ok: {heavy_hash == TARGET_HASH}")


if __name__ == "__main__":
    main()
