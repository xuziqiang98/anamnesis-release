# Exploit Analysis: QuickJS Atomics + Resizable ArrayBuffer stale-pointer -> connectback

## Target primitive
**connectback** under:
- Full RELRO (no GOT overwrite)
- seccomp blocks process-spawning syscalls (`execve*`, `fork`, `clone*`)

Goal:
1. Connect to `127.0.0.1:9999`
2. Receive `<u32 filename_len LE><filename><u32 content_len LE><content>`
3. Write `content` to `filename`

## Vulnerability
`js_atomics_op()` / `js_atomics_store()` capture a raw element pointer (`ptr`) via `js_atomics_get_ptr()` and then convert the operand (`JS_ToBigInt64` / `JS_ToUint32`), which can execute attacker JS via `valueOf()`. If `valueOf()` resizes a Resizable ArrayBuffer, the backing store may be `realloc()`ed/split, making `ptr` stale. The subsequent atomic operation uses that stale pointer, producing a UAF/OOB read/write.

## Exploit overview
The exploit builds:
1. **libc pointer leak** (unsorted-bin fd)
2. **arbitrary 64-bit read/write** by corrupting a `BigUint64Array` object’s internal data pointer
3. **stack return address overwrite** (ret2ROP) to call `mprotect` and jump into stack-resident shellcode
4. **shellcode** performs network + file syscalls directly (no `execve`, no modules)

### 1) libc pointer leak (unsorted bin)
- Allocate a RAB of size `0x3000` and a `BigInt64Array` view.
- Call `Atomics.add(ta, 6, evil)` where `evil.valueOf()` shrinks the RAB to `0x20`.
- The shrink splits the original malloc chunk; the large remainder becomes an **unsorted bin** free chunk.
- The stale pointer targets offset `0x30`, which lands on the free chunk’s **fd pointer** (`main_arena+96`), leaking a libc pointer.

### 2) Arbitrary read/write by typed-array header corruption
We corrupt `JSObject.u.array.u.ptr` for a `BigUint64Array`:
- Create a small RAB of `0x70` bytes and a `BigInt64Array` view.
- Trigger `Atomics.store(ta, 13, evil)`:
  - index `13` => byte offset `0x68`.
  - `evil.valueOf()` shrinks RAB to `0x20`, freeing a remainder chunk.
  - Immediately allocate a `BigUint64Array(backing)`; its JSObject is allocated into that freed remainder.
  - The stale pointer write at offset `0x68` overlaps and overwrites the victim typed array’s data pointer.

Now `victim[i]` reads/writes from attacker-chosen addresses.

### 3) Locate libc base without /proc
From the leaked libc pointer, scan backward page-by-page within a small window and search for the ELF magic `0x7f454c46` (appears as `0x464c457f` in little-endian 32-bit). This yields `libc_base`.

### 4) Locate the initial stack
- Read libc’s GOT relocation for `_dl_argv` (`0x1e6dd0` in glibc 2.41). This gives the address of `_dl_argv` (stored in `ld-linux`).
- Read `*_dl_argv` to obtain `argv[]`, which lives on the initial process stack.

### 5) Find main’s saved return address and overwrite it
- Scan a window of stack memory for the return address value used when `main` returns into libc (`libc_base + 0x29ca8` for glibc 2.41).
- Overwrite that saved RIP with a small ROP chain:
  1. `ret` (alignment)
  2. `pop rdi; ret` → page-aligned address for shellcode
  3. `pop rsi; ret` → `0x2000`
  4. `pop rdx; pop rbx; ret` → `7` (RWX)
  5. `mprotect`
  6. jump to shellcode

To avoid corrupting active interpreter stack frames, the shellcode bytes are written **far below** the current stack pointer (near the bottom of the scanned stack window), then mprotected.

### 6) Shellcode: connect, receive protocol, write file
The shellcode is plain x86_64 Linux syscall code:
- `socket(AF_INET, SOCK_STREAM, 0)`
- `connect(127.0.0.1:9999)`
- `read()` loops to fetch:
  - 4-byte filename length
  - filename bytes (+ add NUL terminator)
  - 4-byte content length
  - content bytes
- `openat(AT_FDCWD, filename, O_WRONLY|O_CREAT|O_TRUNC, 0644)`
- `write(fd, content, content_len)`
- `close(fd)`, `close(sock)`, `exit(0)`

This satisfies the required connectback primitive under the seccomp constraints (no process spawning).

## PoC files
- PoC JavaScript: `/tmp/work/poc.js`

