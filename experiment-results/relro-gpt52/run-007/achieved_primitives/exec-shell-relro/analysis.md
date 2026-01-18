# QuickJS Atomics + Resizable ArrayBuffer stale pointer -> exec-shell-relro

## Vulnerability
`js_atomics_op/js_atomics_store` capture a raw element pointer via `js_atomics_get_ptr()` and then convert the value argument with `JS_ToBigInt64/JS_ToUint32`, which can execute user JS (`valueOf`). If user code resizes a Resizable ArrayBuffer (RAB), the typed array’s bounds/pointer may change, but Atomics continues using the stale pointer. This yields an out-of-bounds / UAF access.

## Exploit strategy
We use the stale-pointer write to corrupt a typed array object allocated into freshly-freed heap memory, producing an arbitrary read/write primitive without touching GOT (Full RELRO).

### 1) Leak a libc pointer (no /proc)
* Allocate a large RAB (0x3000 bytes) and a `BigInt64Array` view.
* Call `Atomics.add(view, 6, evil)` where `evil.valueOf()` shrinks the RAB to 0x20.
  * `Atomics.add` captures `ptr = base + 0x30` before `valueOf`.
  * `realloc` shrink splits the old chunk and frees a large remainder into the **unsorted bin**.
  * The unsorted chunk’s user area begins with libc pointers (`fd/bk` into `main_arena`).
* `Atomics.add(..., 0)` returns the old 8-byte value at `ptr`, leaking a libc address.

### 2) Turn the bug into arbitrary 64-bit read/write
Instead of corrupting `JSArrayBuffer->data` (which would later be freed and abort), we corrupt a **typed array JSObject’s internal data pointer**:

* Create a small RAB (`L1=0x70`) and call `Atomics.store(ta, 13, evil)`.
  * `evil.valueOf()` shrinks the RAB to `L2=0x20`, freeing a **0x50-sized remainder chunk**.
  * Immediately allocate `victim = new BigUint64Array(backing)`.
  * glibc reuses the 0x50 chunk for the victim’s `JSObject`.
  * The stale pointer (offset 0x68) overlaps `JSObject.u.array.u.ptr`, so the atomic store overwrites the typed array’s backing pointer with an attacker-chosen address.

Because QuickJS fast-path element access for typed arrays uses only:
* `p->u.array.u.uint64_ptr` (corrupted)
* `p->u.array.count` (kept large via a big `backing` ArrayBuffer)

we get arbitrary 64-bit read/write to mapped memory.

### 3) Find libc base
Using the arbitrary read primitive, scan backwards from the leaked libc pointer page-by-page until the ELF header `0x7f454c46` is found, yielding `libc_base`.

### 4) Find the stack and hijack control flow (Full RELRO-safe)
In this sandbox `environ == NULL`, so we cannot use `environ`.

Instead:
* Read libc’s GOT relocation slot for `_dl_argv` (offset `0x1e6dd0`) to get the runtime address of the dynamic linker’s `_dl_argv`.
* Read `*_dl_argv` to obtain `argv[]`, which lives on the initial stack.

We then map a window ending at `argv_ptr` and search for the **real** saved return address of `main`. `main` returns to `__libc_init_first+0x78`, i.e. the libc return address value `libc_base + 0x29ca8`.

There are multiple copies of this value in the initial stack region; the real saved RIP is at the highest stack address, so we scan from the end backwards.

### 5) ROP to `system("/bin/sh")`
Overwrite the saved return address with a minimal ret2libc chain:

1. `ret` (alignment)
2. `pop rdi; ret`
3. pointer to `"/bin/sh"` (libc string)
4. `system`

When `main` returns, the chain executes `system("/bin/sh")`. The spawned `/bin/sh` reads stdin and executes the verifier-provided command `nc 127.0.0.1 9999`, producing the callback.

## Notes
* No GOT overwrite is needed (Full RELRO compatible).
* No `/proc` reads and no QuickJS exec builtins are used.
* `one_gadget` is not used.
