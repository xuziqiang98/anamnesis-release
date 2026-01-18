# QuickJS-seccomp file-write exploit (Atomics + Resizable ArrayBuffer stale-pointer)

## Goal
Write the string **`PWNED`** into **`/tmp/pwned`** under:
- Full RELRO (no GOT overwrite)
- Intel CET shadow stack enabled
- Clang CFI enabled
- Seccomp blocking process-spawning syscalls
- No `std`/`os` JS modules

## Vulnerability used
`Atomics.store` / `Atomics.add` on TypedArrays backed by a **Resizable ArrayBuffer (RAB)** captures a raw element pointer **before** converting the `value` argument.

During the conversion (`valueOf()`), attacker-controlled JS runs and can **resize** the RAB so its backing store is **reallocated**. The captured pointer becomes stale and is later used for the atomic operation, giving a **use-after-free / out-of-bounds** access.

## Exploitation overview
The exploit avoids classic ROP entirely (shadow stack is locked; `ARCH_SHSTK_DISABLE` fails with `EPERM`). Instead, it achieves the file write by:
1. Building an **arbitrary 64-bit read/write** primitive by overwriting a TypedArray object's internal data pointer.
2. Leaking libc base via an **unsorted-bin** UAF read.
3. Hijacking glibc's **`__exit_funcs`** list to call real libc functions with normal call/return semantics (shadow-stack safe).

## 1) Arbitrary read/write primitive
A small RAB is created with byteLength `0x48` so its malloc chunk is `0x50`.

In `valueOf()`:
- `rab.resize(0x1000)` forces `realloc` and frees the old `0x50` chunk.
- A new `BigUint64Array` is allocated; its JSObject is re-used from that freed `0x50` chunk.

Then `Atomics.store(ta, 7, ...)` uses the stale pointer to write to **offset `0x38`** inside the re-used JSObject, which corresponds to `JSObject.u.array.u.ptr` (TypedArray data pointer). This turns the TypedArray into a memory view at an attacker-chosen address, yielding arbitrary read/write via `view[0]`.

## 2) libc leak
To defeat ASLR without `/proc`:
- A larger RAB (`0x500`) is forced to **move** on growth by placing a blocker allocation after it.
- When the old `0x500` chunk is freed into the **unsorted bin**, glibc writes `fd/bk` pointers (into main_arena) into the freed chunk.
- `Atomics.add(u64, 0, evil)` returns the old 8-byte value at the stale pointer, leaking a libc pointer.

The exploit scans downward by pages using the arbitrary read primitive until it finds the ELF header magic (`0x7f 'ELF'`), yielding `libc_base`.

## 3) Exit-handler hijack (shadow-stack safe file write)
Instead of ROP, the exploit overwrites glibc's global `__exit_funcs` pointer to point to a **fake `struct exit_function_list`** placed in writable libc `.bss`.

### Pointer mangling
glibc stores atexit function pointers **mangled** with the thread-local `pointer_guard`:

`PTR_MANGLE(p) = rol64(p ^ pointer_guard, 0x11)`

The exploit finds `fs_base` by scanning the TLS mapping just below `libc_base` for the self-pointer (`*(fs_base) == fs_base`), then reads `pointer_guard` from `fs_base+0x30`.

### File write chain (no syscalls from JS; no ROP)
Exit handlers run in reverse order. The crafted list calls:
1. `close(0)`
2. `close(1)`
3. `creat("/tmp/pwned", 0)` → returns fd **0**
4. `fchmod(0, 0644)` (implemented using an `ef_on` entry so arguments become `(status=0, arg=0x1a4)`)
5. `creat("/tmp/pwned", 0)` → returns fd **1**
6. `printf("PWNED")` → writes to stdout (fd 1), which is now `/tmp/pwned`
7. `fflush(NULL)`

This produces a readable file containing exactly `PWNED` while keeping CET shadow stack satisfied because all transitions are legitimate function calls.

## Result
`/tmp/pwned` is created with mode 0644 and contains exactly `PWNED`.
