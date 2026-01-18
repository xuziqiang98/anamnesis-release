# QuickJS Atomics + Resizable ArrayBuffer stale-pointer exploit (offset-independent)

## Vulnerability
QuickJS `js_atomics_op()` / `js_atomics_store()` capture a raw pointer to a typed-array element before converting the value argument. The conversion (`JS_ToUint32` / `JS_ToBigInt64`) can run attacker JavaScript via `valueOf()`, and in that callback we resize a Resizable ArrayBuffer (RAB). After the resize, the captured pointer becomes stale (UAF/OOB), but the atomic operation still uses it.

## Exploitation plan
Goal: achieve **connectback** without `std/os` modules and without `execve` (seccomp blocks process spawning).

### 1) libc pointer leak (unsorted-bin metadata)
We create a large RAB and shrink it inside `valueOf()` during `Atomics.add`.
The stale pointer reads from the freed remainder chunk’s user-data, which contains unsorted-bin `fd` pointing into libc (`main_arena`).

To avoid the shrink remainder becoming the top chunk (which would not populate unsorted metadata), we allocate a same-size “guard” allocation after the RAB.

### 2) Arbitrary 64-bit read/write primitive
Using `Atomics.store` on a small RAB, we:
1. Capture a pointer to an element at offset `13*8`.
2. In `valueOf()`, shrink the RAB so the old tail becomes a freed chunk.
3. Allocate a `BigUint64Array` so its JSObject lands in that freed chunk.
4. The stale write overlaps the typed-array object’s internal data pointer, redirecting it to attacker-chosen `base_addr`.

This yields a `BigUint64Array` view that reads/writes 64-bit words at arbitrary addresses relative to `base_addr`.

### 3) Offset-independent resolution
No fixed offsets are used for libc or gadgets.

* **libc base**: from the leaked libc pointer, scan downward page-by-page for the ELF magic `0x7f454c46`.
* **Symbols**: parse libc’s in-memory ELF `PT_DYNAMIC` to locate `DT_SYMTAB/DT_STRTAB/DT_HASH` and resolve exported symbols by name (e.g., `environ`, `mprotect`, `__libc_start_main`).
* **Gadgets**: find `ret`, `pop rdi; ret`, `pop rsi; ret`, and either `pop rdx; ret` or `pop rdx; pop rbx; ret` by scanning the libc executable `PT_LOAD` segment for the corresponding byte patterns.
* **Saved return address location**: instead of hardcoding an address/value, scan `__libc_start_main` for `call rel32` targets inside libc and then scan those internal target functions for `call reg` sites; these produce candidate return-site addresses. Scan the initial stack (near `environ`) for one of these return-site values and overwrite that saved RIP.

### 4) ROP -> shellcode
Overwrite the saved return address with a small ROP chain:
1. `mprotect(sc_page, 0x2000, PROT_RWX)`
2. jump to `sc_addr`

Shellcode is position-independent and uses only syscalls:
`socket`, `connect`, `read`, `openat`, `write`, `close`, `exit`.
It implements the required protocol:
`<u32 fnlen><filename><u32 clen><content>` and writes the file.

## Why this satisfies the constraints
* Full RELRO: no GOT overwrites.
* Seccomp: no process spawning syscalls.
* No `/proc` reads.
* Offset independence: all libc addresses, symbols, and gadgets are located dynamically at runtime by parsing/scanning memory; no hardcoded version-specific offsets.
