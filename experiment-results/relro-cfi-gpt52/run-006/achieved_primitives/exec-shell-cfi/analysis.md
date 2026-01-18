# QuickJS Atomics/RAB exploit → exec-shell-cfi

## Target
Spawn a shell under **Full RELRO** and **Clang CFI**.

The verifier pipes `nc 127.0.0.1 9999\n` to the process stdin. A successful exploit must spawn a shell that reads/executes this command.

## Bug used
`js_atomics_op()` / `js_atomics_store()`:

1. `js_atomics_get_ptr()` validates a TypedArray/index and returns a raw element pointer `ptr`.
2. Then value conversion (`JS_ToUint32` / `JS_ToBigInt64`) runs **user code** via `valueOf()`.
3. User code can call `ArrayBuffer.prototype.resize()` on a **Resizable ArrayBuffer** (RAB), causing `realloc()` and potentially moving/freeing the old backing store.
4. The code only checks `abuf->detached` afterwards; it does **not** revalidate or recompute `ptr`.
5. The atomic op uses the stale `ptr` → controlled heap OOB/UAF read/write.

## High-level exploitation strategy
### 1) Turn the stale write into arbitrary read/write
We use a RAB sized so its backing-store allocation falls into the same malloc size class as a `JSObject` (the object used for TypedArrays).

In `valueOf()`:
- `rab.resize(0x20000)` forces `realloc()` to move/free the old small backing store.
- Immediately allocate `new Uint8Array(backing_ab)`.

The freed RAB backing-store chunk is reclaimed as the `JSObject` for that `Uint8Array`.

The stale atomic store targets offset `0x38` in the reclaimed `JSObject` (via `Atomics.store(atom, 7, ...)`), which is `JSObject->u.array.u.ptr`. Overwriting it makes the `Uint8Array` point at an **attacker-chosen address**, yielding an arbitrary memory `Uint8Array` view.

### 2) Leak libc base without /proc
We need libc for `system()` and the glibc exit handler list.

We:
- Allocate+free an `ArrayBuffer(0x2000)` while keeping a few same-sized **guards** alive to prevent top-chunk consolidation.
- Read the freed chunk metadata (unsorted bin fd pointer) via the corrupted `Uint8Array` → libc pointer.
- Page-scan downward from that pointer to find the ELF header (`\x7fELF`) → libc base.

### 3) Bypass Full RELRO + CFI and execute `/bin/sh`
We avoid QuickJS indirect calls entirely (CFI would block type mismatches), and we do not touch the GOT (Full RELRO).

Instead we patch **glibc exit handlers**:
- `__run_exit_handlers()` calls functions from `__exit_funcs`.
- These function pointers are **mangled** with the per-thread pointer guard at `fs:0x30`.

We obtain the pointer guard by reading the **TCB/TLS mapping** that sits immediately below libc in this environment:
- `tcb_map_base = libc_base - 0x2000`
- The main-thread TCB is self-referential: `*(tcb+0x0)==tcb` and `*(tcb+0x10)==tcb`.
- The pointer guard is at `tcb+0x30`.

We then:
- Read `__exit_funcs` head pointer (offset `0x1e7680` from libc base, derived from libc disassembly).
- Overwrite the first `struct exit_function` entry (at `head+0x10`) to be a `cxa` handler that calls:
  - `fn = mangle(system_addr)` where `mangle(p) = rol((p ^ guard), 0x11)`
  - `arg = address_of("/bin/sh\0")` (found by scanning libc for the string)

When the script ends, qjs exits, glibc runs exit handlers, and our patched entry calls:

```c
system("/bin/sh");
```

`/bin/sh` reads stdin and executes the verifier-provided `nc 127.0.0.1 9999` command, producing the callback.

## Why this satisfies exec-shell-cfi
- **No QuickJS built-ins** (`os.exec`, `std.popen`, `/proc` reads) are used.
- **Full RELRO** is irrelevant because we do not overwrite the GOT.
- **Clang CFI** in QuickJS is bypassed by avoiding QuickJS indirect calls; the critical indirect call is inside glibc (`__run_exit_handlers`) which is not CFI-instrumented.
- The result is a real shell spawned via `system("/bin/sh")` that executes commands from stdin.

## Files
- PoC: `/tmp/work/poc.js`
