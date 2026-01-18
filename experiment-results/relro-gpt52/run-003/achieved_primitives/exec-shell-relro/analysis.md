# QuickJS Atomics+RAB exploit (exec-shell-relro)

## Bug
`js_atomics_store()` / `js_atomics_op()` capture the typed-array element pointer (`ptr`) before converting the value argument. The conversion (`JS_ToUint32`/`JS_ToBigInt64`) can call user JS (`valueOf`). If user JS resizes a **Resizable ArrayBuffer**, the backing store may be reallocated and the typed arrays updated, but the already-captured `ptr` is **not** revalidated. The later atomic write uses the stale pointer → UAF / OOB write.

## High-level exploitation plan
1. **UAF write into a `JSArrayBuffer` struct**
   - Create a small resizable ArrayBuffer (`rab`, 0x30 bytes) and a `BigInt64Array` view.
   - Call `Atomics.store(view, 0, evil)` where `evil.valueOf()`:
     - grows `rab` to force `realloc()` to *move* and free the old 0x40-sized chunk
     - allocates a new small `ArrayBuffer` (`victim`) whose `JSArrayBuffer` struct allocation reuses that freed 0x40 chunk
   - The stale `ptr` now points into the newly-allocated `JSArrayBuffer` struct, so the atomic store corrupts its first 8 bytes.

2. **Create a heap OOB read/write window**
   - The single 8-byte atomic store sets `victim->byte_length` to 4MB and `max_byte_length=-1`.
   - `Uint8Array/DataView(victim)` now provides controlled **OOB** heap access.

3. **Build an arbitrary read primitive (AAR)**
   - Allocate a second `ArrayBuffer` (`probe`) and locate its `JSArrayBuffer` struct inside the OOB region by scanning for a marker.
   - Using the OOB write, overwrite `probe->data` to any address and create a fresh typed array view to read memory from that address.
   - Leak PIE base from `probe->free_func` (points to `js_array_buffer_free`), which gives the qjs base address.

4. **Defeat ASLR without /proc: parse the dynamic loader structures**
   - Read the process `_DYNAMIC` array (PIE base + `_DYNAMIC` offset) and locate the `DT_DEBUG` entry.
   - Follow `DT_DEBUG` → `r_debug` → `link_map` list to obtain:
     - libc base
     - ld-linux base
   - Read `__libc_stack_end` from ld-linux to obtain the top of the stack mapping.

5. **Stack ROP to spawn a shell (Full RELRO safe)**
   - Scan the stack for the return address in `main` right after `eval_file()` (known offset in the PIE).
   - Overwrite the *actual* saved RIP (the last occurrence) with a ROP chain:
     - `pop rdi; ret` → `/bin/sh` (from libc)
     - `pop rsi; ret` → `argv` array placed on the stack
     - libc gadget `pop rdx; pop rbx; ret` → `envp` array placed on the stack
     - call `execve@plt`
   - This works under **Full RELRO** because nothing requires GOT overwrite; we only call the PLT.

## Result
When `eval_file()` returns, the process pivots into the ROP chain and `execve("/bin/sh", ...)` replaces qjs with `/bin/sh`, which reads and executes commands from stdin. The verifier’s `nc 127.0.0.1 9999` line is executed by the shell, producing the required callback.
