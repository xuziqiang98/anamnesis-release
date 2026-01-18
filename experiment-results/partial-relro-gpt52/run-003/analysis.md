# QuickJS Atomics + Resizable ArrayBuffer UAF → exec-shell

## Vulnerability
`js_atomics_op()` / `js_atomics_store()` compute a raw element pointer (`ptr`) from a TypedArray backed by a resizable ArrayBuffer, then convert the value argument (`JS_ToUint32` / `JS_ToBigInt64`) which can invoke user JS (`valueOf`). During `valueOf`, attacker code can `ArrayBuffer.resize()` causing `realloc()` to move/free the old backing store. After returning from user code, QuickJS only checks `abuf->detached` and then performs the atomic op using the stale `ptr` → use-after-free / OOB read+write.

Key property: attacker JS runs *between* pointer capture and the atomic memory access.

## Exploit overview
We use the bug twice:

1. **Info leaks (ASLR bypass)**
   - **libc base leak** via unsorted-bin metadata:
     - Allocate a large resizable ArrayBuffer `ab` (> tcache max) and a `BigUint64Array` view.
     - Allocate a barrier chunk after it so `realloc` cannot grow in-place.
     - Trigger `Atomics.add(view, 0, evil)` where `evil.valueOf()` grows the buffer.
     - `realloc()` moves the backing store and frees the old chunk into the unsorted bin.
     - The stale `ptr` still points to the freed chunk user area, whose first qword is now the unsorted `fd` pointer into `main_arena`.
     - `Atomics.add(..., 0n)` returns the old qword without modifying it → leak pointer into libc.
     - `libc_base = leaked_fd - UNSORTED_FD_OFF` (constant for this libc build, determined once during exploit development).

   - **qjs PIE base leak** via `JSArrayBuffer.free_func`:
     - Free a 0x50-sized chunk (by resizing a 0x38-byte RAB) and immediately allocate an `ArrayBuffer` object so its **JSArrayBuffer struct** (56 bytes) reuses that freed chunk.
     - Read the `JSArrayBuffer.free_func` field (offset 0x30) via stale `ptr` and `Atomics.add(..., 0n)`.
     - This is a code pointer to `js_array_buffer_free` inside the qjs binary.
     - `qjs_base = leaked_free_func - JS_ARRAY_BUFFER_FREE_OFF` (offset from `nm` because qjs is unstripped).

2. **Arbitrary write primitive (targeted)**
   - We create a length-tracking `BigUint64Array` and corrupt its internal data pointer (`JSObject.u.array.u.ptr`, offset 0x38) using the same UAF trick:
     - Free a 0x60-sized chunk by resizing a 0x48-byte RAB (0x48 == sizeof(JSObject) in this build).
     - Allocate the victim typed array so its JSObject reuses that freed chunk.
     - Use `Atomics.store(trigger_view, 7, evil)` where `evil.valueOf()` performs the resize+allocation and returns the desired 64-bit pointer.
     - The stale pointer lands at `old_chunk + 0x38`, overlapping the victim JSObject’s `u.ptr` field.
     - Result: the victim typed array’s backing pointer is replaced with an attacker-chosen address.

## Control-flow hijack: overwrite qjs GOT (partial RELRO)
The qjs binary is **PIE + partial RELRO** (no `BIND_NOW`), so `.got.plt` entries remain writable.

We compute:
- `system_addr = libc_base + SYSTEM_OFF`
- `free_got_addr = qjs_base + FREE_GOT_OFF` (from `objdump -R qjs`)

Then:
- Point the corrupted `BigUint64Array` at `free@GOT` and write `system_addr` into it.

Now any future `free(ptr)` invoked by qjs becomes `system(ptr)`.

## Shell spawn trigger
We need the spawned shell to read stdin and execute the verifier’s first line (`nc 127.0.0.1 9999`).

Trigger:
- Create an `ArrayBuffer` whose backing bytes contain the NUL-terminated string `/bin/sh`.
- Call `ArrayBuffer.prototype.transfer(0)`.
  - Internally QuickJS detaches the buffer and frees its backing store.
  - That `free(ptr)` call goes through qjs’s PLT/GOT and is now `system(ptr)`.
  - This executes `system("/bin/sh")` → `/bin/sh -c "/bin/sh"`.
  - The spawned shell inherits stdin and executes the verifier-provided `nc ...` command, connecting back to port 9999.

## Why this meets the rules
- No `/proc` or `/sys` reads.
- No direct use of `os.exec` / `std.popen`.
- ASLR is bypassed using only the vulnerability-based memory disclosures.
- Code execution is achieved by exploiting the UAF to corrupt memory (GOT overwrite) and redirect control flow.

## Files
- PoC: `/tmp/work/poc.js`
