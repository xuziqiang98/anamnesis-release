# Exploit Analysis (QuickJS Atomics + Resizable ArrayBuffer UAF) -> exec-shell

## Primitive Achieved
**exec-shell**: the PoC overwrites `fwrite@GOT` with `system` and then executes `print("/bin/sh")`, resulting in `system("/bin/sh")` spawning a shell which reads commands from `stdin`.

The verifier pipes `nc 127.0.0.1 9999\n` to stdin; the spawned `/bin/sh` executes it and connects back, producing `[ShellVerify] SUCCESS`.

## Vulnerability Used
The bug is in `js_atomics_op()` / `js_atomics_store()`:

* `js_atomics_get_ptr()` computes a raw element pointer `ptr` into a TypedArray (backed by a resizable ArrayBuffer).
* The value argument conversion (`JS_ToBigInt64`/`JS_ToUint32`) can execute user JavaScript (`valueOf`).
* During `valueOf`, the attacker resizes the underlying resizable ArrayBuffer (`ab.resize(...)`). This can `realloc()` the backing store, freeing the old backing store.
* After returning, the Atomics operation continues using the **stale `ptr`**, producing a UAF (or OOB) access.

We exploit this by forcing `realloc` to move the backing store, then reusing the freed chunk for a different allocation, so that the stale `ptr` reads/writes attacker-chosen structures.

## Key Heap/Allocator Detail (glibc 2.41)
The original ASAN-based trigger hard-coded sizes that don’t map cleanly to glibc bins.

On this system (glibc 2.41), we need the freed backing store chunk to be reused by a `malloc(56)` allocation (the `JSArrayBuffer` struct allocation).

We therefore create a resizable ArrayBuffer with initial `byteLength = 0x38` (56). That backing store allocation is compatible with the later `malloc(56)` allocation for `JSArrayBuffer`.

We also allocate a “barrier” ArrayBuffer after the target RAB backing store to reduce the chance that `realloc` grows in-place.

## Exploitation Strategy
### 1) UAF overlap with `JSArrayBuffer` struct
We call `Atomics.compareExchange(BigInt64Array, idx, expected, replacement)`.

* `js_atomics_get_ptr()` captures a stale pointer into the old RAB backing store.
* `expected` is an object whose `valueOf()`:
  1. grows the RAB (`ab.resize(0x6000)`) forcing `realloc` and freeing the old backing store chunk,
  2. allocates `victim = new ArrayBuffer(...)` so that `malloc(56)` for the victim’s `JSArrayBuffer` struct **reuses** the freed backing-store chunk.

At this point, the stale `ptr` points into the victim’s `JSArrayBuffer` struct.

### 2) PIE leak (qjs base)
We leak the function pointer stored in `JSArrayBuffer.free_func`:

* We target offset `+48` inside `JSArrayBuffer` (word index 6 of a BigInt64 view).
* We use `Atomics.compareExchange` with an expected value that will not match, so it **reads** and returns the old 64-bit value without writing.

This yields the runtime address of `js_array_buffer_free` (a function in the PIE main binary).

We compute:

* `qjs_base = leak(js_array_buffer_free) - OFF_JS_ARRAY_BUFFER_FREE`

### 3) libc leak via GOT read
With `qjs_base`, we compute the address of `fwrite@GOT`:

* `fwrite_got = qjs_base + OFF_FWRITE_GOT`

We create a second UAF overlap, but this time we use `Atomics.store` at offset `+16` (word index 2) to overwrite `JSArrayBuffer.data` with `fwrite_got`.

Now a normal `DataView` on that corrupted ArrayBuffer can read arbitrary memory at `fwrite@GOT`.

We first call `print('X')` to force lazy-binding so `fwrite@GOT` contains the resolved libc address.

Then:

* `fwrite_addr = *(uint64_t*)fwrite_got`
* `libc_base = fwrite_addr - OFF_LIBC_FWRITE`
* `system_addr = libc_base + OFF_LIBC_SYSTEM`

### 4) GOT overwrite to gain code execution
We write `system_addr` back into `fwrite@GOT` using the same corrupted `DataView`.

Now the next call to `print(str)` will execute:

* `system(str)`

because `js_print()` calls `fwrite(str, 1, len, stdout)` and on x86_64 the extra arguments are ignored by `system()`.

### 5) exec-shell
Finally:

* `print('/bin/sh')`  ->  `system('/bin/sh')`

`system` spawns `/bin/sh -c /bin/sh`, which starts a shell that reads commands from stdin. The verifier’s `nc 127.0.0.1 9999` line is consumed and executed by the shell, proving command execution.

## Files
* PoC: `/tmp/work/poc.js`

## Notes on Constraints
* No `/proc` or `/sys` is read.
* No QuickJS built-ins like `os.exec()` / `std.popen()` are used.
* ASLR is bypassed using only memory disclosures obtained via the UAF (leaking `js_array_buffer_free` and `fwrite@GOT`).
