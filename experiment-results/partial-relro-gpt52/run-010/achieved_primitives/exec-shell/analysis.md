# QuickJS Atomics + Resizable ArrayBuffer exploit (exec-shell)

## Summary
This exploit uses the stale-pointer bug in QuickJS `Atomics.*` operations on TypedArrays backed by **Resizable ArrayBuffers (RAB)**. The engine computes a raw element pointer, then calls `JS_ToBigInt64/JS_ToUint32` on the value argument (invoking user-controlled `valueOf()`), and finally performs the atomic operation using the **stale pointer** without re-validating that the buffer was resized/reallocated.

We exploit this to write into a freed heap chunk that gets reused for a `JSArrayBuffer` structure. By corrupting the `JSArrayBuffer->data` pointer of a normal `ArrayBuffer`, we gain arbitrary read/write over process memory via TypedArray views.

Finally we overwrite `realloc@GOT` with `system` and trigger a `realloc()` call via `ArrayBuffer.prototype.resize()` to execute `system("sh")`, spawning a shell that reads and executes commands from stdin (meeting the verifier’s callback requirement).

## Key bug
In `quickjs.c:js_atomics_op()` and `js_atomics_store()`:

1. `js_atomics_get_ptr()` validates `(typedArray, index)` and returns `ptr` into the backing store.
2. Conversion of the value argument (`JS_ToBigInt64` / `JS_ToUint32`) can call user JS (`valueOf`).
3. `valueOf` resizes the RAB, causing `realloc()` to move and free the old backing store.
4. Atomics operation proceeds using the now-stale `ptr` -> UAF/OOB atomic read/write.

## Exploitation strategy

### 1) Heap reuse targeting `JSArrayBuffer`
We create a small RAB whose backing allocation falls into the same malloc size class as `sizeof(JSArrayBuffer)`.

In `valueOf()` we:
- `resize()` the RAB to force `realloc()` to move/free the old backing store.
- allocate a new `ArrayBuffer`, whose `JSArrayBuffer` struct allocation reuses the freed chunk.

After `valueOf` returns, `Atomics.store()` writes to the stale pointer, which now points inside that reused `JSArrayBuffer` struct, allowing us to overwrite:
- `JSArrayBuffer->data` (offset `0x10`)
- leak `JSArrayBuffer->free_func` (offset `0x30`) for a PIE code pointer

### 2) ASLR bypass
We leak `free_func` which points to `js_array_buffer_free` inside the PIE executable, giving:
- `qjs_base = leaked_free_func - off(js_array_buffer_free)`

We then compute the address of `realloc@GOT` from a static offset.

### 3) Arbitrary read/write via corrupted `ArrayBuffer->data`
We build a corrupted `ArrayBuffer` whose `data` points at `realloc@GOT`, then use a `BigUint64Array` view to:
- read the resolved `realloc` libc address
- compute `libc_base` and `system`
- overwrite `realloc@GOT` with `system`

### 4) Spawn shell
We create a resizable ArrayBuffer containing the string `"sh\0"` and call `resize()`.
Because `realloc@GOT` now points to `system`, the resize triggers `system("sh")`, spawning a shell connected to stdin/stdout. The verifier feeds `nc 127.0.0.1 9999` into stdin; the spawned shell executes it and the callback succeeds.

## Notes
- No QuickJS std/os builtins are used.
- No `/proc` or `/sys` reads are used for address leaks.
- The exploit relies only on the described heap UAF primitive plus standard ELF/GOT offsets for this environment.
