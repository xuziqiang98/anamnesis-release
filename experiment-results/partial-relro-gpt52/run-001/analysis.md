# QuickJS Atomics/RAB UAF -> exec-shell

## Overview
The bug is in `js_atomics_op()` / `js_atomics_store()`:

1. `js_atomics_get_ptr()` computes a raw element pointer `ptr` into a TypedArray.
2. Argument conversion (`JS_ToUint32` / `JS_ToBigInt64`) can run user JS (`valueOf`).
3. During `valueOf`, a **Resizable ArrayBuffer (RAB)** can be resized, causing `realloc()` to **move** the backing store and **free** the old chunk.
4. The Atomics operation then executes using the stale `ptr` (UAF / OOB).

We use this to build:
- a **libc leak** (UAF read from an unsorted-bin freed chunk),
- an **arbitrary read/write** by overlapping a freed 0x50 chunk with a `JSArrayBuffer` header and corrupting its `data` pointer,
- a **GOT overwrite** to redirect a libc call to `system("/bin/sh")`.

The verifier feeds `nc 127.0.0.1 9999\n` to stdin; a spawned `/bin/sh` reads stdin and executes it, producing the callback.

## Stage 1: libc base leak via unsorted-bin fd

We create a large RAB and a `BigUint64Array` view.

- Initial size: `0x5000` (large enough that when freed it goes to **unsorted bin**).
- In `valueOf()`, resize to `0x40000` (> mmap threshold) to force `realloc()` to **move** and free the old chunk.

Immediately after `realloc` frees the old chunk into the unsorted bin, glibc writes the bin pointers into the freed chunk’s user-data (`fd`/`bk`).

We then execute `Atomics.compareExchange(ta, 0, malicious, 0n)`:
- `ptr` is captured **before** `valueOf`.
- `valueOf` frees the old chunk.
- the stale `ptr` reads the freed chunk’s first qword (unsorted-bin `fd`).

On glibc 2.41 the unsorted-bin head pointer equals `main_arena + 0x60` (it points to the fake bin header: `&bins[0] - 0x10`).
So:

```
libc_base = leak_fd - 0x1e7b20
```

## Stage 2: arbitrary read/write by corrupting `JSArrayBuffer->data`

We need a reliable way to read and write process memory (stack + qjs image + GOT).

We exploit chunk-size matching:
- `sizeof(JSArrayBuffer)` is 0x38 bytes, so the allocator chunk size is **0x50**.
- We allocate a RAB with byteLength **0x38** so its *data backing store* is also a **0x50** chunk.

In `valueOf()`:
1. `rab.resize(0x40000)` forces `realloc()` to move and **free** the old 0x50 chunk into tcache.
2. `victim = new ArrayBuffer(...)` allocates a fresh `JSArrayBuffer` header (0x38) which reuses the freed 0x50 chunk.

After returning from `valueOf`, `Atomics.exchange()` uses the stale pointer (into the freed chunk, now the `JSArrayBuffer` header) to overwrite the `data` field:
- `data` is at offset **0x10** inside `JSArrayBuffer`.
- With `BigUint64Array`, element index `2` targets offset `0x10`.

This yields a “fake” ArrayBuffer whose backing pointer can be set to an arbitrary address; creating a TypedArray over it gives direct memory reads/writes.

## Stage 3: leak qjs PIE base from initial stack (auxv)

The process initial stack contains `argv[]`, `envp[]`, and then the ELF auxiliary vector (`auxv`).

Instead of using `environ` (copy-relocated into the main executable), we read glibc’s internal `__libc_argv` from libc `.bss`:

- `__libc_argv` offset in this glibc: `0x1e86e0`.
- `argv_ptr = *(uint64_t *)(libc_base + 0x1e86e0)`.

Using the arbitrary read primitive, we scan:
1. `argv[]` until NULL,
2. `envp[]` until NULL,
3. parse `auxv` pairs until finding `AT_PHDR` (type 3).

`AT_PHDR` gives the in-memory address of the program headers, i.e. `qjs_base + e_phoff`.
For qjs, `e_phoff = 0x40`.

So:

```
qjs_base = AT_PHDR_value - 0x40
```

## Stage 4: GOT overwrite fopen -> system, then spawn shell

qjs is PIE but only **Partial RELRO**, so the GOT is writable.

From `readelf -r qjs`, the `fopen` GOT relocation offset is `0x10b340`.

We compute:

```
fopen_got = qjs_base + 0x10b340
system    = libc_base + 0x53110
```

Then write `system` into `fopen@GOT`.

Finally:
- import the `std` module (done before the GOT overwrite),
- call `std.open("/bin/sh", "r")`.

`std.open()` calls `fopen(filename, mode)`, but after the overwrite this becomes `system("/bin/sh")`, spawning a shell that reads commands from stdin. The verifier’s first stdin line is `nc 127.0.0.1 9999`, which the shell executes, producing the required callback.

## Notes
- The exploit deliberately keeps corrupted ArrayBuffers alive to avoid GC-triggered frees of non-malloc pointers.
- The process may crash on exit due to freeing corrupted buffers; this does not affect the verifier because the callback happens immediately after the shell runs `nc`.
