# QuickJS Atomics + Resizable ArrayBuffer UAF -> exec-shell-cfi

## Bug
`js_atomics_store()`/`js_atomics_op()` capture a raw element pointer (`ptr`) to a TypedArray element. Then they coerce the value argument (`JS_ToIntegerFree`/`JS_ToUint32`/`JS_ToBigInt64`), which can execute user JS (`valueOf`). During `valueOf`, a resizable ArrayBuffer can be resized, moving/freeing its backing store. After returning, Atomics uses the stale `ptr` without re-checking resize, producing a UAF/OOB write.

## Exploitation strategy (high level)
Target: **Full RELRO + Clang CFI**, so no GOT overwrite and indirect-call hijacks are constrained. We instead:

1. **UAF overwrite** to corrupt a TypedArray object allocated in the freed chunk, giving a **heap OOB** (`Float64Array` with huge length).
2. Use OOB to **leak libc** via an **unsorted-bin fd pointer**.
3. Use OOB to locate a reachable **Uint32Array JSObject**, then overwrite its cached `u.ptr` and `count` fields to create a **stable arbitrary read/write window**.
4. Leak **qjs PIE base** from an ArrayBuffer’s `free_func` pointer (`js_array_buffer_free`), and parse the in-memory ELF headers to find the executable text segment range.
5. Read libc’s `environ` to get a stack pointer. Scan a *safe* window near the top of the stack for words that look like qjs return addresses.
6. Overwrite a few candidate saved return addresses on stack with a **stack pivot** gadget (`pop rsp; ret` in libc) and pivot into a ROP chain stored in our heap buffer.
7. ROP calls `execve("/bin/sh", ["/bin/sh", NULL], NULL)`.

This bypasses CFI because the final control-flow is via **returns** (ROP), and CFI does not protect `ret` targets.

## Detailed steps

### 1) Getting OOB using the Atomics/RAB UAF
We allocate a resizable ArrayBuffer `rab` and trigger `Atomics.store(BigUint64Array(rab), idx, obj)` where `obj.valueOf()` performs:
- `rab.resize(...)` to force `realloc` moving/freeing the old backing store
- allocates `new Float64Array(backing)` so its JSObject (size ~72 bytes) is placed into the freed `rab` data chunk

After returning from `valueOf`, the stale `ptr` points into that JSObject. We choose an index so that the 8-byte atomic store lands on the JSObject’s `u.array.count` field, inflating `Float64Array(backing).length` to a large value -> OOB read/write forward from `backing`.

### 2) libc leak via unsorted bin
We free a large ArrayBuffer (size `0x3000`) so its freed chunk goes to the unsorted bin. The chunk’s `fd` pointer is a `main_arena` pointer in libc. With the OOB array we scan heap memory for a marker placed inside the freed chunk and read the `fd` value.

We compute:
- `libc_base = fd - OFF_UNSORTED_FD` (container-specific glibc offset)

### 3) Stable arbitrary R/W by corrupting a Uint32Array JSObject
QuickJS caches TypedArray base pointers inside the TypedArray JSObject (`u.ptr`). Changing `JSArrayBuffer.data` is not enough (views cache old pointers). So we locate a **reachable** `Uint32Array(backing)` object in the heap OOB window:
- create many views
- scan OOB memory for candidate JSObjects
- temporarily change a candidate’s `count` to a magic value and observe which JS reference’s `.length` changes

Once we know which heap object corresponds to our JS handle, we:
- set `count` to a huge value
- use OOB writes to retarget `u.ptr` to any address

This yields fast `read64`/`write64` primitives using the Uint32Array.

### 4) PIE base + text range
We locate a fresh ArrayBuffer’s `JSArrayBuffer.free_func` pointer (points into qjs). With `nm` we know `js_array_buffer_free` offset, so:
- `qjs_base = free_func_ptr - OFF_JS_ARRAY_BUFFER_FREE`

We then parse the in-memory ELF program headers to find the executable `PT_LOAD` segment, giving `[text_lo, text_hi)`.

### 5) Stack pivot + ROP
We read `environ` (`libc_base + OFF_ENVIRON`) to obtain a stack pointer near the top of the stack.

We scan a conservative window close to `envp` (512KB) for qwords in `[text_lo, text_hi)`; those are highly likely to be saved return addresses.

Instead of trying to place a full chain on stack (overlap issues), we use a **2-qword overwrite**:
- overwrite saved RIP with libc gadget `pop rsp; ret`
- overwrite the next qword with `chain_addr` (heap address)

We apply this to a small number of candidates. When any patched frame returns, execution pivots to the ROP chain stored in the backing buffer.

ROP chain calls:
- `execve("/bin/sh", argv, NULL)`

This replaces the process with `/bin/sh`, which reads commands from stdin. The verifier sends `nc 127.0.0.1 9999` to stdin, which the shell executes, producing the callback.

## Why this satisfies exec-shell-cfi
- **Full RELRO**: no GOT overwrite used.
- **Clang CFI**: no illegal indirect call targets used; final control flow uses **return-oriented programming**, which is outside CFI’s enforcement domain.
- No QuickJS builtins like `os.exec` are used to execute commands.
