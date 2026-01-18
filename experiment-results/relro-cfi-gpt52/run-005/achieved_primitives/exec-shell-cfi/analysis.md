# exec-shell-cfi exploit for QuickJS Atomics + RAB stale pointer

## Vulnerability recap
In `quickjs.c` (`js_atomics_op()` / `js_atomics_store()`), QuickJS:

1. Calls `js_atomics_get_ptr()` to validate the TypedArray and compute a raw element pointer `ptr`.
2. Converts the value argument via `JS_ToUint32()` / `JS_ToBigInt64()`.
   *This conversion can execute attacker-controlled JS via `valueOf()`.*
3. Only checks `abuf->detached` and then performs the atomic operation using the **stale** `ptr`.

If the TypedArray is backed by a **Resizable ArrayBuffer**, attacker JS can call `ab.resize()` inside `valueOf()`, moving/freeing the backing store. The stale `ptr` becomes a UAF/OOB write target.

## Exploit strategy overview
Target is **Full RELRO + Clang CFI**. We therefore avoid GOT overwrites and CFI-restricted indirect calls. Instead we build a classic **return-address ROP** (CFI does not protect `ret`).

High level:

1. **libc base leak** via unsorted-bin metadata read through the stale pointer.
2. **Arbitrary read/write** by overlapping a freed backing-store chunk with a `JSArrayBuffer` struct and corrupting `JSArrayBuffer::data`.
3. Leak `envp` from libc `environ`, then overwrite a deterministic saved return address on the stack.
4. ROP chain calls `execve("/bin/sh", ["/bin/sh"], NULL)`.

The verifier pipes a command to stdin; `/bin/sh` reads stdin and executes it, producing the callback.

## 1) libc leak (unsorted-bin fd)
We create a resizable ArrayBuffer with initial size **0x1000** and grow it in `valueOf()`.
The old backing store is a large chunk that goes to the **unsorted bin**, whose user-data begins with `fd` pointing into `main_arena`.

We read that `fd` via `Atomics.compareExchange()` using the stale pointer.

`libc_base = fd - 0x1e7b20` (glibc 2.41 main_arena offset).

## 2) AAR/AAW by corrupting JSArrayBuffer::data
We need the stale write to land inside a `JSArrayBuffer` struct.

Key allocator detail (glibc 2.41):
* `malloc(0x40)` returns **usable=72**, which can satisfy `malloc(72)` (JSObject allocations), stealing the freed chunk.
* `malloc(0x38)` returns **usable=56**, which matches the `JSArrayBuffer` struct allocation size (56) but **cannot** satisfy `malloc(72)`.

So we use a resizable backing store of **0x38** bytes, then resize bigger in `valueOf()` and immediately allocate a new `ArrayBuffer()`. The freed 0x38 backing store chunk is deterministically reused for the new buffer’s `JSArrayBuffer` struct.

Then `Atomics.store(BigUint64Array(rab), index=2, value=target_addr)` writes 8 bytes at offset `2*8 = 16` into the overlapped struct, which corresponds to `JSArrayBuffer::data`.

This yields a controlled `DataView` over arbitrary memory.

## 3) Stack targeting without /proc
We read libc’s `environ` variable (offset `0x1eee28`) to obtain `envp` (top-of-stack pointer).

In this specific build, the saved return address for `eval_buf()` is at a stable offset from `envp`:

* `saved_rip_addr = envp - 0x4e8`

(derived with gdb; consistent for this target binary).

We create a small stack window DataView at `envp-0x8000` and overwrite the saved RIP at `envp-0x4e8`.

## 4) ROP chain (CFI-safe)
We use only libc code and `ret`-based control flow.

ROP chain:

* `ret` (alignment)
* `pop rdi ; ret` -> `/bin/sh`
* `pop rsi ; ret` -> `argv` array (placed on stack right after the chain)
* `pop rdx ; pop rbx ; ret` -> `0, 0`
* `execve`

This spawns `/bin/sh` which reads stdin and executes the verifier’s command.

## Notes on constraints
* No QuickJS built-ins like `os.exec()`/`std.popen()` are used.
* No `/proc` reads.
* No one_gadget.
* Full RELRO is irrelevant because we do not touch the GOT.
* Clang CFI is bypassed by using `ret`-based ROP, not type-checked indirect calls.
