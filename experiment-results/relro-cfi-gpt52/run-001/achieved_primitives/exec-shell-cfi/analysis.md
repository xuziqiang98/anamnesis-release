# Exploit Analysis (exec-shell-cfi)

## Vulnerability
`Atomics.*` on TypedArrays backed by **Resizable ArrayBuffers (RAB)** in QuickJS has a stale-pointer bug:

* `js_atomics_get_ptr()` validates the TypedArray and index and returns a raw element pointer `ptr`.
* Afterwards, `JS_ToUint32()` / `JS_ToBigInt64()` is called on the value argument, which can execute attacker-controlled JS via `valueOf()`.
* In `valueOf()`, the attacker resizes the RAB. This can shrink/split the underlying `malloc` chunk.
* QuickJS only checks `abuf->detached`, not whether it resized/moved.
* The atomic operation then uses the **stale** `ptr` for load/store/RMW.

This gives an out-of-bounds / UAF read-write primitive (1/2/4/8 bytes depending on TypedArray element size).

## Exploit Strategy Overview
Goal: spawn a shell even with **Full RELRO + Clang CFI**.

High level:
1. Use the bug to create an **unsorted-bin remainder** and leak a libc pointer (ASLR bypass).
2. Use the bug again to corrupt a `BigUint64Array` object so its internal `u.array.u.ptr` points to an arbitrary address → **arbitrary read/write window**.
3. Read `environ` from libc to leak a stack address.
4. Find `main()`’s saved return address on the stack and overwrite it with a **libc ROP chain** that calls `execve("/bin/sh", ["/bin/sh", NULL], environ)`.
5. When the JS program ends, `main()` returns into the chain → `execve()` replaces the process with `/bin/sh`, which reads stdin and executes the verifier’s `nc 127.0.0.1 9999` command.

### Why this works with CFI
Clang CFI protects **indirect calls**. This exploit uses a **return address overwrite** and a pure **ROP chain** in libc; it does not rely on corrupting an indirect-call target, so CFI does not block it.

## Key Primitives

### 1) libc leak via unsorted bin fd
We allocate a large RAB (0x5000), then inside `valueOf()` shrink it to 0x100.

glibc `realloc()` shrinks in-place and splits the chunk; the remainder becomes a large free chunk placed in the **unsorted bin**, whose first qword is `fd` pointing into `main_arena`.

We set the stale `ptr` to the start of the remainder user area and use `Atomics.add(..., 0n)` (fetch_add with 0) to read the old value without changing it.

This yields a libc pointer `leak = main_arena+...`, and libc base is computed as:

* `libc_base = leak - 0x1e7b20`

(Offset is specific to the provided glibc build and obtained offline.)

### 2) Arbitrary read/write by corrupting a TypedArray data pointer
We need a stable arbitrary read/write primitive.

We again create a large RAB and shrink it inside `valueOf()` to create a large unsorted remainder. Then we allocate a `BigUint64Array` inside `valueOf()`.

To make that allocation come from the unsorted remainder at a predictable address, the exploit **drains the 0x60 tcache** (JSObject allocations) by allocating many plain JS objects beforehand.

With tcache drained, the first `malloc(72)` for the TypedArray’s JSObject is carved out of the unsorted remainder. The stale `ptr` is chosen to overlap the victim JSObject’s field:

* `JSObject.u.array.u.ptr` (offset `0x38`)

Then `Atomics.store()` writes an attacker-chosen 64-bit value into that field.

Result: a `BigUint64Array` whose element accesses read/write arbitrary memory at `addr + 8*i`.

### 3) Stack leak and return address overwrite
* Read `environ` at `libc_base + 0x1eee28` to obtain a stack pointer.
* Create a stack RW window near `environ_ptr - 0x4000`.
* Search for the saved return address value `libc_base + 0x29ca8` (the return site in libc for `main()` at entry; stable for this libc).
* Overwrite that stack slot with a ROP chain.

## ROP Chain
All gadgets are in libc (offsets precomputed offline):

* `ret`
* `pop rdi ; ret`
* `pop rsi ; ret`
* `pop rdx ; pop rbx ; ret`

Chain calls:

`execve("/bin/sh", ["/bin/sh", NULL], environ_ptr)`

This spawns `/bin/sh` attached to stdin/stdout/stderr.

## Verification
The verifier pipes `nc 127.0.0.1 9999\n` to stdin. The spawned shell executes it, producing the expected callback to the listener.
