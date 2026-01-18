# Exploit Analysis (exec-shell-cfi)

## Summary
This exploit uses the Atomics + Resizable ArrayBuffer bug to get a **stale pointer** into a heap chunk that is freed/reused during `valueOf()` re-entrancy. Using that stale pointer we:

1. **Leak a libc pointer** from an **unsorted-bin freed chunk**.
2. **Corrupt a `Uint8Array` JSObject** to turn it into an **arbitrary read/write (ARW) byte view** by overwriting its internal `u.array.u.ptr` field.
3. Use ARW to overwrite **`main()`’s saved return address** on the stack with a short **libc ROP chain**:

`ret; pop rdi; ret; system("/bin/sh"); _exit()`

When `main()` returns, the process jumps into the ROP chain, spawning `/bin/sh` which reads and executes stdin. The verifier supplies `nc 127.0.0.1 9999\n` on stdin, and the spawned shell executes it, creating the required callback.

This works under **Full RELRO** (no GOT overwrite) and **Clang CFI** (no invalid indirect-call targets). We only use a return-address overwrite (ROP), which is not blocked by CFI.

## Root cause
In `js_atomics_store()`/`js_atomics_op()`:

* `js_atomics_get_ptr()` computes a raw element pointer `ptr` into a TypedArray backing store.
* Then `JS_ToBigInt64()` / `JS_ToUint32()` converts an attacker-controlled object, which can execute JS via `valueOf()`.
* During `valueOf()`, attacker code can `ArrayBuffer.prototype.resize()`, causing `realloc()` and freeing/moving the backing store.
* After returning, Atomics uses the stale `ptr` for the atomic access.

## Stage 1: libc leak via unsorted bin
We create a resizable ArrayBuffer of size `0x500` and trigger `Atomics.compareExchange()`:

* `valueOf()` grows the buffer (`resize(0x900)`), forcing `realloc()` and freeing the old `0x500` chunk.
* That freed chunk lands in the **unsorted bin**, whose first qword becomes `fd` pointing into libc (`main_arena` region).
* Because `compareExchange` can be made to *not write* (mismatched expected), we get a pure read.

Empirically for the provided glibc (Debian glibc 2.41), the leak is:

`libc_base = unsorted_fd - 0x1e7b20`

## Stage 2: building an ARW `Uint8Array`
We want a JS primitive that reads/writes arbitrary addresses. QuickJS typed arrays use the JSObject “fast array” fields:

* `p->u.array.u.ptr` (data pointer)
* `p->u.array.count` (length)

We exploit the stale-pointer write to overwrite `u.array.u.ptr` in a newly created `Uint8Array` object:

1. Create a small resizable ArrayBuffer (`0x48`) and a `BigUint64Array` view.
2. Trigger `Atomics.store(ta, idx, evil)` where `evil.valueOf()`:
   * calls `resize(0x500)` to free the old `0x48` backing-store chunk
   * allocates `victim = new Uint8Array(large_backing)` to reclaim that freed chunk as a **JSObject**
   * returns the desired 64-bit address to store
3. After `valueOf()` returns, Atomics performs the stale `atomic_store` into the reclaimed chunk.

In this build the `u.array.u.ptr` field sits at offset `0x38` in the `JSObject`, so we use index `7` (`7*8 = 0x38`).

Result: `victim` becomes an ARW byte-view over attacker-chosen address.

## Stage 3: stack return-address overwrite + ROP
Using the libc base, we read `environ` (dynamic symbol) to get the stack location of `envp`:

* `environ_addr = libc_base + 0x1eee28`
* `envp = *(uint64_t*)environ_addr`

On this target, at `main()` entry:

* `saved_return_address_location = envp - 0x128`

We create a second ARW `Uint8Array` pointing to `saved_return_address_location` and write a ROP chain using libc gadgets:

* `ret` @ `libc_base + 0x2846b` (stack alignment)
* `pop rdi; ret` @ `libc_base + 0x2a145`
* `system` @ `libc_base + 0x53110`
* `"/bin/sh"` string @ `libc_base + 0x1a7ea4`
* `_exit` @ `libc_base + 0xdd280`

When `qjs` finishes and `main()` returns, execution flows into the chain and spawns `/bin/sh` reading stdin.

## Notes on constraints
* No `os.exec()` / `std.popen()` are used.
* No `/proc` or `/sys` address leaks.
* No one_gadget.
* Full RELRO is bypassed by stack ROP, not GOT overwrites.
* CFI is bypassed because we do not forge indirect-call targets; we overwrite a return address.
