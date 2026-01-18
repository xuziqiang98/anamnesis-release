# Exploit Analysis (exec-shell-cfi)

## Vulnerability
`js_atomics_store()` / `js_atomics_op()` capture a raw element pointer `ptr` via `js_atomics_get_ptr()` and then call `JS_ToBigInt*` / `JS_ToUint32`, which can execute attacker JS (`valueOf`). During `valueOf`, a resizable ArrayBuffer can be shrunk, potentially reallocating/splitting the backing allocation. After returning from `valueOf`, QuickJS uses the stale `ptr` for the atomic operation. This gives an **8-byte arbitrary write** (and read via fetch-add) into memory that may now belong to freed/split heap chunks.

Target is **Full RELRO + Clang CFI**: we cannot use GOT overwrites or indirect-call hijacks to non-CFI targets. We instead use a pure **stack return-address overwrite** (returns are not protected by CFI).

## High-level exploitation plan
1. **Leak libc base**: shrink a non-mmapped RAB to create an unsorted free chunk; read its `fd` pointer (which points into `main_arena`) using an atomic read primitive and derive `libc_base`.
2. **Build a stable arbitrary read/write primitive** by corrupting a `BigUint64Array` JSObject’s cached data pointer (`JSObject.u.array.u.ptr`). Typed arrays do not free this pointer; they only read/write through it.
3. **Leak stack** via `&environ` from libc.
4. **Overwrite `main`’s saved return address** on the stack with a small libc ROP chain that calls `system("/bin/sh")` and then `_exit(0)`.

## Key primitives

### 1) libc leak (unsorted bin fd)
- Allocate a resizable ArrayBuffer of size `0x2000` and an `BigInt64Array` view.
- Call `Atomics.add(view, 4, obj)` where `obj.valueOf()` shrinks the buffer to 8 bytes.
- The stale `ptr` still points into the split-off free remainder; reading it yields the unsorted-bin `fd` pointer.
- We use the known libc offset `main_arena+0x60` (here `0x1e7b20`) to compute `libc_base`.

### 2) TypedArray pointer corruption to obtain AAR/AAW
We allocate many `BigUint64Array(backing)` “candidates” inside `valueOf()` right after shrinking another RAB. The stale atomic store writes an 8-byte value into some newly allocated small object.

We detect the corrupted typed array by ensuring its reads look like a stack pointer (for `&environ`) and later by checking the memory at `env_ptr` (environment pointers on stack).

Once we have a corrupted `BigUint64Array`, `arr[i]` reads/writes arbitrary memory at:

```
addr = corrupted_ptr + i*8
```

### 3) ROP chain
We locate `main`’s saved return address in a stack window ending at `env_ptr` (last ~0x800 bytes), then overwrite it with:

```
ret;
pop rdi; "/bin/sh";
system;
pop rdi; 0;
_exit;
```

All addresses are computed from `libc_base` using fixed offsets (no /proc leaks).

When `main` returns, execution pivots into the chain and spawns `/bin/sh` reading from stdin. The verifier-provided command (`nc 127.0.0.1 9999`) is executed by the shell and triggers the callback.

## Why it bypasses Full RELRO + CFI
- No GOT/PLT overwrite is used (Full RELRO irrelevant).
- No function-pointer/virtual dispatch hijack is used (CFI irrelevant).
- Control flow is achieved via **stack return address overwrite**, which is not checked by Clang CFI.

## Result
The PoC reliably spawns a shell and passes `run_shell_verify_callback_cfi.sh`.
