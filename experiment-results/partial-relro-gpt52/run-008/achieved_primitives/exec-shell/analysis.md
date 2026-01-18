# Exploit Analysis (exec-shell)

## Vulnerability recap
`js_atomics_op()` / `js_atomics_store()` compute a raw element pointer for a TypedArray (`js_atomics_get_ptr()`), then call `JS_ToUint32` / `JS_ToBigInt64` on a user-controlled value. Those conversions can execute user JS (`valueOf`). If `valueOf` resizes a **Resizable ArrayBuffer** (RAB), the backing store can shrink and `realloc()` can split/free a tail chunk. The atomic op then uses the **stale pointer**, giving a UAF/OOB primitive.

Key bug: only `abuf->detached` is checked after user code; there is no re-validation of bounds or pointer after resize.

## High-level exploit strategy
We need native code execution without using forbidden QuickJS built-ins.

We use the bug to:
1. **Leak libc base** via an unsorted-bin pointer.
2. **Leak JSContext and JSRuntime pointers**.
3. **Overwrite `JSRuntime.sab_funcs.sab_free` and `sab_opaque`** to call `setcontext(ucontext)`.
4. Craft a `ucontext_t` that pivots into `execve("/bin/sh", ["/bin/sh","-i"], …)`.

The shell replaces the qjs process image and reads commands from stdin (verifier pipes `nc ...` to stdin).

## Primitive 1: libc leak (unsorted bin)
We allocate a large RAB (0x5000) and call `Atomics.add()` with a malicious `valueOf` that resizes the buffer to 0x20.

`realloc()` splits a large tail chunk; since it’s > tcache max, it goes to the **unsorted bin**. The first qword of a freshly-freed unsorted chunk user area is `p->fd = bin_at(main_arena,1)` (i.e. `main_arena + 0x60` on glibc x86-64 because of the `-offsetof(malloc_chunk, fd)` adjustment).

We use `Atomics.add(..., 0n)` so the writeback doesn’t change the metadata.

`libc_base = leak - main_arena_off - 0x60`.

Constants (glibc 2.41, from debug symbols):
- `main_arena` offset: `0x1e7ac0`

## Primitive 2: leak JSContext*
We need `JSRuntime*` to patch `sab_funcs`.

We force a runtime bytecode allocation via `new Function("return 1")` while a carefully-sized realloc remainder is free. We then read the `JSFunctionBytecode.realm` field (type `JSContext*`) at a known offset inside that remainder using the stale atomic pointer.

## Primitive 3: arbitrary read/write into JSRuntime via corrupted TypedArray
We create a `BigUint64Array` object whose internal `u.array.u.ptr` is overwritten by the stale atomic store:
- Use a RAB shrink that reliably produces a remainder chunk used for the `BigUint64Array` **JSObject** allocation.
- Target the `u.array.u.ptr` field at offset 56 inside `JSObject`.
- `Atomics.exchange` returns the original pointer (useful heap leak), and writes our chosen pointer.

With `u.array.u.ptr = ctx`, `view[3]` reads `*(ctx+0x18)` which is `ctx->rt` (JSRuntime*).

We create a second corrupted `BigUint64Array` with `u.array.u.ptr = rt` to write into the runtime structure.

## Control-flow hijack: `sab_free = setcontext`
QuickJS finalizes SharedArrayBuffers with:

```c
rt->sab_funcs.sab_free(rt->sab_funcs.sab_opaque, abuf->data);
```

So if we overwrite:
- `rt->sab_funcs.sab_free = setcontext`
- `rt->sab_funcs.sab_opaque = <ucontext address>`

then finalization calls `setcontext(ucontext)`.

Offsets in `JSRuntime` (from gdb):
- `sab_free` @ `0x180`
- `sab_opaque` @ `0x190`

## `setcontext`-based ROP
We place a crafted `ucontext_t` in a normal ArrayBuffer backing store and point `sab_opaque` to it.

From glibc 2.41 `setcontext` disassembly (x86-64), it loads registers from fixed offsets (e.g. RIP from +0xa8, RSP from +0xa0, RDI/RSI/RDX from +0x68/+0x70/+0x88), then `ret` into the chosen RIP.

We set:
- RIP = `execve` (libc offset `0xdddd0`)
- RDI = ptr to "/bin/sh"
- RSI = ptr to argv array `["/bin/sh","-i",NULL]`
- RDX = ptr to envp array `[NULL]`
- RSP = controlled stack inside the same buffer

`setcontext` offset used: `0x453b0`.

## Trigger
We allocate a `SharedArrayBuffer` early and keep it alive. When the script ends, qjs tears down the runtime and runs finalizers. The SharedArrayBuffer finalizer calls our patched `sab_free`, transferring control to `setcontext`, and then to `execve("/bin/sh", …)`.

This spawns a shell which executes the verifier’s stdin commands.
