# Exploit Analysis: Atomics + Resizable ArrayBuffer UAF -> CFI-safe exec-shell (CET)

## Target primitive
**exec-shell-cet-cfi**: spawn a shell which reads and executes stdin, under:
- Full RELRO
- Intel CET (shadow stack enabled)
- Clang CFI (forward-edge type checks)

The verifier pipes `"nc 127.0.0.1 9999\n"` to stdin. A real shell must execute that command.

## Vulnerability
In `js_atomics_op()` (and similarly `js_atomics_store()`), QuickJS:
1. Computes a raw element pointer `ptr` into a TypedArray’s backing store via `js_atomics_get_ptr()`.
2. Converts the value argument with `JS_ToBigInt64()` / `JS_ToUint32()`, which can execute JS user code via `valueOf()`.
3. Only checks `abuf->detached` afterwards, not whether the backing store moved due to `ArrayBuffer.prototype.resize()`.
4. Performs the atomic operation using the **stale** `ptr`.

If `resize()` grows the buffer, glibc `realloc()` often moves it, freeing the old chunk. The atomic op then becomes a UAF write/read into freed heap memory.

## Exploitation strategy (no ROP; CFI-compatible)
### Key observation: QuickJS uses autoinit properties for built-in methods
QuickJS installs many built-in prototype methods as **autoinit properties** (`JS_DefineAutoInitProperty`).
On first access, the engine allocates a fresh `JSObject` of class `JS_CLASS_C_FUNCTION` for that method.

### Use-after-free target: the freshly instantiated `Array.prototype.concat` function object
We:
1. Create a resizable ArrayBuffer (RAB) of size `0x40` and a `BigInt64Array` view.
2. Call `Atomics.add(ta, 7, malicious)`.
   - Index 7 means the stale pointer will target offset `7*8 = 56` bytes from the base of the freed chunk.
3. In `malicious.valueOf()`:
   - Grow the RAB (`rab.resize(0x4000)`) so `realloc()` moves it and **frees** the original `0x40` chunk.
   - Immediately access `arr.concat` *for the first time*.
     This triggers autoinit and allocates the `concat` C-function object, which reuses the just-freed chunk.
4. After `valueOf()` returns, `js_atomics_op()` performs `atomic_fetch_add()` using the stale pointer.
   That pointer now overlaps the new `JSObject` for `concat`.

### CFI-safe control-flow hijack
`Array.prototype.concat` is a normal `JS_CFUNC_DEF` entry, i.e. it uses the **generic JSCFunction signature**:

```c
JSValue (*)(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv)
```

We retarget its `u.cfunc.c_function.generic` pointer to `js_os_exec`.
This is **CFI-safe** because `js_os_exec` has the same JSCFunction type.
No return-address corruption occurs, so Intel CET shadow stack is not violated.

## Avoiding ASLR without leaks
We do not need a runtime address leak.
The exploit uses a **PIE-relative pointer add**:

- `js_array_concat` stub symbol offset: `0x10ab30`
- `js_os_exec` stub symbol offset: `0x10b900`
- delta: `0xdd0`

Because both functions reside in the same PIE, their difference is constant even under ASLR.
The atomic primitive performs:

```
concat_cfunc_ptr += 0xdd0
```

turning `js_array_concat` into `js_os_exec`.

## Shell spawn
After the overwrite, calling the corrupted `concat` function actually calls `js_os_exec`:

```js
hijacked(["/bin/sh"], { block: false, usePath: false });
```

This forks and execs `/bin/sh`, inheriting stdin.
The verifier’s piped command (`nc 127.0.0.1 9999`) is read and executed by the shell, producing the required callback.

## Why mitigations don’t stop this
- **Full RELRO**: no GOT overwrite is used.
- **CET shadow stack**: no ROP/return address hijack; only a forward-edge function pointer retarget.
- **Clang CFI**: we redirect a JSCFunction pointer to another JSCFunction with matching signature.

