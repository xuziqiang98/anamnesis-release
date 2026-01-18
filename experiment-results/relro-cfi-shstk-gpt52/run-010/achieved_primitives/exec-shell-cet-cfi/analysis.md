# QuickJS Atomics + RAB stale pointer → exec-shell-cet-cfi

## Target / Constraints
- **Primitive**: `exec-shell-cet-cfi` (Full RELRO + Intel CET shadow stack + Clang CFI)
- **No ROP** (shadow stack) and no GOT overwrite (Full RELRO).
- Need a shell that reads stdin; verifier pipes: `nc 127.0.0.1 9999`.

## Bug
`js_atomics_op()` captures a raw element pointer `ptr` via `js_atomics_get_ptr()` and then calls `JS_ToUint32/JS_ToBigInt64` on user-controlled values. The coercion can run user JS (`valueOf()`), where we **shrink a resizable ArrayBuffer**, reallocating/splitting its backing store. After returning, `js_atomics_op()` uses the stale `ptr` for the atomic operation → **OOB/UAF read+write**.

## Key heap layouts (glibc)
We use two resize targets to create predictable remainder chunk sizes:

### Layout A (0x50 remainder → `JSArrayBuffer` struct)
- Initial RAB byteLength `L1 = 0x418`
- Shrink to `L2 = 0x3d0`
- glibc `realloc` shrink splits off a **0x50** remainder chunk, which is then reused by `malloc(56)` for a new `JSArrayBuffer` struct.
- Using a `BigUint64Array` view on the RAB, an OOB atomic at a computed index reads `JSArrayBuffer.free_func`, which points to `js_array_buffer_free` → **leak qjs PIE base**.

### Layout B (0x60 remainder → `JSObject` for TypedArray)
- Initial RAB byteLength `L1 = 0x418`
- Shrink to `L2 = 0x3c0`
- This produces a **0x60** remainder chunk, which is reused by `malloc(72)` for a `JSObject`.
- We allocate `new Uint8Array(backing)` inside `valueOf()` so its `JSObject` lands in that remainder.
- We then use the stale-pointer atomic write to overwrite **`JSObject.u.array.u.ptr`** (offset `0x38` in `struct JSObject`, derived from the source layout where `JSGCObjectHeader` is 0x18 bytes and union `u` begins at 0x30).
- Result: a `Uint8Array` that reads/writes **arbitrary memory** without crashing during cleanup (TypedArray finalizers do **not** free `u.ptr`).

## Bypassing CET + CFI: libc atexit pointer mangling
Direct icall hijacks in QuickJS are constrained by Clang CFI, and return-address hijacks are blocked by CET.

Instead we hijack **libc’s `__exit_funcs`** list:
- libc stores exit handlers in `struct exit_function_list`.
- Function pointers in this list are protected by **PTR_MANGLE**: `mangled = rol(ptr ^ guard, 17)` where `guard` is from TLS (`fs:0x30`).

### Recovering the pointer guard
Even in minimal qjs, libc registers one atexit handler in `__libc_start_main`: the loader’s `rtld_fini` (passed in `%rdx` from ld-linux).

We obtain the **unmangled** `rtld_fini` address as:
- Find ld-linux base via the `r_debug` / `link_map` chain (from `DT_DEBUG` in qjs `.dynamic`).
- In ld-linux entry stub, `%rdx` is set with `lea rdx, [rip + disp]` to `_dl_fini`. Disassembly shows `_dl_fini` is at offset **0x5380** in this environment.
- So `rtld_fini = ld_base + 0x5380`.

We read `mangled_rtld_fini` from `__exit_funcs[0].fn` and compute:
- `guard = ror(mangled_rtld_fini, 17) ^ rtld_fini`.

### Patching exit handler to `system("/bin/sh")`
- Compute `system = libc_base + 0x58750`.
- Use libc’s built-in `"/bin/sh"` string at `libc_base + 0x1cb42f`.
- Compute `mangled_system = rol(system ^ guard, 17)`.
- Overwrite `__exit_funcs[0].fn = mangled_system` and `__exit_funcs[0].arg = "/bin/sh"`.

When qjs exits normally, libc runs the patched atexit handler, invoking:
- `system("/bin/sh")`

The spawned shell reads stdin and executes the verifier’s command, producing the callback.

## Files
- PoC: `/tmp/work/poc.js`

## Why this meets the primitive
- Spawns `/bin/sh` (via libc `system`) and the shell **reads stdin** (verifier’s `nc 127.0.0.1 9999`).
- No GOT writes, no ROP, no `/proc` reads, no QuickJS `os.exec`/`std.popen`.
- Works under CET shadow stack and Clang CFI by using libc’s exit handler machinery.
