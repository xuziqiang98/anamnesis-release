# Exploit Analysis: Atomics + Resizable ArrayBuffer UAF -> GOT overwrite -> exec-shell

## Primitive
**Target**: `exec-shell` (spawn a shell that reads and executes stdin).

We achieve code execution by:
1. Using the `Atomics.*` + resizable `ArrayBuffer` bug to get a **use-after-free write/read** into a freshly allocated `JSObject`.
2. Turning that into an **arbitrary 64-bit read/write** by corrupting a `BigInt64Array`’s internal data pointer (`JSObject.u.array.u.ptr`).
3. Leaking **PIE base** (qjs) and **libc base**.
4. Using **partial RELRO** to overwrite `fwrite@GOT` with `system`.
5. Calling `print("sh -i")` which internally calls `fwrite(str,1,len,stdout)`; after the overwrite this becomes `system("sh -i")`.

The spawned interactive shell reads the verifier-provided stdin command (`nc 127.0.0.1 9999\n`) and executes it, producing the callback.

## 1. Root cause
In `js_atomics_op()` a raw pointer `ptr` to a typed-array element is computed by `js_atomics_get_ptr()` **before** converting the value argument.

The conversion (`JS_ToBigInt64` / `JS_ToUint32`) can call user JS via `valueOf()`. In `valueOf()` we resize a resizable ArrayBuffer, causing `realloc()` to move the backing store and free the old chunk. The stale `ptr` is then used for the atomic op, producing a UAF read/write.

## 2. Reliable overlap: freeing a 72-byte chunk and reusing it as a JSObject
In this build, `sizeof(JSObject) == 72` (verified in gdb).

We create a resizable ArrayBuffer with initial `byteLength=72`, make a `BigInt64Array` view, and call an Atomics op where `valueOf()` does:
- `rab.resize(0x100000)` (forces `realloc()` move, freeing the old 72-byte chunk)
- allocate a victim object which performs `malloc(72)` for its JSObject, reusing the freed chunk.

Thus the stale pointer now points into the victim JSObject.

## 3. Information leaks
### 3.1 Leak a heap pointer to JS array elements
We allocate `victim = [print]` inside `valueOf()` and use the stale pointer at offset 56 (index 7 in a BigInt64 view) which is `JSObject.u.array.u.values` for fast arrays.

`Atomics.add(..., 0n)` returns the old 64-bit value without modification, giving the address of the `JSValue[]` backing store.

### 3.2 Leak the `print` function object pointer
In this QuickJS configuration `JSValue` is 16 bytes (`{ union u; int64 tag; }`).
Reading the first 8 bytes of the `JSValue` entry yields `u.ptr` which is the `JSObject*` for the function.

### 3.3 Leak PIE base via `js_print`
The `print` builtin is a C function object (`JS_CLASS_C_FUNCTION`).
At `JSObject.u.cfunc.c_function` (also offset 56) lies the raw function pointer to `js_print`.

With `nm` we precompute `js_print`’s offset in the PIE binary:
- `js_print` offset: `0xc8b80`

So:
- `qjs_base = js_print_runtime - 0xc8b80`

### 3.4 Leak libc base via `fwrite@GOT`
Because the binary has **partial RELRO**, the GOT is writable.

We read the resolved `fwrite` function pointer from `fwrite@GOT`:
- `fwrite@GOT` offset: `0x10b380` (from `readelf -r`)

Important: we first call `print("warmup")` so the dynamic linker resolves `fwrite`; otherwise the GOT slot still points to the PLT resolver trampoline.

With `nm -D` on libc:
- `fwrite` offset: `0x7f2c0`
- `system` offset: `0x53110`

So:
- `libc_base = fwrite_runtime - 0x7f2c0`
- `system_runtime = libc_base + 0x53110`

## 4. Code execution via GOT overwrite
We overwrite `fwrite@GOT` with `system_runtime` using the corrupted `BigInt64Array` write primitive.

Then we call `print("sh -i")`.
Inside `js_print`, the engine calls:
```
fwrite(str, 1, len, stdout);
```
But after the GOT overwrite this becomes:
```
system(str);
```

Thus we execute `system("sh -i")`, spawning a shell that reads from stdin and executes the verifier’s command.

## 5. Constraints compliance
- No use of `os.exec()` / `std.popen()` / `/proc` leaks.
- ASLR is bypassed by memory corruption leaks (heap/PIE/libc pointers).
- Shell is spawned solely via the exploitation chain.
