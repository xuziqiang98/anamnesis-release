# Exploit analysis (exec-shell-cet-cfi)

## Vulnerability used
The bug is in `js_atomics_store()` / `js_atomics_op()`:

* `js_atomics_get_ptr()` computes a raw element pointer `ptr` for a TypedArray element.
* Then `JS_ToBigInt*` / `JS_ToUint32` converts the value argument, which can run user JS via `valueOf()`.
* Inside `valueOf()` we resize the Resizable ArrayBuffer (RAB), causing `realloc()` to move/free the old backing store.
* After the conversion, QuickJS **does not re-validate that the RAB was resized**, and it performs the atomic operation using the stale `ptr`.

That gives a controlled write (and with `compareExchange`, a read) to memory that is no longer the RAB backing store.

## High-level exploitation strategy
We avoid ROP entirely (CET SHSTK blocks it) and avoid calling non-CFI libc targets directly (Clang CFI blocks indirect calls to libc).

Instead we:

1. **Heap corruption primitive**: Use the stale-pointer write to corrupt a TypedArray **JSObject** field.
2. **Memory disclosure**: Use an OOB TypedArray to read heap memory and leak a `JSObject *` pointer.
3. **CFI-safe control-flow hijack**: Overwrite a QuickJS C function pointer (`JSObject.u.cfunc.c_function`) from `js_os_open` to `js_os_exec`. Both are valid QuickJS `JSCFunction`-typed entrypoints, so CFI allows the indirect call.
4. Call `os.open(["sh"])`, which after patching actually executes `js_os_exec(["sh"])` and spawns `/bin/sh` reading stdin.

The verifier pipes `nc 127.0.0.1 9999` into stdin, so `sh` executes it and triggers the callback.

## Step-by-step

### 1) Create an out-of-bounds BigUint64Array
We allocate a non-resizable `victim_ab` and later create `oob = new BigUint64Array(victim_ab)`.

Using the Atomics/RAB bug we overlap the **72-byte freed backing store chunk** with the **72-byte `JSObject` allocation** for `oob`.

We then overwrite `JSObject.u.array.count` (the bounds used by typed array element access) at offset **64**:

* `BigUint64Array` element size is 8 bytes
* offset 64 corresponds to index `8`

After this, `oob[i]` allows OOB reads/writes past the end of `victim_ab`.

### 2) Leak the `JSObject *` pointer for `os.open`
We `await import('os')` (no `--std` flag needed).

We then allocate a **large** JS Array (`holder = new Array(0x1000)`) and store a recognizable pattern:

* `holder[0] = 0x41414141`
* `holder[1] = os.open`
* `holder[2] = 0x42424242`

In QuickJS `JSValue` is 16 bytes (`{ union u; int64 tag; }`).
For an object value, `tag == JS_TAG_OBJECT == -1`, so the memory representation is:

* qword0: `JSObject *`
* qword1: `0xffffffffffffffff`

We use the OOB read to scan heap memory for:

```
[0x41414141, tag=0][ptr, tag=-1][0x42424242, tag=0]
```

This yields the raw `JSObject *` pointer for `os.open`.

### 3) Build a targeted arbitrary read/write for `os.open->c_function` and patch it
We create a second typed array `rw = new BigUint64Array(rw_ab)`.

Using the Atomics/RAB bug a second time, we overwrite **the data pointer** inside the `rw` typed array JSObject (`JSObject.u.array.u.ptr`) at offset **56** (index `7`) so that:

* `rw.u.ptr = (os_open_obj + 56)`

`os_open_obj + 56` is exactly the `JSObject.u.cfunc.c_function` slot for a C function object.

Now:

* `rw[0]` reads the current function pointer (leak)
* `rw[0] = ...` overwrites it (write)

We read the original pointer (`js_os_open` or `js_os_open.cfi`), compute the PIE base (`qjs_base`), and write back:

* `js_os_exec` or `js_os_exec.cfi`

### 4) Spawn the shell
Finally we call:

```js
os.open(["sh"]);
```

After patching, this performs an indirect call to `js_os_exec(["sh"])`, which forks and execs `sh`.
The shell reads stdin (provided by the verifier) and executes `nc 127.0.0.1 9999`, producing the required callback.

## Why CET SHSTK + CFI + Full RELRO do not stop this

* **Full RELRO**: no GOT overwrite is used.
* **Intel CET shadow stack**: we never corrupt return addresses; only data pointers and a C function pointer inside a `JSObject`.
* **Clang CFI**: we redirect a `JSCFunction` call to another valid `JSCFunction`-typed target within the same binary (`js_os_open` -> `js_os_exec`). This passes forward-edge type checks.
