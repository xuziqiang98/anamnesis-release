# QuickJS Atomics(RAB) stale-pointer exploit -> exec-shell-cet-cfi

## Target / mitigations

Binary: `qjs` built with:
- **Full RELRO** (GOT read-only)
- **Intel CET** (**IBT + Shadow Stack**) enabled by verifier
- **Clang CFI** (fine-grained forward-edge checks on indirect calls)

Goal: spawn a shell that reads and executes verifier-provided stdin (`nc 127.0.0.1 9999`).

## Bug primitive

In `js_atomics_store()` / `js_atomics_op()` the engine:
1. Validates the typed array + index and **captures a raw element pointer** `ptr`.
2. Converts the `value` argument via `JS_ToIntegerFree` / `JS_ToBigIntFree`, which can run user JS (`valueOf`).
3. Only checks `abuf->detached` (no check for resize/realloc).
4. Performs the atomic store using the **stale `ptr`**.

With a resizable ArrayBuffer (RAB), `ab.resize(new_len)` calls `realloc()` and may move/free the old backing store. If we allocate another object of the same malloc sizeclass inside `valueOf`, the stale atomic store becomes a **use-after-free write** into that newly allocated object.

## Key heap/grooming detail: sizeclass selection

`Atomics.store` writes into the freed **RAB data** chunk.
To overwrite a `JSObject` (72 bytes) we must ensure the freed RAB-data chunk is in the **same glibc sizeclass** as `malloc(72)`.

In this build, choosing `new ArrayBuffer(72, {maxByteLength: ...})` makes the backing-store allocation request `malloc(72)`, matching the `JSObject` sizeclass. Using e.g. 80 bytes does **not** reliably reuse the same sizeclass (glibc rounds differently).

## Stage 1: OOB read via `u.array.count` corruption

We trigger a stale 4-byte store (Int32 Atomics) to overwrite `JSObject.u.array.count`:
- Create trigger RAB of length **72**.
- Call `Atomics.store(Int32Array(trigger_ab), 16, evil)`.
  - Index `16` -> stale pointer offset `16*4 = 0x40`.
  - In `JSObject`, `u.array.count` is at offset **0x40**.
- In `evil.valueOf()`:
  - `trigger_ab.resize(0x500)` forces `realloc` and frees old 72-byte chunk
  - allocate victim `Uint32Array` so its `JSObject` reuses the freed chunk

Result: victim typed array becomes a **fast-array with corrupted count**, giving OOB reads over subsequent heap memory.

## Stage 2: leak a stable heap object pointer (Atomics.store function object)

We allocate a `JSBoundFunction` using:

```js
bf = Atomics.store.bind(Atomics, ARG1, ARG2);
```

Because `JSValue` is 16 bytes in this build (`{ union u; int64 tag; }`), the `JSBoundFunction` struct contains distinctive patterns:
- `func_obj.tag == JS_TAG_OBJECT == -1` (`0xffffffffffffffff`)
- `this_val.tag == -1`
- `argc == 2`
- `argv[0].u.int32 == ARG1`, `argv[0].tag == 0`
- `argv[1].u.int32 == ARG2`, `argv[1].tag == 0`

We use the OOB `Uint32Array` to scan nearby heap memory for this layout and recover:
- `func_obj.u.ptr` which is the heap pointer to the existing `Atomics.store` **JS function object** (`JSObject*`).

## Stage 3: arbitrary read/write by corrupting `u.array.u.ptr`

We trigger a stale 8-byte store (BigInt Atomics) to overwrite `JSObject.u.array.u.ptr`:
- Call `Atomics.store(BigInt64Array(trigger_ab), 7, evil)`
  - Index `7` -> stale pointer offset `7*8 = 0x38`.
  - In `JSObject`, `u.array.u.ptr` is at offset **0x38**.

In `evil.valueOf()` we again resize the trigger RAB (freeing the 72-byte chunk) and allocate a `BigUint64Array` victim whose JSObject reuses it. The atomic store writes an arbitrary pointer value into `u.ptr`.

This yields a typed array that performs element access at attacker-chosen addresses: an **arbitrary qword read/write** primitive.

## Stage 4: CET/CFI-friendly control flow hijack

### Leak qjs PIE base
Using the arbitrary read, we read from the `Atomics.store` function object at offset `+0x38`:
- `JSObject.u.cfunc.c_function` (a function pointer)

For `Atomics.store`, this points to `js_atomics_store` inside the PIE binary. Using the known symbol offset (from `nm`):
- `js_atomics_store` offset = `0x10ad50`

we compute:
- `qjs_base = leaked_js_atomics_store - 0x10ad50`.

### Overwrite Atomics.store -> js_os_exec
We then overwrite `Atomics.store`’s `c_function` pointer to point to `js_os_exec` (also in the same binary):
- `js_os_exec` offset = `0x10b900`
- `js_os_exec_addr = qjs_base + 0x10b900`

Finally:
```js
Atomics.store(["/bin/sh"], { block: true });
```

This works under mitigations because:
- **No ROP / no returns are corrupted** → **Shadow Stack** is satisfied.
- The call is a normal C call from the JS engine.
- **IBT** is satisfied since `js_os_exec` is a real function entry compiled with `endbr64`.
- **Clang CFI** is satisfied because the indirect call site expects a `JSCFunction`-typed pointer and `js_os_exec` has the same signature.

## Result

`js_os_exec(["/bin/sh"], {block:true})` spawns a shell inheriting stdin/stdout. The verifier pipes `nc 127.0.0.1 9999` into stdin, which the shell executes, producing the required callback.

File: `/tmp/work/poc.js`.
