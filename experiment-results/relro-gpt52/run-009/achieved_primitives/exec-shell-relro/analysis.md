# Exploit Analysis: Atomics + Resizable ArrayBuffer (Full RELRO) -> exec-shell

## Bug primitive

`js_atomics_op()` / `js_atomics_store()` capture a raw element pointer (`ptr`) via `js_atomics_get_ptr()` **before** converting the value argument. Value conversion (`JS_ToBigInt64`/`JS_ToUint32`) can execute attacker JS via `valueOf()`. During `valueOf()` we resize a resizable ArrayBuffer (RAB), so the previously validated `ptr` becomes stale:

- **in-place shrink**: `ptr` now points into the freed tail chunk (OOB)
- **move**: `ptr` points into freed memory (UAF)

The atomic operation then dereferences `ptr` without re-validating the resized length.

## High-level exploitation strategy

We use the stale `ptr` write to corrupt a `BigUint64Array` JSObject allocated inside the freed tail chunk, specifically overwriting `JSObject.u.array.u.ptr` (offset `0x38`).

Because the TypedArray is **length-tracking on a resizable ArrayBuffer** (`track_rab = true`), `typed_array_is_oob()` returns false and the engine does not re-check that `u.ptr` matches the backing buffer. The result is a powerful primitive:

- A `BigUint64Array` whose element access performs arbitrary 8-byte reads/writes at attacker-chosen addresses.

## Stage 1: libc base without /proc

We need libc addresses for `swapcontext` and `execve`.

1. Leak a “high” pointer (0x7f...) using the stale `ptr` read (Atomics `compareExchange` with mismatched expected value so it does not modify memory).
2. Create a corrupted scanner TypedArray pointing near that pointer and scan downward for an ELF header (`0x7f454c46`).
3. Validate the candidate base is **libc** by checking the first 8 bytes at `base + off(execve)` match the known `execve` prologue bytes for this libc build.

This avoids forbidden `/proc` leaks.

## Stage 2: locate the target ArrayBuffer metadata on the heap

1. Leak a heap anchor using safe-linking: create a tcache chunk whose `next` is NULL; the stored value is `chunk_addr >> 12`.
2. Corrupt another `BigUint64Array` into a heap scanner (`u.ptr = heap_anchor`).
3. Allocate the target `ArrayBuffer ropAb` and place a unique 64-bit marker at the start of its data.
4. Scan forward from the heap anchor to find:
   - `ropAb` **data pointer** (marker location)
   - `JSArrayBuffer` struct containing that data pointer (verify `byte_length` and `max_byte_length` fields)

## Stage 3: control-flow hijack (Full RELRO safe)

QuickJS `JSArrayBuffer` has:

- `opaque` (offset `0x28`)
- `free_func` callback pointer (offset `0x30`)

When an ArrayBuffer is freed/finalized, QuickJS calls:

```
free_func(rt, opaque, data_ptr)
```

We overwrite:

- `free_func = libc.swapcontext`
- `opaque = pointer_to_attacker_ucontext`

Extra args are ignored by `swapcontext`, so the call effectively becomes:

```
swapcontext(rt, ucontext)
```

This is perfect because we fully control the second argument.

## Stage 4: shell spawn

We build a valid `ucontext_t` inside `ropAb`’s data, setting the saved registers to:

- `RIP = execve`
- `RDI = "/bin/sh"` pointer (stored in `ropAb`)
- `RSI = argv` pointer (stored in `ropAb`)
- `RDX = NULL`
- `RSP =` stack inside `ropAb`
- `fpregs` pointer set to the embedded `__fpregs_mem` area

Then we drop references and force GC. Finalization calls `swapcontext`, which loads our context and jumps directly into `execve("/bin/sh", ["/bin/sh", NULL], NULL)`.

This yields an interactive `/bin/sh` reading stdin; the verifier’s `nc 127.0.0.1 9999` command is executed, producing the callback.

## Why Full RELRO doesn’t matter

We do not touch the GOT. We hijack a heap-resident function pointer (`JSArrayBuffer.free_func`) and use libc addresses obtained via memory disclosure.

## Constraints compliance

- No one_gadget
- No `os.exec`, `std.popen`, or `/proc`/`/sys` address leaks
- Code execution is achieved solely via the reported Atomics+RAB UAF/OOB vulnerability
