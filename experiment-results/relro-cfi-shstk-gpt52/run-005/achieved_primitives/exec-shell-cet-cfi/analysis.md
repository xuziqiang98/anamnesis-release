# QuickJS Atomics + ResizableArrayBuffer stale pointer -> exec-shell-cet-cfi

## Target / mitigations

* **Full RELRO**: no GOT overwrite.
* **Intel CET SHSTK**: classic ROP is blocked.
* **Clang CFI**: forward-edge type checks block many function-pointer overwrites inside **qjs**.

Therefore we need a control-flow transfer that:

1. Does not rely on ROP/stack corruption
2. Happens through existing control flow
3. Uses a call-site not protected by Clang CFI (e.g. inside libc)

We achieve that by overwriting **glibc’s atexit handler list** (`__exit_funcs`) so that process exit calls `system("exec /bin/sh -s")`.

## Vulnerability

In `js_atomics_op/js_atomics_store`, QuickJS computes an element pointer `ptr` for a TypedArray backed by a **Resizable ArrayBuffer** (RAB), then coerces a JS argument (`valueOf`), and finally uses the stale `ptr` for the atomic operation.

Inside `valueOf`, we can call `ArrayBuffer.prototype.resize()` to trigger `realloc()` on the RAB backing store. If the reallocation **moves** the buffer, the old backing store becomes **freed**, while `ptr` still points into it: a UAF write/read.

## Step 1 — libc base leak (no /proc)

We shrink a large RAB so that the tail remainder chunk is freed into the **unsorted bin**. With the stale pointer read primitive (`Atomics.compareExchange`) we read the freed chunk’s `fd`, which is `main_arena+96`.

With a known constant offset for this glibc build:

* `libc_base = fd - 0x203b20`

## Step 2 — stable arbitrary read/write primitive

Goal: obtain a JS object that can read/write arbitrary addresses.

QuickJS stores the data pointer for (typed arrays / fast arrays) inside the JSObject union:

* `JSObject.u.array.u.ptr` (8-byte pointer)

We corrupt this pointer for a `Uint8Array` object.

### Key trick

We force `realloc()` to **move** the RAB backing store:

* Create RAB of size `0x450` with `maxByteLength=0x8000`
* Allocate a large barrier `ArrayBuffer(0x6000)` right after it to prevent in-place growth
* Use the Atomics bug with `Atomics.store()`:
  * stale `ptr` targets `old_base + 0x38` (TypedArray index **7**)
  * `valueOf()` grows the RAB to `0x4000`, freeing the old `0x450` chunk
  * in the same `valueOf()`, allocate `view = new Uint8Array(backing)`

We first drain the malloc(72) tcache bin by allocating many plain objects and keeping them alive. That makes the next `malloc(72)` for the `Uint8Array`’s JSObject come from splitting the just-freed chunk, so our stale write overlaps the correct object.

Then the atomic store overwrites `JSObject.u.array.u.ptr` with an attacker-chosen `base` address.

Result: a `{base, u8}` pair where `u8[i]` accesses memory at `base+i`, giving arbitrary read/write.

## Step 3 — get glibc pointer guard (needed for mangled exit handlers)

glibc mangles atexit function pointers with a per-process pointer guard (`PTR_MANGLE`).

We recover it from `AT_RANDOM` in the initial stack auxv:

1. Read `environ` from libc (`libc_base + 0x20ad58`) to get `envp`.
2. Use the arbitrary read primitive to read the stack at `envp`, walk to the NULL terminator, then parse auxv entries until type `AT_RANDOM (25)`.
3. The pointer guard is the **second** QWORD at `AT_RANDOM` (first is stack canary):

`guard = *(uint64_t*)(rand_ptr + 8)`

## Step 4 — overwrite exit handler list to call system()

We overwrite the head `struct exit_function_list` with a single entry of flavor `ef_cxa`:

* `next = NULL`
* `idx = 1`
* `fns[0].flavor = 4` (ef_cxa)
* `fns[0].func.cxa.fn = PTR_MANGLE(system)`
* `fns[0].func.cxa.arg = cmd_ptr`

Pointer mangling used:

`mangled = rol64(system ^ guard, 17)`

We obtain the list head pointer from a fixed offset in libc for this build:

* `exit_head = *(uint64_t*)(libc_base + 0x203680)`

(Offset determined offline by observing which libc .data pointer changes when registering an `atexit()` handler.)

## Step 5 — command string placement

We overwrite an existing environment string (not `PATH=`) in-place on the stack to contain:

`exec /bin/sh -s\0`

Then we set `cmd_ptr` to that string address.

When `system()` runs, it spawns `/bin/sh -c "exec /bin/sh -s"` and replaces the `sh -c` with an interactive `/bin/sh -s` that reads commands from stdin.

## Why this bypasses CET/CFI/RELRO

* No ROP or stack smashing: **CET shadow stack** remains intact.
* No GOT overwrite: **Full RELRO** irrelevant.
* The hijacked indirect call is inside **glibc’s exit handler logic**, not in QuickJS, so **Clang CFI in qjs** does not type-check the call.

## Verification

The verifier pipes `nc 127.0.0.1 9999` into stdin. The spawned shell executes it, connecting back and producing `[ShellVerify] SUCCESS`.
