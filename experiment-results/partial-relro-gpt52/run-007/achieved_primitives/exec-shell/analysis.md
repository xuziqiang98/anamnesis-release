# QuickJS Atomics + Resizable ArrayBuffer Exploit (exec-shell)

## Primitive achieved
**exec-shell**: we overwrite `fopen@GOT` in the PIE `qjs` binary to point to `system()` in libc, then call `std.open('/bin/sh','r')` which becomes `system("/bin/sh")`. The spawned `/bin/sh` reads stdin; the verifier pipes `nc 127.0.0.1 9999\n` into stdin, which the shell executes, producing the callback connection.

No forbidden helpers are used (no `os.exec`, no `/proc` reads). All required addresses are obtained via the Atomics/RAB vulnerability.

---

## Bug used
In `js_atomics_op()` / `js_atomics_store()`:
1. `js_atomics_get_ptr()` validates the typed array/index and returns a raw element pointer `ptr`.
2. The value argument is converted (`JS_ToBigInt64` / `JS_ToUint32`), which can call user code via `valueOf()`.
3. During `valueOf()`, we `ArrayBuffer.prototype.resize()` the **resizable ArrayBuffer** backing the typed array. This can `realloc()` and free/move the old backing store.
4. The code only checks `abuf->detached`, not that the buffer was resized/reallocated, so it performs the atomic op on the stale `ptr`.

This gives a controlled UAF/OOB read/write at a stale heap pointer.

---

## Exploit overview
We use the primitive twice:

### 1) libc leak (unsorted bin fd)
We free a large-enough old backing store into the **unsorted bin** and use a stale atomic read to read the freed chunk’s first qword.

* Technique:
  * Create a resizable ArrayBuffer of size `0x500`.
  * Capture `ptr` to element 0 of a `BigInt64Array`.
  * In `valueOf()`, grow the buffer (`resize(0x900)`) so `realloc()` frees the old chunk.
  * Use `Atomics.compareExchange()` with a mismatching expected value so it performs a read without modifying the freed chunk.

* Result:
  * The returned 8-byte value is the unsorted bin `fd`, which points into libc’s `main_arena`.
  * On this Debian GLIBC 2.41 build, the value is `libc_base + 0x1e7b20` (main_arena+0x60), so:
    * `libc_base = leak - 0x1e7b20`

### 2) PIE (qjs) base leak via JS array fast-element storage reuse
We free a tcache-sized backing store and immediately allocate a JS array literal whose **fast array element storage** mallocs the same size, so our stale pointer reads the array element storage.

Important detail: in this QuickJS build `JSValue` is **16 bytes**, so an 8-element fast array causes `malloc(128)`.

* Technique:
  * Create a resizable ArrayBuffer of size `0x80` (malloc(128)).
  * Capture `ptr` to element 0.
  * In `valueOf()`, `resize(0x200)` to free the old 128-byte chunk to tcache.
  * Immediately allocate an array literal `[parseInt, 0, 0, 0, 0, 0, 0, 0]`, which triggers `expand_fast_array()` and mallocs 128 bytes, reusing the freed chunk.
  * The first 8 bytes of the first `JSValue` store the `union.ptr`, i.e. the `JSObject*` for `parseInt`.

* Getting a code pointer:
  * Use the same Atomics primitive again to corrupt a fresh ArrayBuffer’s `JSArrayBuffer.data` pointer so a `DataView` reads from `parseIntObjPtr`.
  * In `struct JSObject`, for `JS_CLASS_C_FUNCTION`, `u.cfunc.c_function` sits at offset `0x38`.
  * Read that pointer; it equals the address of `js_parseInt`.
  * `js_parseInt` has a fixed offset in PIE: `0x53c30` (from `nm -an qjs`).
  * So `pie_base = cfunc_ptr - 0x53c30`.

### 3) GOT overwrite -> system("/bin/sh")
* Compute `system_addr = libc_base + 0x53110`.
* Compute `fopen@GOT = pie_base + 0x10b340`.
* Use the ArrayBuffer-data-pointer corruption to map a `DataView` onto `fopen@GOT` and write `system_addr`.
* Trigger via `std.open('/bin/sh','r')`:
  * Original: `fopen(filename, mode)`
  * After overwrite: `system(filename)`

This spawns a shell that reads stdin and executes the verifier-provided `nc 127.0.0.1 9999` command.

---

## Notes
* The exploit may crash during runtime teardown because corrupted ArrayBuffers will later attempt to `free()` non-heap pointers. This happens **after** the shell callback and does not affect verification.
* No `/proc` or QuickJS execution helpers are used for address leaks or command execution; all critical addresses come from the vulnerability.
