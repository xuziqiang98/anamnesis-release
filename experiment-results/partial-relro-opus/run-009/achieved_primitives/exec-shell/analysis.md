# QuickJS Atomics UAF Exploit Analysis

## Vulnerability Summary

The vulnerability exists in QuickJS's Atomics operations (`js_atomics_op` and `js_atomics_store`) when used with Resizable ArrayBuffers (RAB). A pointer to the buffer element is captured before the `valueOf()` callback is invoked on the operand. If `valueOf()` resizes the buffer, the captured pointer becomes stale (use-after-free).

**Affected Code:** `quickjs.c`, function `js_atomics_op()` around line 58725

```c
ptr = js_atomics_get_ptr(ctx, abuf, &size_log2, NULL, this_val, argv[0], 2);
// ... ptr is now captured ...
if (JS_ToBigInt64(ctx, &v, argv[1]))  // valueOf() called here - may resize buffer!
    return JS_EXCEPTION;
// ... ptr is now stale if buffer was resized ...
```

## Exploitation Strategy

### 1. Information Leaks

**PIE Base Leak:**
- Allocate a 56-byte resizable ArrayBuffer (same size as JSArrayBuffer struct)
- Trigger UAF by resizing in `valueOf()`
- Read from offset 6 (48 bytes) which overlaps with `free_func` pointer in a reused JSArrayBuffer struct
- Subtract known offset `0x14bc0` to get PIE base

**Libc Base Leak:**
- Allocate a large (0x500 byte) resizable ArrayBuffer
- Trigger UAF - the freed chunk goes to unsorted bin
- Read the `fd` pointer which contains `main_arena` address
- Subtract offset `0x1e7b20` to get libc base

### 2. Arbitrary Read/Write Primitive

The key insight is that writing at offset 2 (16 bytes) of a 56-byte victim buffer can corrupt the `uint64_ptr` field of a BigUint64Array TypedArray. This happens because:

1. The 56-byte data chunk is freed during resize
2. A new ArrayBuffer(56) is allocated - its data reuses the freed chunk
3. Creating a BigUint64Array on this new buffer allocates a TypedArray JSObject
4. The stale pointer write corrupts a field that ends up being the TypedArray's data pointer

By writing a target address (e.g., fwrite@GOT) instead of regular data, the TypedArray's `uint64_ptr` becomes corrupted to point to that address. Subsequent reads/writes through the TypedArray operate on the GOT entry.

### 3. Code Execution

**GOT Overwrite:**
- Corrupt TypedArray's `uint64_ptr` to point to `fwrite@GOT`
- Read original fwrite address (libc function pointer)
- Overwrite with `system()` address

**Trigger Shell:**
- Call `print("/bin/sh")`
- QuickJS's print internally calls `fwrite(str, 1, len, stdout)`
- After GOT overwrite: `fwrite("/bin/sh", ...)` → `system("/bin/sh")`
- Shell is spawned!

## Key Offsets

| Symbol | Offset from Base |
|--------|-----------------|
| `js_array_buffer_free` (PIE) | 0x14bc0 |
| Libc main_arena | 0x1e7b20 |
| `fwrite@GOT` (PIE) | 0x10b380 |
| `system()` (libc) | 0x53110 |

## Exploit Flow

```
1. leak_pie()  → Get PIE base from free_func pointer
2. leak_libc() → Get libc base from unsorted bin fd
3. Corrupt TypedArray to point to fwrite@GOT
4. Overwrite fwrite@GOT with system
5. print("/bin/sh") → system("/bin/sh") → Shell!
```

## Mitigations Bypassed

- **ASLR**: Bypassed via information leaks
- **PIE**: Bypassed via PIE base leak
- **Safe Linking**: Not needed - we use struct corruption, not tcache poisoning
- **NX/DEP**: Not needed - we use code reuse (GOT overwrite)

## Files

- `/tmp/work/poc.js` - Working exploit that spawns shell
- `/tmp/work/analysis.md` - This analysis document
