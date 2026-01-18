# QuickJS Atomics RAB Resize Exploit Analysis

## Vulnerability Overview

The vulnerability exists in QuickJS's handling of `Atomics` operations on TypedArrays backed by Resizable ArrayBuffers (RABs). The bug is a classic use-after-free triggered through JavaScript's `valueOf()` callback mechanism.

### Root Cause

In `js_atomics_op()` (quickjs.c:58725-58867) and `js_atomics_store()` (quickjs.c:58869-58920):

1. A raw pointer `ptr` to the buffer element is captured via `js_atomics_get_ptr()`
2. User JavaScript code is executed via `JS_ToUint32()` or `JS_ToBigInt64()` on the value argument
3. The `valueOf()` callback can resize the underlying ArrayBuffer
4. When resized, `js_realloc()` may free the old buffer and allocate a new one
5. Only the `detached` flag is checked after valueOf returns - not whether the buffer was resized
6. The stale pointer is then used for atomic operations

## Exploitation Strategy

### Step 1: Binary Base Leak

Using the UAF, we read from freed memory that gets reallocated as a JSArrayBuffer structure. The `free_func` field at offset 48 contains a pointer to `js_array_buffer_free`, giving us the binary base:

```javascript
let freeFunc = Atomics.add(victimView, 6, {valueOf: ...});
let binaryBase = freeFunc - 0x14bc0;
```

### Step 2: OOB Buffer Creation

By corrupting the `byte_length` field (offset 0) of a JSArrayBuffer structure, we create a buffer with artificially large length:

```javascript
Atomics.store(view, 0, {
    valueOf: function() {
        victim.resize(4096);
        // Spray ArrayBuffers
        return BigInt("0xFFFFFFFF7FFFFFFF"); // Sets byte_length to 0x7FFFFFFF
    }
});
```

This gives us Out-of-Bounds read/write capability within the heap.

### Step 3: libc Leak via GOT Read

Using OOB access, we find JSArrayBuffer structures and corrupt their `data` pointer to point to GOT[free]:

```javascript
oobView.setBigUint64(struct.dataOffset, gotFree, true);
```

Reading through the corrupted buffer's view gives us the libc `free` address:
- `libc_base = libc_free - 0xa3240`
- `system = libc_base + 0x53110`

### Step 4: GOT Overwrite

We overwrite GOT[free] with the address of `system`:

```javascript
gotWriter.setBigUint64(0, systemAddr, true);
```

### Step 5: Trigger Shell

Create a buffer containing "/bin/sh\0", then release it. When QuickJS frees the buffer, it calls:
- `free(buffer_data)` → `system(buffer_data)` → `system("/bin/sh")`

## Key Techniques

1. **JSArrayBuffer Structure Corruption**: The 56-byte JSArrayBuffer structure contains critical fields including `data` pointer, `opaque`, and `free_func`. Corrupting these gives powerful primitives.

2. **byte_length Inflation**: Setting `byte_length` to 0x7FFFFFFF creates a massive OOB read/write window into the heap.

3. **Heap Spray**: Spraying ArrayBuffers ensures predictable allocation patterns where JSArrayBuffer structures land at our UAF location.

4. **GOT Overwrite**: Classic technique - replacing `free` with `system` in the GOT causes subsequent frees to execute shells.

## Exploit Flow

```
1. UAF Leak #1 → Binary base (via free_func pointer)
2. UAF #2 → Create OOB buffer (corrupt byte_length)
3. OOB Read → Find JSArrayBuffer structures
4. OOB Write → Corrupt data pointer to GOT
5. GOT Read → libc address leak
6. GOT Write → Replace free with system
7. Trigger → Free buffer containing "/bin/sh" → Shell!
```

## Constraints Bypassed

- **ASLR**: Defeated via information leaks (binary base + libc base)
- **No direct /proc access**: All leaks done through heap manipulation
- **No os.exec()**: Code execution achieved through GOT corruption

## Files

- `poc.js` - Proof of concept exploit achieving shell execution
