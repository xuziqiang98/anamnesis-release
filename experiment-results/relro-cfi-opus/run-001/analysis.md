# QuickJS Atomics Heap Buffer Overflow Exploit Analysis

## Vulnerability Summary

The vulnerability exists in QuickJS's `Atomics` operations (`js_atomics_op()` and `js_atomics_store()`) when operating on TypedArrays backed by resizable ArrayBuffers (RAB). A pointer to the buffer element is captured before user code execution via `valueOf()`, and this stale pointer is later used even after the underlying buffer has been resized and potentially reallocated.

### Root Cause

In `js_atomics_op()`:
1. Line 58736-58738: `js_atomics_get_ptr()` captures `ptr` pointing to the buffer element
2. Line 58755: `JS_ToUint32()` is called, which can execute user code via `valueOf()`
3. The `valueOf()` callback can call `ArrayBuffer.resize()` which uses `js_realloc()`, potentially moving the buffer to a new location and freeing the old memory
4. Line 58764: Only `abuf->detached` is checked, NOT if the buffer was resized
5. Lines 58772+: The stale `ptr` is used for atomic operations

## Exploitation Strategy

### 1. Trigger Heap Corruption (byte_length corruption)

Create a resizable ArrayBuffer with 56-byte data (matching JSArrayBuffer struct size). During the Atomics operation:
- The stale pointer points to the freed 56-byte region
- A new ArrayBuffer is allocated, and its JSArrayBuffer struct (56 bytes) lands in the freed space
- The atomic operation writes to the stale pointer, corrupting `byte_length`

### 2. OOB Access

After corrupting `byte_length` from 64 to 0x100000, create a new BigUint64Array view on the corrupted ArrayBuffer. This provides read/write access to ~1MB of adjacent heap memory.

### 3. Arbitrary Read/Write Primitive

Key insight: TypedArrays have their own internal pointer (`u.array.ptr`) separate from `JSArrayBuffer.data`. The TypedArray caches the data pointer in its own structure.

Steps:
1. Spray ArrayBuffers with marker values
2. Scan OOB region to find JSArrayBuffer structures
3. Find the corresponding TypedArray's `u.array.ptr` (appears twice in memory - once in JSArrayBuffer.data and once in JSObject.u.array.ptr)
4. Corrupt the TypedArray's internal pointer to redirect reads/writes

### 4. Leak libc Base

Resize a large ArrayBuffer (>0x410 bytes) to move it. The freed chunk goes to the unsorted bin, and its `fd` pointer points to `main_arena + 0x60`. Read this via the Atomics vulnerability to get a libc leak.

```
libc_base = leak - 0x60 - MAIN_ARENA_OFFSET
```

### 5. Leak Stack Address

Use the arbitrary read primitive to read the `environ` variable from libc, which points to the environment variables on the stack.

### 6. CFI Bypass via Stack ROP

Since Clang CFI only protects forward edges (indirect calls), not backward edges (returns), we can still use ROP. Write a simple ROP chain to the stack:

```
ret              ; stack alignment
pop rdi; ret
"/bin/sh"
system
```

Target the return address from `__libc_start_call_main`, which is executed when `main()` returns.

## Key Offsets (glibc 2.41)

| Symbol | Offset |
|--------|--------|
| main_arena | 0x1e7ac0 |
| system | 0x53110 |
| /bin/sh | 0x1a7ea4 |
| pop rdi; ret | 0x2a145 |
| ret | 0x2846b |
| environ | 0x1eee28 |

## Protections Bypassed

1. **Full RELRO**: GOT is read-only, so we use stack-based ROP instead of GOT overwrite
2. **Clang CFI**: Only protects forward edges; backward-edge (return) control flow hijacking via ROP still works
3. **ASLR**: Bypassed via libc and stack leaks through arbitrary read primitive
4. **PIE**: Not directly relevant since we use libc gadgets
5. **NX**: Data execution prevention bypassed via ROP

## Reliability

The exploit is highly reliable because:
1. Heap spray ensures predictable layout
2. OOB access is large (1MB) providing flexibility
3. Multiple spray buffers increase chance of finding a controllable target
4. Return address targeting is consistent across runs

## Conclusion

The vulnerability allows arbitrary read/write primitive construction through careful heap manipulation. Despite Full RELRO and CFI protections, ROP-based code execution is achievable by targeting return addresses on the stack, which Clang CFI does not protect.
