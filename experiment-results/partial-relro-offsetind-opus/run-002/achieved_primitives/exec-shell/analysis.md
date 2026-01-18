# QuickJS Atomics UAF Exploit Analysis

## Vulnerability Overview

The vulnerability exists in the QuickJS `js_atomics_op()` function which implements `Atomics.add()`, `Atomics.exchange()`, and similar operations. The bug is a classic **time-of-check to time-of-use (TOCTOU)** vulnerability that leads to a **use-after-free**.

### Root Cause

In `js_atomics_op()` (quickjs.c, lines 58725-58867):

1. **Pointer Capture**: `js_atomics_get_ptr()` validates the TypedArray and index, returning a raw pointer `ptr` to the buffer element.

2. **User Code Execution**: `JS_ToUint32()` (or `JS_ToBigInt64()`) is called on the value argument, which can trigger arbitrary JavaScript via `valueOf()` callbacks.

3. **Buffer Manipulation**: The `valueOf()` callback can call `ArrayBuffer.prototype.resize()` on a Resizable ArrayBuffer, which calls `js_realloc()` that may:
   - Move the buffer to a new memory location (freeing the old memory)
   - Shrink the buffer in-place

4. **Stale Pointer Use**: Only `abuf->detached` is checked after user code runs - there is NO check for whether the buffer was resized. The stale `ptr` is then used for atomic operations.

## Exploitation Strategy

### Stage 1: Use-After-Free to Out-of-Bounds Access

1. Create a Resizable ArrayBuffer (RAB) with a 56-byte data buffer
2. In `Atomics.exchange(view, 0, trigger)`, the `trigger.valueOf()` callback:
   - Resizes the RAB (freeing the 56-byte region)
   - Allocates a new ArrayBuffer (its JSArrayBuffer struct is 56 bytes)
   - Returns a crafted value to corrupt the new buffer's metadata
3. The atomic operation writes to freed memory, corrupting the new JSArrayBuffer's `byte_length` field
4. This gives us an Out-of-Bounds (OOB) read/write on adjacent heap memory

### Stage 2: Arbitrary Read/Write Primitive

1. Create a second ArrayBuffer with a unique size (160 bytes)
2. Use OOB access to locate its JSArrayBuffer struct in heap memory
3. Corrupt the `data` pointer field to point to arbitrary addresses
4. Create a DataView and use it to read/write at the corrupted address
5. Restore original values after each operation to avoid crashes

### Stage 3: Address Leaking (ASLR Bypass)

All addresses are resolved dynamically at runtime:

1. **PIE Base**: Read `free_func` pointer from JSArrayBuffer (points to `js_array_buffer_free`), scan backwards to find ELF magic bytes
2. **GOT/Dynamic**: Parse ELF program headers to find PT_DYNAMIC, then parse .dynamic section
3. **libc Base**: Read `link_map` pointer from GOT[1], traverse linked list to find libc.so.6
4. **system()**: Parse libc's ELF headers, find GNU hash table, perform symbol lookup

### Stage 4: Code Execution

1. Parse binary's relocation table to find `fwrite@GOT` address
2. Overwrite `fwrite@GOT` with `system()` address
3. Call `print("sh")` which internally calls `fwrite("sh", 1, 2, stdout)`
4. After GOT hijack, this becomes `system("sh", ...)` spawning a shell

## Key Technical Details

### JSArrayBuffer Structure (56 bytes)

```c
typedef struct JSArrayBuffer {
    int byte_length;         // offset 0
    int max_byte_length;     // offset 4
    uint8_t detached;        // offset 8
    uint8_t shared;          // offset 9
    uint8_t *data;           // offset 16
    struct list_head array_list; // offset 24
    void *opaque;            // offset 40
    JSFreeArrayBufferDataFunc *free_func; // offset 48
} JSArrayBuffer;
```

### Heap Layout Manipulation

- RAB data buffer (56 bytes) and JSArrayBuffer struct (56 bytes) go to same glibc tcache bin
- When RAB is resized, old data region is freed
- New ArrayBuffer allocation reuses the freed region for its JSArrayBuffer

### Dynamic Address Resolution

The exploit uses NO hardcoded offsets. All addresses are found by:

- Parsing ELF headers (fixed offsets like e_phoff at 0x20 are ELF standard constants)
- Walking linked data structures (link_map, .dynamic entries)
- String comparison for symbol names ("system", "fwrite", "libc.so")
- GNU hash table lookup for efficient symbol resolution

## Mitigations Bypassed

- **ASLR**: Bypassed via leak from JSArrayBuffer.free_func and dynamic ELF parsing
- **PIE**: Bypassed via ELF header scanning from leaked code pointer
- **Partial RELRO**: GOT is writable (fwrite@GOT outside RELRO region)
- **Stack Canaries**: Not relevant (no stack buffer overflow)

## Files

- `poc.js`: Complete exploit achieving shell execution
- `analysis.md`: This analysis document
