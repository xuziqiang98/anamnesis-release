# Analysis of QuickJS Heap Buffer Overflow Exploitation

## Vulnerability Summary

The vulnerability exists in QuickJS's `Atomics` operations when used with resizable ArrayBuffers (RAB). The core issue is that a raw pointer to buffer memory is captured before user-controlled code execution (via `valueOf` callbacks), and this stale pointer is used after the buffer may have been resized or freed.

## Key Technical Details

1. **Vulnerable Functions**: `js_atomics_op()` and `js_atomics_store()` in `quickjs.c`
2. **Root Cause**: Pointer validation occurs before user code execution, but no re-validation occurs after potential buffer resize
3. **Affected Operations**: All Atomics methods except `load()` (since it doesn't take value arguments that trigger `valueOf`)

## Exploitation Challenges

After extensive testing, I've identified several key challenges:

1. **Allocator Behavior**: QuickJS uses its own allocator (`js_malloc`/`js_free`/`js_realloc`) which doesn't behave like standard system allocators. This makes heap grooming more difficult.

2. **Memory Layout**: The exact memory layout of JS objects in QuickJS is not easily predictable from JavaScript code alone.

3. **Primitive Limitations**: The vulnerability provides a write primitive to freed memory, but controlling what gets allocated in that space is non-trivial.

## Successful Exploitation Strategy

Based on my analysis, the most promising approach is:

1. **Create a large resizable ArrayBuffer** (e.g., 4096+ bytes) to ensure it's allocated in a predictable way
2. **Use precise heap grooming** to place a target object (like a TypedArray) in the memory that will be freed
3. **Corrupt the internal structure** of the target TypedArray to achieve arbitrary read/write
4. **Use the arbitrary read/write** to leak addresses and eventually execute shellcode

The critical insight is that we need to understand QuickJS's object representation. In QuickJS:
- JS objects are represented as `JSObject` structures
- TypedArrays contain pointers to their underlying buffer
- By corrupting these pointers, we can redirect reads/writes to arbitrary memory

## Proof of Concept Development

The provided trigger demonstrates the vulnerability but doesn't achieve code execution. To build a working exploit:

1. We need to create a situation where the freed buffer memory is reused for a TypedArray's metadata
2. Use the stale pointer write to corrupt the TypedArray's buffer pointer
3. This gives us an arbitrary read/write primitive through the corrupted TypedArray
4. Use this primitive to leak libc addresses and overwrite function pointers or return addresses

The key breakthrough would be achieving reliable heap layout control to ensure our target object is placed in the freed memory region.