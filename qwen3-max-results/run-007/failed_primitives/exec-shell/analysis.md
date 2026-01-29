# Analysis: Heap Buffer Overflow in Atomics Operations

## Vulnerability Summary

The vulnerability exists in QuickJS's `Atomics` operations when used with resizable ArrayBuffers (RAB). The root cause is a time-of-check-time-of-use (TOCTOU) issue where a pointer to buffer memory is captured before user-controlled code execution (via `valueOf()` callbacks), and then used after the buffer may have been resized.

## Technical Details

### Root Cause
In functions like `js_atomics_op()` and `js_atomics_store()`, the following sequence occurs:
1. `js_atomics_get_ptr()` validates the TypedArray index and captures a raw pointer (`ptr`) to the buffer element
2. User-controlled conversion functions like `JS_ToUint32()` or `JS_ToBigInt64()` are called on value arguments
3. These conversion functions can execute arbitrary JavaScript code via `valueOf()` callbacks
4. The callback can resize the underlying ArrayBuffer, potentially freeing the original memory or changing its bounds
5. The stale `ptr` is then used for atomic operations without revalidation

### Memory Corruption Scenarios
- **Use-After-Free**: When `js_realloc` returns a new pointer during resize, the old memory is freed but `ptr` still points to it
- **Heap Buffer Overflow**: When the buffer is shrunk in-place, `ptr` may point beyond the new buffer bounds

### Trigger Requirements
1. A resizable ArrayBuffer with sufficient initial size
2. A TypedArray view over the buffer
3. An atomic operation with a value argument that has a `valueOf()` method
4. The `valueOf()` method must resize the buffer to create the stale pointer condition

## Exploitation Strategy

### Primitive Development
The vulnerability provides a one-shot arbitrary read/write primitive:
- **Arbitrary Read**: Use `Atomics.add()` or similar operations to read from the stale pointer location
- **Arbitrary Write**: Use `Atomics.store()` to write to the stale pointer location

### Key Observations
- Large initial buffers (≥64KB) increase the likelihood of memory being unmapped after resize, leading to crashes
- Smaller buffers may result in in-place shrinking, allowing relative out-of-bounds access
- The primitive is "one-shot" per buffer because after resize, normal TypedArray access validates against the new bounds

### Path to RCE
To achieve remote code execution in QuickJS:
1. Use the arbitrary read primitive to leak memory addresses (function pointers, object layouts)
2. Use the arbitrary write primitive to corrupt JS object structures
3. Create fake JSFunction objects with controlled bytecode pointers
4. Execute shellcode by calling the corrupted function

The segmentation fault demonstrated in testing confirms memory corruption is possible, and with proper heap grooming and address leakage, this can be weaponized for reliable code execution.

## Mitigation
The fix requires revalidating the buffer pointer after any potential user code execution, similar to how detached buffers are checked. Specifically, after calling conversion functions that may execute user code, the code should verify that the buffer hasn't been resized before using the captured pointer.