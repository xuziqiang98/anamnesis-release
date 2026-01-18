# Bug Report: Heap Buffer Overflow in Atomics Operations via Resizable ArrayBuffer

## Summary

A heap buffer overflow (use-after-free or out-of-bounds read/write) vulnerability exists in the `Atomics` operations (`Atomics.add`, `Atomics.sub`, `Atomics.and`, `Atomics.or`, `Atomics.xor`, `Atomics.exchange`, `Atomics.compareExchange`, `Atomics.store`) when operating on TypedArrays backed by resizable ArrayBuffers (RAB). The vulnerability occurs because a pointer to the buffer element is captured before user code execution (via `valueOf`), and this stale pointer is later used for atomic operations even after the underlying buffer has been resized, and potentially reallocated

## Vulnerability Class

**Heap Buffer Overflow (Out-of-Bounds Write/Read)** or **Use-After-Free**

## Affected Files and Functions

1. **Primary vulnerability**: `quickjs.c`, function `js_atomics_op()` (lines 58725-58867)
2. **Secondary vulnerability**: `quickjs.c`, function `js_atomics_store()` (lines 58869-58920)

## Root Cause Analysis

### The Bug in `js_atomics_op` (lines 58725-58867)

```c
static JSValue js_atomics_op(JSContext *ctx,
                             JSValueConst this_obj,
                             int argc, JSValueConst *argv, int op)
{
    int size_log2;
    uint64_t v, a, rep_val;
    void *ptr;  // Will become stale after resize
    JSValue ret;
    JSClassID class_id;
    JSArrayBuffer *abuf;

    // LINE 58736-58738: Captures ptr pointing to buffer element
    if (js_atomics_get_ptr(ctx, &ptr, &abuf, &size_log2, &class_id,
                           argv[0], argv[1], 0))
        return JS_EXCEPTION;

    rep_val = 0;
    if (op == ATOMICS_OP_LOAD) {
        v = 0;
    } else {
        if (size_log2 == 3) {
            int64_t v64;
            // LINE 58745: CAN CALL USER CODE via valueOf!
            if (JS_ToBigInt64(ctx, &v64, argv[2]))
                return JS_EXCEPTION;
            v = v64;
            if (op == ATOMICS_OP_COMPARE_EXCHANGE) {
                // LINE 58749: CAN CALL USER CODE via valueOf!
                if (JS_ToBigInt64(ctx, &v64, argv[3]))
                    return JS_EXCEPTION;
                rep_val = v64;
            }
        } else {
            uint32_t v32;
            // LINE 58755: CAN CALL USER CODE via valueOf!
            if (JS_ToUint32(ctx, &v32, argv[2]))
                return JS_EXCEPTION;
            v = v32;
            // ... more JS_ToUint32 calls for compareExchange
        }
        // LINE 58764: Only checks detached, NOT resized!
        if (abuf->detached)
            return JS_ThrowTypeErrorDetachedArrayBuffer(ctx);
   }

   // LINE 58772+: Uses stale ptr for atomic operations - VULNERABILITY!
   a = atomic_fetch_add((_Atomic(uint8_t) *)ptr, v);
   // ... other atomic operations using ptr
}
```

**The issue**: At lines 58736-58738, `js_atomics_get_ptr` validates the TypedArray and index, and returns a raw pointer `ptr` to the buffer element. After this validation, at lines 58745-58761, `JS_ToBigInt64` or `JS_ToUint32` are called which can execute arbitrary JavaScript code via `valueOf()` callbacks. This callback can resize the underlying resizable ArrayBuffer, potentially causing `js_realloc` return a new buffer pointer and freeing the old memory. However, at line 58764, only `abuf->detached` is checked - there is NO check for whether the buffer was resized. The stale `ptr` is then used for atomic operations at lines 58772+.

### Why the Resize Causes Memory Issues

When `ArrayBuffer.prototype.resize()` is called on a RAB (in `js_array_buffer_resize`, lines 56151-56199):

```c
// For non-shared RABs:
data = js_realloc(ctx, abuf->data, max_int(len, 1));  // Can return new pointer!
// ...
abuf->byte_length = len;
abuf->data = data;  // Buffer pointer updated
js_array_buffer_update_typed_arrays(abuf);  // Updates TypedArray views
```

The `js_realloc` call can:
1. **Move the buffer** to a new memory location (freeing the old memory)
2. **Shrink the buffer** in-place (making old offsets out-of-bounds)

Either way, the `ptr` captured before the resize is now invalid:
- If buffer was moved: `ptr` points to freed memory (use-after-free)
- If buffer was shrunk: `ptr` may point beyond the new buffer bounds (heap-buffer-overflow)

### The Same Bug in `js_atomics_store` (lines 58869-58920)

```c
static JSValue js_atomics_store(JSContext *ctx, ...)
{
    void *ptr;
    JSArrayBuffer *abuf;

    // LINE 58878-58880: Captures ptr
    if (js_atomics_get_ptr(ctx, &ptr, &abuf, &size_log2, NULL,
                           argv[0], argv[1], 0))
        return JS_EXCEPTION;

    if (size_log2 == 3) {
        // LINE 58883-58886: CAN CALL USER CODE via valueOf!
        ret = JS_ToBigIntFree(ctx, JS_DupValue(ctx, argv[2]));
        if (JS_ToBigInt64(ctx, &v64, ret)) { ... }

        // LINE 58890-58891: Only checks detached!
        if (abuf->detached)
            return JS_ThrowTypeErrorDetachedArrayBuffer(ctx);

        // LINE 58892: Uses stale ptr - VULNERABILITY!
        atomic_store((_Atomic(uint64_t) *)ptr, v64);
    } else {
        // Same pattern with JS_ToIntegerFree and JS_ToUint32...
    }
}
```

## Affected Operations

All of these `Atomics` methods are affected:
- `Atomics.add()`
- `Atomics.sub()`
- `Atomics.and()`
- `Atomics.or()`
- `Atomics.xor()`
- `Atomics.exchange()`
- `Atomics.compareExchange()` (both value arguments can trigger resize)
- `Atomics.store()`

Note: `Atomics.load()` is NOT affected because it doesn't take a value argument that could trigger valueOf.
