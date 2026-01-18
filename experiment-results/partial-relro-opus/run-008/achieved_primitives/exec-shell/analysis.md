# QuickJS Atomics UAF Exploit Analysis

## Vulnerability Summary

The vulnerability exists in QuickJS's `Atomics` operations (`js_atomics_op()` and `js_atomics_store()`) when operating on TypedArrays backed by Resizable ArrayBuffers (RAB). A stale pointer is captured before user code execution via `valueOf()`, and this pointer is used for atomic operations after the underlying buffer may have been reallocated.

## Exploitation Strategy

### Stage 1: Trigger UAF to Create OOB Primitive

1. Create a resizable ArrayBuffer with an initial size (48 bytes)
2. Create a BigUint64Array view over it
3. Craft a malicious object with `valueOf()` that:
   - Resizes the buffer to trigger reallocation (freed old buffer)
   - Sprays ArrayBuffer objects to fill the freed chunk
4. Call `Atomics.add()` which:
   - Captures pointer to buffer element
   - Calls `JS_ToUint32()` triggering our `valueOf()`
   - Uses stale pointer for atomic operation
5. The atomic operation corrupts a sprayed JSArrayBuffer structure's `byte_length` field
6. Result: A JSArrayBuffer with corrupted `byte_length` (0x7ffffff0) allowing massive OOB read/write

### Stage 2: Leak Binary Base Address

Using the OOB primitive:
1. Scan heap for JSArrayBuffer structures (pattern: `0xffffffff00000008` = byte_length=8, max=-1)
2. Each JSArrayBuffer has `free_func` pointer at offset +48 bytes
3. `free_func` points to `js_array_buffer_free` in the binary
4. Calculate: `binary_base = free_func - 0x14bc0`

### Stage 3: Leak libc Base Address

1. Use OOB write to corrupt another JSArrayBuffer's `data` pointer
2. Point it to `free@GOT` (binary_base + 0x10b008)
3. Read through the corrupted buffer to get libc's `free()` address
4. Calculate: `libc_base = libc_free - 0xa3240`

### Stage 4: Overwrite GOT to Hijack Control Flow

1. Write `system()` address (libc_base + 0x53110) to `free@GOT`
2. Now every call to `free(ptr)` becomes `system(ptr)`

### Stage 5: Set Up Shell Trigger

1. Use OOB write to set multiple JSArrayBuffer `data` pointers to `/bin/sh` string in libc
2. Address: `libc_base + 0x1a7ea4`

### Stage 6: Trigger Shell

When the JavaScript program exits:
1. QuickJS garbage collector frees all ArrayBuffer objects
2. `js_array_buffer_free()` calls `js_free_rt()` which calls `free(data)`
3. Since `free@GOT = system`, this becomes `system("/bin/sh")`
4. Shell spawns and reads commands from stdin

## Key Offsets Used

| Symbol | Offset |
|--------|--------|
| js_array_buffer_free | 0x14bc0 (binary) |
| free@GOT | 0x10b008 (binary) |
| free | 0xa3240 (libc) |
| system | 0x53110 (libc) |
| "/bin/sh" | 0x1a7ea4 (libc) |

## Primitives Achieved

1. **OOB Read/Write**: Via corrupted JSArrayBuffer with extended byte_length
2. **Arbitrary Read**: By corrupting JSArrayBuffer.data pointer
3. **Arbitrary Write**: Same technique, writing through corrupted buffer
4. **Code Execution**: Via GOT hijacking (free -> system)
5. **Shell Spawn**: system("/bin/sh") via crafted data pointer

## Mitigations Bypassed

- **ASLR**: Leaked both binary and libc base addresses via heap pointers
- **Partial RELRO**: GOT was writable, allowing GOT overwrite
- **PIE**: Address leak made this irrelevant
- **NX**: Used code reuse (GOT hijacking) instead of shellcode
