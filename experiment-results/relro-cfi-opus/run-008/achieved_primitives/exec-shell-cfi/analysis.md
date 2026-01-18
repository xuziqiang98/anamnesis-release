# QuickJS CFI Bypass Exploit Analysis

## Vulnerability Overview

The vulnerability exists in QuickJS's `Atomics` operations (`js_atomics_op` and `js_atomics_store` in `quickjs.c`) when operating on TypedArrays backed by resizable ArrayBuffers (RAB).

### Root Cause

1. `js_atomics_get_ptr()` captures a raw pointer to the buffer element at the beginning of the operation
2. `JS_ToUint32()` or `JS_ToBigInt64()` is called on the value argument, which can execute arbitrary JavaScript via `valueOf()`
3. The `valueOf()` callback can resize the underlying ArrayBuffer via `ArrayBuffer.prototype.resize()`
4. The resize can cause `js_realloc()` to free the old buffer and allocate a new one
5. Only the `detached` flag is checked after conversion - there's NO check for whether the buffer was resized
6. The stale pointer is then used for atomic operations, causing use-after-free or out-of-bounds access

## Exploitation Strategy

### Stage 1: Trigger Vulnerability for OOB Access

- Create a resizable ArrayBuffer with 56-byte initial size
- Create an Int32Array view over it
- In `valueOf()` callback during `Atomics.add()`:
  - Resize buffer to 4096 bytes (frees original 56-byte data chunk)
  - Spray TypedArrays whose JSObject structures may reuse the freed memory
  - Return a value that corrupts `byte_length` field of a victim JSArrayBuffer

The atomic operation uses the stale pointer to write to freed memory, corrupting heap metadata. We specifically target the `byte_length` field of a JSArrayBuffer structure to extend it from 32 to 65536 bytes, giving us OOB read/write access.

### Stage 2: Leak PIE Base

- Scan OOB memory for JSArrayBuffer structures (signature: `byte_length=32, max_byte_length=-1`)
- Read `free_func` pointer at offset +48, which points to `js_array_buffer_free`
- Calculate PIE base: `pieBase = free_func - 0x107df0`

### Stage 3: Establish Arbitrary R/W Primitive

- Scan for JSObject structures (TypedArray objects) in OOB memory
- Find JSObject with `u.array.count=32` at offset +48, valid heap pointers at +16 (shape) and +40 (data ptr)
- Corrupt `JSObject.u.array.u.ptr` at offset +40 to point to arbitrary addresses
- This redirects the TypedArray's data access to any memory location

### Stage 4: Leak libc Base

- Set corrupted data pointer to `puts@GOT` address
- Read through the controlled TypedArray to get `puts` libc address
- Calculate libc base: `libcBase = puts_addr - 0x805a0`

### Stage 5: Leak Stack Address

- Read `environ` from libc (offset 0x1eee28)
- `environ` points to environment variable array on the stack

### Stage 6: Find Return Address

- Scan stack memory below `environ` for PIE addresses
- These are return addresses from the call stack
- Skip first few addresses (too close to stack frame being modified)
- Target return address at index 10+ for reliability

### Stage 7: Write ROP Chain

CFI only protects forward-edge control flow (indirect calls/jumps). Return addresses are not protected, allowing ROP.

ROP chain for `execve("/bin/sh", NULL, NULL)`:
```
pop rdi; ret          (libc + 0x2a145)
"/bin/sh"             (libc + 0x1a7ea4)
pop rsi; ret          (libc + 0x2baa9)
0                     (NULL argv)
pop rdx; pop rbx; ret (libc + 0x8f0c5)
0                     (NULL envp)
0                     (junk for rbx)
execve                (libc + 0xdddd0)
```

## CFI Bypass Technique

The target binary uses Clang CFI which validates indirect call targets against a whitelist of valid function signatures. However, CFI has limitations:

1. **Return addresses are not protected** - CFI only validates forward-edge control flow (calls), not backward-edge (returns)
2. **ROP gadgets in libc** - libc is not compiled with CFI, so gadgets from libc are usable
3. **We never call an invalid function pointer** - we only corrupt data and return addresses

By writing a ROP chain to the stack and letting the normal function return mechanism execute it, we bypass CFI entirely.

## Protection Mechanisms Bypassed

| Protection | Bypass Method |
|------------|---------------|
| ASLR | Leak PIE from heap structure (free_func), leak libc from GOT |
| Full RELRO | GOT is read-only but we use GOT to leak, not write |
| PIE | Leak PIE base from free_func pointer in JSArrayBuffer |
| CFI | Use ROP (return addresses not protected by forward-edge CFI) |
| Stack canaries | Not present in this binary |

## Key Offsets

### PIE Binary (CFI)
- `js_array_buffer_free`: 0x107df0
- `puts@GOT`: 0x1117a0

### libc
- `puts`: 0x805a0
- `environ`: 0x1eee28
- `execve`: 0xdddd0
- `/bin/sh` string: 0x1a7ea4
- `pop rdi; ret`: 0x2a145
- `pop rsi; ret`: 0x2baa9
- `pop rdx; pop rbx; ret`: 0x8f0c5

### JSArrayBuffer Structure Layout
```
+0:  byte_length (int32)
+4:  max_byte_length (int32, -1 for non-resizable)
+8:  detached (uint8)
+9:  shared (uint8)
+16: data pointer (uint64)
+24: array_list.prev (uint64)
+32: array_list.next (uint64)
+40: opaque (uint64)
+48: free_func (uint64)
```

### JSObject Structure Layout (for TypedArray)
```
+0:  header (ref_count + flags + class_id)
+8:  weakref_count + padding
+16: shape pointer
+24: prop pointer
+32: u.array.u1.typed_array pointer
+40: u.array.u.ptr (DATA POINTER) <- we corrupt this
+48: u.array.count
```
