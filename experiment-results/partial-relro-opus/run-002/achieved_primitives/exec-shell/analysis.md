# QuickJS Atomics UAF Exploit Analysis

## Vulnerability Summary

The vulnerability exists in QuickJS's `js_atomics_op()` and `js_atomics_store()` functions where a use-after-free occurs through the Resizable ArrayBuffer feature. When performing atomic operations on a TypedArray backed by a resizable ArrayBuffer:

1. The data pointer is captured early (line 58736-58738 in quickjs.c)
2. User-controlled `valueOf()` callback executes during argument conversion
3. The callback can resize the ArrayBuffer via `ArrayBuffer.prototype.resize()`
4. The stale pointer is used for subsequent atomic operations
5. This allows reading/writing to freed memory

## Exploitation Strategy

### Stage 1: PIE Base Leak

Using `Atomics.add(view, 6, mal)` where:
- `view` is a BigUint64Array on a 56-byte resizable ArrayBuffer
- `mal.valueOf()` resizes the buffer and sprays new ArrayBuffers
- Index 6 corresponds to the `free_func` field of JSArrayBuffer (offset 48)
- The returned value is `js_array_buffer_free` address, revealing PIE base

### Stage 2: OOB Primitive Creation

Using `Atomics.exchange(view, 0, mal)` to corrupt `byte_length`:
- Spray many 64-byte ArrayBuffers before the UAF
- The UAF overwrites `byte_length` field of a victim buffer
- Setting it to 0xffffffff00010000 creates 64KB out-of-bounds access
- New BigUint64Array view on corrupted buffer allows OOB read/write

### Stage 3: Structure Discovery

Scanning OOB memory to find JSArrayBuffer structures:
- Look for `js_array_buffer_free` pointers (PIE + 0x14bc0)
- These indicate the `free_func` field at offset 48
- Calculate structure start at (found_index - 6)

### Stage 4: Gadget-Based Shell Execution

Key gadget at PIE + 0x36736:
```asm
lea 0x20(%rdx), %rdi   ; rdi = data + 32
call *(%rdx)           ; call [data + 0]
```

When `free_func` is called as `free_func(rt, opaque, data)`:
- rdx = data (controlled buffer)
- Gadget sets rdi = data + 32, then calls [data + 0]

Payload layout:
- data[0..7] = execve@plt (PIE + 0x11410)
- data[32..39] = "/bin/sh\0"

Result: `execve("/bin/sh", opaque=NULL, envp=data)` spawns shell

## Key Addresses

| Symbol | Offset |
|--------|--------|
| js_array_buffer_free | 0x14bc0 |
| execve@plt | 0x11410 |
| lea rdi,rdx+0x20; call [rdx] gadget | 0x36736 |

## JSArrayBuffer Structure

```
Offset  Field
0       byte_length (4) + max_byte_length (4)
8       detached (1) + shared (1) + padding
16      data (pointer to user data)
24      array_list.prev
32      array_list.next
40      opaque
48      free_func
```

## Exploit Flow

1. Trigger UAF to read `free_func` → Leak PIE base
2. Trigger UAF to corrupt `byte_length` → Create OOB primitive
3. Prepare victim buffers with execve@plt + "/bin/sh" payload
4. Use OOB write to overwrite victim's `free_func` with gadget
5. Trigger GC to finalize victim buffer
6. Gadget executes: rdi = "/bin/sh", call execve@plt
7. Shell spawns

## Files

- `/tmp/work/exploit20.js` - Working PoC
- `/tmp/work/analysis.md` - This analysis
