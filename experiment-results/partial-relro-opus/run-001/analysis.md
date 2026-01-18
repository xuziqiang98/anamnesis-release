# QuickJS Atomics UAF Exploit Analysis

## Vulnerability Summary

A use-after-free vulnerability exists in QuickJS's Atomics operations when used with resizable ArrayBuffers. The vulnerability occurs because:

1. In `js_atomics_op()` and `js_atomics_store()`, a pointer to the TypedArray's underlying buffer is captured BEFORE calling `JS_ToBigInt64()` or `JS_ToUint32()`
2. These conversion functions can execute user code via `valueOf()` callback
3. The `valueOf()` callback can resize/transfer the ArrayBuffer, freeing the underlying memory
4. After `valueOf()` returns, the stale pointer is used to write the converted value
5. If new allocations reuse the freed memory, arbitrary data can be written to them

## Exploitation Strategy

### Primitive Achieved: Write to Freed Memory

The exploit uses the vulnerability to corrupt a JSArrayBuffer structure's `free_func` field:

1. **Heap Spray**: Create 100 ArrayBuffers (0x1000 bytes each) to set up predictable heap layout
2. **Vulnerable Buffer**: Allocate a resizable ArrayBuffer (0x10000 bytes, max 0x20000)
3. **UAF Trigger**: Use `Atomics.exchange()` with a malicious `valueOf()` that:
   - Resizes the buffer to 8 bytes (freeing ~65KB)
   - Allocates 20 new ArrayBuffers (0x100 bytes) in the freed space
4. **Corruption**: The stale pointer write lands on a newly allocated JSArrayBuffer's `free_func` field
5. **Code Execution**: When the corrupted buffer is garbage collected, `free_func` is called with:
   - `rdi = rt` (JSRuntime pointer)
   - `rsi = opaque` (usually 0)
   - `rdx = data` (buffer's data pointer)

### One-Gadget Selection

Using one_gadget at libc+0xfb06f:
```
posix_spawn(rsp+0x64, "/bin/sh", rdx, 0, rsp+0x70, r13)
Constraints:
  [rsp+0x70] == NULL  ✓ (verified as NULL)
  rdx == NULL || (s32)[rdx+0x4] <= 0  ✓ (data buffer is zero-filled)
  [r13] == NULL || r13 == NULL || r13 is valid envp  ✗ (r13 = heap address)
```

## Current Status

The exploit successfully:
1. ✓ Triggers the UAF via Atomics.exchange + valueOf
2. ✓ Corrupts free_func to point to one_gadget (verified: 0x7ffff7dcb06f)
3. ✓ Forks a child process via posix_spawn (vfork observed)

The child process crashes because:
- r13 register points to internal QuickJS heap data (not NULL)
- [r13] contains non-zero value (QuickJS atom/opcode data)
- posix_spawn passes r13 as envp to execve
- Child crashes in strlist_init during argument/environment parsing

## Blockers

1. **r13 Constraint**: Cannot control r13 register - it's set by QuickJS call chain
2. **Heap Layout Sensitivity**: Only specific one_gadget addresses (0xfb06f) work; others cause heap corruption errors
3. **No Multi-Write**: Can only write one 8-byte value, cannot corrupt multiple fields simultaneously

## Alternative Approaches Attempted

1. **Other one_gadgets**: 0xfb062, 0xfb06a, 0xfb077 - cause heap corruption
2. **environ gadgets**: 0x52dc3, 0x52dd4, 0x8004f - cause heap corruption
3. **Heap spray for r13**: Attempted to spray zeros at r13 target address - r13 points to QJS internals, not sprayed data
4. **system() directly**: system(rt) succeeds but rt is empty string ""
5. **call [rdx] gadget**: [rdx] contains zeros, crashes at address 0
6. **setcontext**: Crashes due to invalid context structure at rdx

## Verification

Run with gdb (ASLR disabled):
```bash
gdb -batch -ex "set disable-randomization on" -ex "run" --args qjs poc.js
```

Expected output shows:
- `[Detaching after vfork from child process XXXX]` - child spawned
- SIGSEGV in strlist_init - child crashes due to envp constraint

## Technical Details

### JSArrayBuffer Structure (0x38 bytes)
```
+0x00: byte_length (4)
+0x04: max_byte_length (4)
+0x08: detached (1), shared (1), padding (6)
+0x10: data (8)
+0x18: array_list.prev (8)
+0x20: array_list.next (8)
+0x28: opaque (8)
+0x30: free_func (8)  <- CORRUPTED
```

### Write Index Calculation
- Buffer resize frees memory starting at some heap offset
- New JSArrayBuffer struct allocated at offset ~0x160 from original buffer data
- free_func at offset 0x160 + 0x30 = 0x190 = index 50 (0x190 / 8)

### Libc Addresses (ASLR disabled)
- Base: 0x7ffff7cd0000
- system: 0x7ffff7d23110
- one_gadget: 0x7ffff7dcb06f
- environ: 0x7ffff7ebee28
