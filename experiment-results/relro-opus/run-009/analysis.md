# QuickJS Atomics Vulnerability Analysis

## Vulnerability Summary

The vulnerability exists in QuickJS's `js_atomics_op()` and `js_atomics_store()` functions
in `quickjs.c`. When processing Atomics operations on a SharedArrayBuffer-backed TypedArray,
the code captures a pointer to the buffer element BEFORE calling the `valueOf()` callback
of the operand. If `valueOf()` resizes the underlying ArrayBuffer, the captured pointer
becomes stale, leading to:

- **OOB Read/Write (shrink)**: When buffer shrinks, the remainder is freed to malloc bins.
  The stale pointer can read/write the freed chunk's metadata (fd, bk, size, etc.)

- **Use-After-Free (grow)**: When buffer grows via realloc and moves, the old memory is freed.
  The stale pointer can read/write the freed old data region.

## Exploitation Primitives Achieved

### 1. Libc Leak
Working reliably. By shrinking a large buffer (3584 bytes -> 16 bytes), the remainder
goes to unsorted bin with fd/bk pointing to main_arena. Reading at appropriate offset
leaks main_arena address, from which libc base is computed.

```javascript
let libc_leak = oobRead(3584, 16, 5);
let libc_base = libc_leak - 0x1e7b20n;
```

### 2. Heap Leak
Working partially. By shrinking a tcache-sized buffer, the remainder's mangled fd can be read.
Due to safe-linking, fd = (chunk_addr >> 12) XOR next_addr. For first entry in bin,
fd = chunk_addr >> 12, giving approximate heap page.

```javascript
let heap_fd = oobRead(128, 32, 6);
let heap_page = heap_fd << 12n;
```

### 3. Heap Metadata Corruption
Can write arbitrary values to freed chunk's fd/bk/size fields. However, glibc 2.41
validates these on subsequent allocations, causing crashes if corrupted incorrectly.

## Exploitation Blockers

### Tcache Safe-Linking (glibc 2.32+)
Tcache fd pointers are mangled: `mangled_fd = (chunk_addr >> 12) XOR real_fd`
Each chunk has a different XOR key based on its address. Without knowing the exact
address of the chunk we're corrupting, we can't compute valid mangled fd values.

**Impact**: Simple tcache poisoning attacks fail because XOR keys differ between
our OOB write buffer and target allocation.

### Full RELRO
The GOT is read-only. Cannot overwrite function pointers like `free@GOT` or `system@GOT`.

### Removed Hooks (glibc 2.34+)
`__free_hook`, `__malloc_hook`, `__realloc_hook` no longer exist.
Cannot simply set a hook to hijack allocation/deallocation.

### Pointer Guard for Exit Handlers
`__exit_funcs` function pointers are protected with PTR_MANGLE/PTR_DEMANGLE.
Without leaking or corrupting the pointer guard key, can't replace exit handlers.

### Unlink Checks (unsorted/small bins)
When corrupting unsorted or smallbin fd/bk, the unlink operation checks:
- `chunksize(P) != prev_size(next_chunk(P))` -> abort
- `FD->bk != P || BK->fd != P` -> abort

These prevent simple arbitrary write via bin corruption.

## Attempted Attack Vectors

1. **Tcache Poisoning**: Blocked by safe-linking XOR key mismatch
2. **Unsorted Bin Attack**: Blocked by glibc integrity checks
3. **Large Bin Attack**: Chunk doesn't reach largebin due to heap state
4. **Type Confusion**: JS objects don't land in freed buffer region
5. **FSOP**: Requires arbitrary write to `_IO_list_all` which we don't have
6. **Exit Handler Corruption**: Blocked by pointer mangling

## Possible Paths Forward

1. **Same-Page Allocation**: Force multiple allocations to land in the same 4KB page
   to have consistent XOR keys. Requires precise heap feng shui.

2. **Largebin Attack**: If a chunk can be inserted into largebin with controlled
   fd_nextsize, can write heap address to arbitrary location. Needs complex setup.

3. **House of Apple / House of Banana**: Modern FSOP variants that bypass vtable
   validation. Requires initial heap address write to _IO_list_all.

4. **TLS Corruption**: If TLS base can be located and reached via OOB, could corrupt
   stack canary or pointer guard key.

5. **_rtld_global Corruption**: Dynamic linker structures contain unmangled function
   pointers. Requires ld-linux address leak and arbitrary write.

## Conclusion

The vulnerability provides strong read/write primitives (libc leak, heap leak,
metadata corruption), but modern glibc 2.41 mitigations make achieving arbitrary
code execution significantly more complex than traditional heap exploits.

The primitive is verified to exist but achieving `exec-shell-relro` requires
additional techniques to bypass:
- tcache safe-linking (for controlled allocation)
- pointer mangling (for exit handlers)
- Full RELRO (for GOT overwrite)
