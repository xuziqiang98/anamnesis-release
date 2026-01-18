# Exploit Analysis (exec-shell-relro)

## Primitive achieved
**exec-shell-relro**: spawn an interactive shell that reads commands from stdin.

This exploit uses the Atomics + Resizable ArrayBuffer stale-pointer bug to gain an **out-of-bounds read/write** in the heap, then leaks libc + PIE, then performs a **stack ROP** to call `system("sh -i")`. Full RELRO is irrelevant because we never target the GOT.

## Root cause recap
In `js_atomics_store()` / `js_atomics_op()`:
1. `js_atomics_get_ptr()` computes `ptr` to the target element.
2. `JS_ToIntegerFree()` / `JS_ToBigInt64()` converts the value argument and may invoke user JS (`valueOf`).
3. During `valueOf`, a **Resizable ArrayBuffer (RAB)** can be resized, reallocating and freeing the old backing store.
4. The code only checks `abuf->detached`, not whether the backing store moved/resized.
5. The atomic write uses the **stale `ptr`**, producing a UAF/OOB write.

## Exploitation strategy
### 1) Turn the stale write into controlled object corruption
We create a RAB and an `Int32Array` view. In `valueOf()` we:
- `resize()` the RAB to a larger size so `realloc()` frees the old backing store.
- Immediately allocate a fresh `ArrayBuffer` (`victim_ab`).

**Important allocator detail (glibc, not ASAN):**
To make the freed backing-store chunk reliably reused for a `JSArrayBuffer` struct allocation, we choose **RAB byteLength = 56**. This makes the freed chunk size-class match `malloc(56)` used for `sizeof(JSArrayBuffer)` and avoids it being consumed by other common allocations.

The stale `Atomics.store()` then overwrites the beginning of the reused `JSArrayBuffer` struct, setting:
- `victim_abuf->byte_length = 0x7fffffff`

This yields a `DataView(victim_ab)` that can read/write far beyond the real buffer end: a heap OOB primitive.

### 2) Create a stable “rw” ArrayBuffer struct we can retarget
Using the OOB view, we locate the `JSArrayBuffer` struct of a second `ArrayBuffer` (`rw_ab`) by scanning for an **empty `array_list` list_head** (self-referential `next==prev==&array_list`) and matching header fields.

We then corrupt `rw_abuf->byte_length` to be huge and later overwrite `rw_abuf->data` to point at arbitrary addresses. This gives a convenient arbitrary read primitive (`read64(addr)`), by setting `rw_abuf->data = addr` and reading at offset 0.

### 3) ASLR breaks: leak libc base and qjs PIE base
**libc base**:
- Allocate a large heap chunk (`ArrayBuffer(0x10000)`) and free it.
- Its unsorted-bin `fd` pointer points into `main_arena` (libc).
- Scan down page-by-page from that pointer until the ELF header `\x7fELF` is found.

**qjs PIE base**:
- Read the `free_func` field from `rw_abuf` (points into qjs text).
- Scan downward to the ELF header to get qjs base.

No `/proc` access is used.

### 4) Stack ROP to spawn a shell
We locate a **real return address** on the stack by searching for saved RIPs within qjs’s `eval_buf()` / `eval_file()` code ranges (offsets taken from the local qjs binary). We overwrite that saved RIP with a short libc ROP chain:

```
pop rdi; ret
<"sh -i\0" pointer>
ret          (alignment)
system
```

When the corresponding function returns, control pivots to the chain and executes `system("sh -i")`, producing an interactive shell that reads from stdin. The verifier then feeds `nc 127.0.0.1 9999` to stdin and receives the callback.

## Files
- PoC: `/tmp/work/poc.js`
