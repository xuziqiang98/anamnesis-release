# QuickJS Atomics + Resizable ArrayBuffer stale-pointer -> connectback (offset-independent)

## Vulnerability
`js_atomics_op()` / `js_atomics_store()` capture an element pointer `ptr` via `js_atomics_get_ptr()` **before** converting the value argument.
The conversion (`JS_ToUint32`, `JS_ToBigInt64`, etc.) can execute attacker JS via `valueOf()`. If the `valueOf()` callback shrinks a **Resizable ArrayBuffer** (RAB), the backing store may be split/reallocated, making the previously-captured `ptr` stale.
QuickJS only checks `abuf->detached`, not whether the backing store was resized/moved, so the subsequent atomic op uses the stale pointer, yielding UAF/OOB read/write.

## Exploit goal
Under Full RELRO + seccomp (no exec/fork/clone), implement the required **connectback** primitive:
1. connect to `127.0.0.1:9999`
2. receive `<u32 fnlen LE><filename><u32 clen LE><content>`
3. write `content` to `filename`

No `std`/`os` modules are used; all syscalls are performed from injected shellcode.

## High-level exploitation strategy
The exploit builds:
1. **libc pointer leak** via allocator metadata exposed by the stale-pointer read
2. **arbitrary 64-bit read/write** by corrupting a `BigUint64Array` object’s internal data pointer (`JSObject.u.array.u.ptr`)
3. **dynamic libc base discovery** by scanning backwards for the ELF header (no hardcoded offsets)
4. **dynamic symbol resolution** by parsing libc’s in-memory ELF dynamic structures (DT_SYMTAB/DT_STRTAB/DT_HASH)
5. **dynamic gadget discovery** by scanning libc executable segments for short byte sequences (`pop rdi; ret`, etc.)
6. **stack return-address overwrite**: find the saved return address of `main` by computing the exact return address value used after `main` returns in `__libc_init_first`, then overwrite it with a ROP chain:
   - `mprotect(stack_page, 0x2000, PROT_RWX)`
   - jump to stack-resident shellcode
7. Shellcode performs socket/connect/read/openat/write/exit.

## Key primitives

### 1) libc pointer leak
Allocate a large RAB and shrink it inside `valueOf()` during an `Atomics.add()` on a `BigInt64Array` view.
On shrink, glibc splits the chunk; the remainder becomes a free chunk whose first qword (in the free-chunk user area) contains a libc pointer (unsorted-bin metadata).

To reduce the chance the remainder becomes the top chunk (which would not contain unsorted fd/bk pointers), the exploit allocates a same-size **barrier** chunk after the large RAB.

### 2) arbitrary read/write via typed array header corruption
A small RAB (`0x70`) is shrunk to `0x20` inside `valueOf()` during an `Atomics.store()`.
The shrink frees a `0x50` remainder chunk which is immediately reused for the `BigUint64Array` JSObject.
The stale-pointer write targets the in-object field:

- `JSObject.u.array.u.ptr` at offset `+0x38` (stable, from `quickjs.c` struct layout)

Overwriting this pointer makes `victim[i]` read/write from attacker-chosen addresses.

## Dynamic resolution (offset-independent)
The exploit is deliberately **offset-independent**:
- libc base is found by scanning for the in-memory ELF magic (`0x7f 'E' 'L' 'F'`)
- symbols are resolved by parsing libc’s dynamic tables in memory (no hardcoded `environ`, `mprotect`, etc. offsets)
- ROP gadgets are found by scanning libc executable mappings for byte patterns, not by fixed offsets

To locate the correct saved return address on the stack without hardcoding a glibc-specific constant, the exploit:
1. resolves `__libc_init_first` from dynsym
2. reads its code bytes and finds the instruction sequence `89 c7 e8` (`mov edi, eax; call ...`), which is the instruction immediately after the indirect call to `main`
3. uses that address as the *exact* return-address value to search for on the stack

## Payload
The payload is stack-resident x86_64 shellcode that performs:
- `socket(AF_INET, SOCK_STREAM, 0)`
- `connect(127.0.0.1:9999)`
- `read` protocol fields
- `openat(AT_FDCWD, filename, O_WRONLY|O_CREAT|O_TRUNC, 0644)`
- `write` content in chunks
- `exit(0)`

This satisfies the connectback contract under the seccomp restrictions.
