# QuickJS Atomics + Resizable ArrayBuffer stale-pointer exploit (connectback)

## Primitive achieved
**connectback** under Full RELRO + seccomp (no `execve*`, `fork`, `clone*`).

Shellcode performs:
1. `socket(AF_INET, SOCK_STREAM, 0)`
2. `connect(127.0.0.1:9999)`
3. `read` protocol: `<u32 fnlen><filename><u32 clen><content>`
4. `openat(AT_FDCWD, filename, O_WRONLY|O_CREAT|O_TRUNC, 0644)`
5. `write` content, then `close`/`exit`

## Vulnerability
In `js_atomics_op()` / `js_atomics_store()` QuickJS captures a raw element pointer (`ptr`) from a TypedArray backed by a **Resizable ArrayBuffer** via `js_atomics_get_ptr()`. It then converts the value argument (`JS_ToUint32` / `JS_ToBigInt64`) which can execute attacker JS (`valueOf`).

`valueOf()` can shrink/resize the ArrayBuffer, causing its backing store to be `realloc()`ed or split. QuickJS only checks `abuf->detached`, not whether it was resized. The atomic operation then uses the stale `ptr`, giving an attacker-controlled OOB/UAF read/write.

## Exploitation overview
The exploit is **offset-independent**: it does not hardcode any libc/binary offsets, GOT/PLT offsets, gadget offsets, or string offsets. All required addresses are resolved at runtime.

### 1) Leak a pointer into libc (heap metadata)
We shrink a large resizable ArrayBuffer during `valueOf()` while `Atomics.add()` holds a stale pointer into the soon-to-be-freed region.

To ensure glibc actually creates a free chunk (and doesn’t merge the remainder into the top chunk), a second large ArrayBuffer is allocated after the target buffer.

The stale atomic read returns a pointer from the freed chunk’s metadata (a libc pointer).

### 2) Turn the stale write into arbitrary 64-bit read/write
We create a small RAB (0x70 bytes) and a `BigInt64Array` view. During `valueOf()`:
- shrink the RAB to 0x20 bytes so `realloc` splits off a 0x50-sized remainder chunk
- allocate a `BigUint64Array(backing)` so its JSObject allocation is serviced from that remainder
- when `js_atomics_store()` resumes, it performs an `atomic_store` through the stale pointer, which overlaps the victim JSObject’s `u.array.u.ptr` field.

This produces a typed array whose element accesses read/write from attacker-chosen addresses.

Only **stable struct offsets** are used:
- `JSObject.u.array.u.ptr` is at `JSObject + 0x38` on x86_64 (derived from the QuickJS source layout).

### 3) Compute libc base by scanning for ELF header
From the leaked libc pointer, the exploit scans backward in memory (via the arbitrary read) page-by-page until it finds the ELF magic `0x7f454c46`. This yields the runtime libc base without hardcoded offsets.

### 4) Resolve symbols dynamically (no hardcoded function offsets)
A minimal in-JS ELF parser walks libc’s program headers to find `PT_DYNAMIC` and then reads the dynamic table to locate:
- `DT_SYMTAB`, `DT_STRTAB`, `DT_HASH` / `DT_GNU_HASH`

It then linearly searches the dynamic symbol table to resolve:
- `mprotect`
- `environ`
- `__libc_init_first`

### 5) Find the main() return-site dynamically (no hardcoded return address)
Rather than using a fixed `__libc_init_first+offset`, the exploit reads the first bytes of `__libc_init_first` and searches for the instruction pattern:
- `call *reg` followed by `mov edi, eax`

The address immediately after this indirect call is the return-site used when `main()` returns. This value is searched on the stack.

### 6) Get stack pointer via `environ`
`environ` is resolved dynamically as above; dereferencing it gives a pointer into the initial stack region. A 2MB window below is scanned for the saved return-site value.

### 7) ROP (gadgets found by byte-pattern scan)
The exploit scans libc’s executable segment for gadget byte sequences:
- `pop rdi; ret` (`5f c3`)
- `pop rsi; ret` (`5e c3`)
- `pop rdx; ret` (and small variants)

A short ROP chain is written over the saved return address to call:
- `mprotect(page, 0x2000, PROT_RWX)`

and then jump into stack-resident shellcode.

## Files
- PoC: `/tmp/work/poc.js`
