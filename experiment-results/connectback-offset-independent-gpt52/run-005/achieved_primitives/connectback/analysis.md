# QuickJS Atomics + ResizableArrayBuffer stale-pointer exploit (offset-independent) -> connectback

## Vulnerability
`Atomics.store` / `Atomics.add` in `js_atomics_store()` / `js_atomics_op()` capture a raw pointer into a TypedArray (`ptr`) via `js_atomics_get_ptr()`, then convert the value argument via `JS_ToBigInt64` / `JS_ToUint32`, which can execute attacker JS (`valueOf`). If attacker code resizes the underlying **Resizable ArrayBuffer**, the backing store can be `realloc()`ed/split, making the captured `ptr` stale. The atomic operation then uses the stale `ptr`, yielding a UAF/OOB read/write.

## Exploit overview
Goal primitive: **connectback** under Full RELRO + seccomp (no `execve*`/`fork`/`clone*`).

The exploit builds:
1. **libc pointer leak** from glibc free-chunk metadata after an in-place `realloc` shrink.
2. **Arbitrary 64-bit read/write** by corrupting a `BigUint64Array`’s internal data pointer using the stale atomic store.
3. **Offset-independent resolution** of libc base, symbols, and gadgets:
   - libc base by scanning for ELF header (`0x7f454c46`)
   - symbol addresses by parsing libc’s in-memory `PT_DYNAMIC` (`DT_SYMTAB/DT_STRTAB/DT_HASH`)
   - gadgets by scanning libc `.text` for byte patterns (`pop rdi; ret`, etc.)
4. **Stack return address overwrite**:
   - resolve `environ` dynamically
   - use `environ -> envp -> env0` to locate a stack page for shellcode
   - scan a small stack window for a return address into libc `.text` preceded by an indirect `call *reg`
5. **ROP**:
   - call `mprotect(stack_page, 0x1000, PROT_RWX)`
   - jump to stack-resident shellcode
6. **Shellcode** performs:
   - `socket(AF_INET, SOCK_STREAM, 0)`
   - `connect(127.0.0.1:9999)`
   - receive `<u32 fnlen><filename><u32 clen><content>` (robust `readn` loop)
   - `openat(AT_FDCWD, filename, O_WRONLY|O_CREAT|O_TRUNC, 0644)`
   - `write(fd, content, clen)`
   - `close`/`exit`

## Key offset-independence points
The exploit **does not** hardcode offsets to:
- libc base
- `mprotect`, `environ`
- any ROP gadgets

Instead it uses:
- ELF header constants (stable)
- dynamic-section parsing (runtime)
- byte-pattern gadget scan (runtime)

## Files
- PoC: `/tmp/work/poc.js`
