# QuickJS Atomics + Resizable ArrayBuffer exploit (offset-independent) -> connectback

## Vulnerability
`js_atomics_store()` / `js_atomics_op()` capture a raw element pointer from a TypedArray, then call `JS_ToUint32/JS_ToBigInt64()` on the value argument. These conversions can execute attacker JS via `valueOf()`. If `valueOf()` resizes a Resizable ArrayBuffer, the captured element pointer becomes stale and is later used for the atomic operation, producing a UAF/OOB read/write.

## High-level exploit plan
Goal primitive: **connectback**
1. Connect to `127.0.0.1:9999`
2. Receive `<u32 fn_len LE><filename><u32 content_len LE><content>`
3. Write `content` to `filename`

Constraints:
- Full RELRO (no GOT overwrite)
- seccomp blocks process spawning (`execve*`, `fork`, `clone*`)
- Offset-independent requirement: **no hardcoded libc/binary offsets or gadget offsets**

The exploit proceeds in three stages:

### 1) libc pointer leak (unsorted-bin metadata)
- Allocate a large RAB `0x3000` and a `BigInt64Array` view.
- Ensure it is not the top chunk by allocating barrier chunks after it.
- Trigger `Atomics.add(ta, 6, evil)` where `evil.valueOf()` shrinks the RAB to `0x20`.
- The stale pointer reads from the freed remainder chunk, returning its unsorted-bin `fd` pointer (a libc address).

### 2) Arbitrary 64-bit read/write
- Allocate a small RAB `0x70` and `BigInt64Array` view.
- During `valueOf()`: shrink to `0x20`, then allocate a `BigUint64Array(backing)` so its object lands in the freed remainder.
- The stale pointer `Atomics.store(ta, 13, base_addr)` overwrites the typed array’s internal data pointer (`u.array.u.ptr`) so that `victim[i]` reads/writes at attacker-chosen addresses.

### 3) Dynamic runtime resolution + control-flow hijack
**No hardcoded offsets** are used:
- **libc base**: found by scanning backward from the leaked libc pointer for an in-memory ELF header (`0x7fELF`).
- **ELF parsing**: parse libc program headers and PT_DYNAMIC to locate `DT_GNU_HASH`, `DT_SYMTAB`, `DT_STRTAB`.
- **Symbol resolution**: implement GNU-hash lookup to resolve `mprotect`, `environ`, and `__libc_start_main` addresses at runtime.
- **Find main’s return address value**: scan near `__libc_start_main` for a distinctive instruction sequence that performs the indirect `call rax` to `main` and then `mov edi,eax; call exit`. The saved return RIP value is the instruction immediately after the indirect call.
- **Stack address**: read `environ` to get a stack pointer (`envp`), then scan a window below it for the saved RIP value.
- **Gadgets**: scan libc executable PT_LOAD segments for byte patterns (`pop rdi; ret`, `pop rsi; ret`, `pop rdx; ret` or `pop rdx; pop rbx; ret`, and `ret`).

The exploit overwrites the saved return address with a small ROP chain:
1. `mprotect(sc_page, 0x2000, PROT_RWX)`
2. jump to stack-resident shellcode

## Payload
Shellcode is x86_64 Linux syscalls only (seccomp-friendly):
- `socket`, `connect`
- `read` exact for filename/content
- `openat(AT_FDCWD, filename, O_WRONLY|O_CREAT|O_TRUNC, 0644)`
- `write` exact
- `close`, `exit`

## Offset-independence notes
The PoC contains:
- No hardcoded libc base offsets
- No hardcoded symbol offsets (`mprotect`, `environ`, etc.)
- No hardcoded gadget offsets
- Only ABI/ELF constants and small struct/size constants used for heap grooming

