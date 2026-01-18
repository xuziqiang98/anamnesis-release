# QuickJS Atomics + Resizable ArrayBuffer stale-pointer -> connectback (offset-independent)

## Target primitive
**connectback** under:
- Full RELRO
- seccomp blocks process spawning (`execve*`, `fork`, `clone*`)

Goal implemented by payload:
1. `socket(AF_INET, SOCK_STREAM, 0)`
2. `connect(127.0.0.1:9999)`
3. `read` protocol: `<u32 filename_len><filename><u32 content_len><content>`
4. `open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644)` and `write(content)`

No JS modules (`std`, `os`) are used.

## Vulnerability
In `js_atomics_op()` / `js_atomics_store()` QuickJS captures a raw element pointer via `js_atomics_get_ptr()`, then runs user JS through `valueOf()` while converting the value argument. `valueOf()` can shrink a Resizable ArrayBuffer, causing `realloc()` splitting/freeing. The function then uses the stale pointer for an atomic read/write, yielding a UAF/OOB access.

## Exploit overview
The exploit is fully **offset-independent**:
- No hardcoded libc offsets (no `libcBase + 0x...`)
- No GOT/PLT offsets
- No gadget offsets
- All addresses resolved at runtime via:
  - memory scanning (ELF header detection)
  - in-memory ELF parsing (PT_DYNAMIC + GNU hash) for symbol resolution
  - byte-pattern gadget search in libc `.text`

### 1) libc pointer leak
A BigInt64Array is created over a resizable ArrayBuffer. During `Atomics.add(ta, 6, evil)` the `evil.valueOf()` shrinks the RAB. The stale pointer read overlaps allocator metadata in the freed split chunk. The returned BigInt is treated as a candidate pointer.

A large “barrier” allocation is used to reduce the chance that `realloc` shrinking merges directly into the top chunk.

### 2) libc base discovery (no hardcoded `main_arena` offset)
Given a candidate pointer that *looks like* a shared-library mapping (`0x7f...`), the exploit scans backward page-by-page (4MB window) for the ELF magic `0x7f454c46`. The first matching page is validated as ELF64 and used as `libcBase`.

### 3) Arbitrary read/write primitive
The stale-pointer write is used to corrupt a `BigUint64Array` object’s internal data pointer (`u.ptr`), giving an arbitrary 64-bit memory view at attacker-chosen `base_addr`. This is used to:
- read libc headers
- parse dynamic linking tables
- read stack memory
- write a ROP chain and shellcode

### 4) Resolve libc symbols dynamically
The exploit parses libc’s ELF program headers to find:
- PT_DYNAMIC
- PF_X PT_LOAD range for gadget scanning

From PT_DYNAMIC it extracts relocated pointers to:
- `DT_GNU_HASH`
- `DT_SYMTAB`
- `DT_STRTAB`

A GNU-hash lookup is implemented in JS to resolve exported symbols at runtime:
- `mprotect`
- `environ`

No fixed offsets are used.

### 5) Find saved return address on the stack (no hardcoded `__libc_start_call_main` offset)
The exploit reads `environ` (resolved dynamically) to obtain a stack pointer (`envp`).

It scans a 1.5MB window below `envp` for values that:
- lie within libc’s executable segment, and
- are immediately after an *indirect call* instruction (`FF D0..D7`) when inspecting libc bytes at `ret-2`.

This identifies the saved return address used when `main` returns, without needing any hardcoded return-site offsets.

### 6) ROP + shellcode
Gadgets are found by byte-pattern scanning within libc’s executable PT_LOAD:
- `ret` (`c3`)
- `pop rdi; ret` (`5f c3`)
- `pop rsi; ret` (`5e c3`)
- `pop rdx; pop rbx; ret` (`5a 5b c3`)

The exploit overwrites the saved RIP with a chain:
1. `mprotect(sc_page, 0x2000, PROT_READ|PROT_WRITE|PROT_EXEC)`
2. jump to stack-resident shellcode

The shellcode performs the required connectback protocol and file write using syscalls only (allowed by seccomp).

## Files
- PoC JS exploit: `/tmp/work/poc.js`
