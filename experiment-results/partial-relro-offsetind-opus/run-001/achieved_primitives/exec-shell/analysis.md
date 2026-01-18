# QuickJS Atomics UAF Exploit Analysis

## Vulnerability Overview

The vulnerability exists in QuickJS's `js_atomics_op()` and `js_atomics_store()` functions. When performing Atomics operations on TypedArrays backed by resizable ArrayBuffers (RAB), a pointer to the buffer element is captured early in the function, before user code can execute via `valueOf()` callbacks. This creates a use-after-free condition when the underlying buffer is resized during the callback.

## Root Cause

In `js_atomics_op()` (quickjs.c, lines 58725-58867):

1. `js_atomics_get_ptr()` captures a raw pointer `ptr` to the buffer element (line 58736-58738)
2. `JS_ToUint32()` or `JS_ToBigInt64()` is called to convert the value argument, which can execute arbitrary JavaScript via `valueOf()` (lines 58745-58761)
3. The `valueOf()` callback can resize the underlying ArrayBuffer via `ab.resize()`
4. When resizing, `js_realloc()` may move the buffer to a new location, freeing the old memory
5. Only `abuf->detached` is checked after the callback (line 58764), not whether the buffer was resized
6. The stale `ptr` is then used for atomic operations (lines 58772+)

## Exploitation Strategy

### Primitive Building

1. **UAF Trigger**: Create a resizable ArrayBuffer with 56 bytes (matching JSArrayBuffer struct size), then in an Atomics operation's `valueOf()` callback:
   - Resize the buffer to force reallocation
   - Allocate a new ArrayBuffer whose JSArrayBuffer struct lands in the freed space
   - The stale pointer now points to the new JSArrayBuffer structure

2. **Arbitrary Read**: Use `Atomics.add(view, index, {valueOf: ...})` to read fields from the victim JSArrayBuffer. Adding 0 preserves the original value while returning it.

3. **Arbitrary Write**: Use `Atomics.exchange(view, index, {valueOf: ...})` to write controlled values to the victim's fields.

### Information Leakage

1. **Binary Base**: Leak `free_func` pointer (offset 48 in JSArrayBuffer) which points to `js_array_buffer_free`. Search backwards from this address for ELF header (0x7f 'E' 'L' 'F').

2. **GOT Address**: Parse the binary's ELF headers dynamically:
   - Read e_phoff to find program headers
   - Find PT_DYNAMIC to locate dynamic section
   - Parse DT_PLTGOT to get GOT.PLT address

3. **Libc Base**: Read resolved function addresses from GOT (GOT[3+]), then search backwards for libc's ELF header.

4. **system() Address**: Parse libc's symbol table dynamically:
   - Find DT_SYMTAB and DT_STRTAB in libc's dynamic section
   - Search string table for "system"
   - Look up corresponding symbol to get function offset

### Code Execution

1. **GOT Overwrite**: Find `fwrite@GOT` in the binary by parsing PLT relocations (DT_JMPREL)

2. **Trigger**: QuickJS's `print()` function uses `fwrite(str, 1, len, stdout)`. Both `fwrite()` and `system()` take the string pointer as their first argument (rdi).

3. **Shell Spawn**: After overwriting fwrite@GOT with system(), calling `print("/bin/sh")` executes `system("/bin/sh")`.

## Key Offsets Used

All offsets used are from source code definitions or standard ELF specifications:

### JSArrayBuffer Structure (from quickjs.c)
- Offset 0: `byte_length` + `max_byte_length` (8 bytes)
- Offset 16: `data` pointer (8 bytes)
- Offset 48: `free_func` pointer (8 bytes)

### ELF64 Header (standard)
- Offset 0x20: `e_phoff` (program header offset)
- Offset 0x36: `e_phentsize` (program header entry size)
- Offset 0x38: `e_phnum` (number of program headers)

### Dynamic Tags (standard ELF values)
- 2: DT_PLTRELSZ
- 3: DT_PLTGOT
- 5: DT_STRTAB
- 6: DT_SYMTAB
- 23: DT_JMPREL

### Elf64_Sym Structure (standard)
- Size: 24 bytes
- Offset 0: `st_name` (4 bytes)
- Offset 8: `st_value` (8 bytes)

## No Hardcoded Offsets

The exploit does not use any hardcoded binary or libc-specific offsets. All addresses are resolved dynamically at runtime by:

1. Parsing ELF headers from leaked pointers
2. Walking program headers to find PT_DYNAMIC
3. Parsing dynamic section for symbol/string tables
4. Searching symbol tables for function names

This makes the exploit portable across different builds and ASLR instances.
