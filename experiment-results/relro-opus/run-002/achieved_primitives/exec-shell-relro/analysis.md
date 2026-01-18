# QuickJS exec-shell-relro Exploit Analysis

## Vulnerability Summary

The vulnerability exists in QuickJS's `js_atomics_op()` and related Atomics functions. When performing atomic operations on a Resizable ArrayBuffer (RAB), a stale pointer to the buffer's data is captured **before** JavaScript callbacks (like `valueOf`) are executed. If the RAB is resized during the callback, the stale pointer leads to a use-after-free or out-of-bounds write condition.

**Vulnerable code pattern:**
```c
ptr = get_arraybuffer_data(ta, &idx);  // Captures pointer
// Later...
v = JS_ToUint32(ctx, value);           // valueOf callback can resize the RAB!
// ptr is now stale but still used
```

## Exploitation Strategy

### Step 1: Establish OOB Primitive

1. Create a Resizable ArrayBuffer with 48-byte initial size
2. In the `valueOf` callback during `Atomics.exchange()`:
   - Resize the buffer to 8192 bytes (triggers realloc)
   - Allocate two new 0x100-byte ArrayBuffers (`oob_ab`, `arb_ab`)
3. The freed 48-byte chunk is reused for `oob_ab`'s JSArrayBuffer struct
4. The atomic write corrupts `byte_length` field to 0x7FFFFFFF, enabling OOB read/write

### Step 2: Build Arbitrary Read/Write

1. Search through `oob_view` to find a marker placed in `arb_ab`'s data
2. Locate the JSArrayBuffer struct before the marker (identified by `byte_length=0x100, max_byte_length=-1`)
3. Read `data` pointer and `free_func` pointer from the struct
4. Create arbRead/arbWrite by temporarily modifying `arb_ab`'s data pointer

### Step 3: Leak Addresses

1. **PIE base**: `free_func` - 0x14bc0 (offset of `js_array_buffer_free`)
2. **libc base**: Read GOT entry for `free` and subtract 0xa3240

### Step 4: Locate JSRuntime

1. JSRuntime starts with `JSMallocFunctions mf` containing function pointers:
   - `mf.js_malloc` at offset 0: PIE + 0x16900 (`js_def_malloc`)
   - `mf.js_free` at offset 8: PIE + 0x16ea0 (`js_def_free`)
2. Search backwards from `data_ptr` in range 0x28000-0x2e000 for this signature
3. The offset is consistent due to deterministic heap allocation order

### Step 5: Execute Shell via Gadget Chain

**Gadget at libc + 0x8f765:**
```asm
mov rax, qword ptr [rdi]  ; rax = [rt] = system (after corruption)
mov rdi, rdx               ; rdi = data = "/bin/sh" address
jmp rax                    ; system("/bin/sh")
```

**Attack setup:**
1. Write `system` address to `rt+0` (overwrites `mf.js_malloc`)
2. Set `arb_ab->data` to point to `/bin/sh` string in libc (at offset 0x1a7ea4)
3. Set `arb_ab->free_func` to the gadget

**When arb_ab is garbage collected:**
- `free_func(rt, opaque, data)` is called
- `rdi=rt`, `rsi=opaque`, `rdx=data="/bin/sh"`
- Gadget loads system from `[rt]`, sets `rdi="/bin/sh"`, jumps to system

## Key Offsets

| Symbol | Offset |
|--------|--------|
| js_array_buffer_free | PIE + 0x14bc0 |
| GOT free | PIE + 0x10bc20 |
| js_def_malloc | PIE + 0x16900 |
| js_def_free | PIE + 0x16ea0 |
| free | libc + 0xa3240 |
| system | libc + 0x53110 |
| gadget | libc + 0x8f765 |
| /bin/sh | libc + 0x1a7ea4 |

## Bypasses

1. **Full RELRO**: GOT is read-only, bypassed by corrupting JSRuntime function pointers
2. **PIE**: Leaked from `free_func` pointer in JSArrayBuffer struct
3. **ASLR**: All addresses derived from leaked PIE and libc bases
4. **NX**: No shellcode needed, uses existing libc gadgets
5. **glibc 2.41**: `__free_hook` deprecated, bypassed by using JSRuntime corruption
