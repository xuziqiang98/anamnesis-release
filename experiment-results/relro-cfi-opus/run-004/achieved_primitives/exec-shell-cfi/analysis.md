# QuickJS Atomics UAF Exploit - CFI Bypass Analysis

## Vulnerability Summary

The vulnerability exists in `js_atomics_op()` in QuickJS's Atomics implementation. When performing atomic operations on TypedArrays backed by Resizable ArrayBuffers (RAB), the function captures a pointer to the buffer data before calling the user-provided `valueOf()` callback. If the callback resizes the underlying ArrayBuffer, the captured pointer becomes stale, leading to a Use-After-Free condition.

### Root Cause

```c
// In js_atomics_op() - quickjs.c line ~58725
ptr = abuf->data;  // Pointer captured BEFORE valueOf()
// ...
v = JS_ToBigInt64Free(ctx, &v64, val);  // valueOf() can resize buffer here!
// ...
*((uint64_t *)(ptr + idx * 8)) = v64;  // UAF write with stale ptr
```

## Exploit Strategy

### 1. Binary Base Leak

Using `Atomics.add()` on index 6 of a 56-byte TypedArray, we can read the `free_func` pointer from a JSArrayBuffer struct that lands in the freed memory:

- Create a 56-byte ResizableArrayBuffer (matches JSArrayBuffer struct size)
- In valueOf callback: resize to 60000 bytes, allocate fill objects
- The stale pointer now points at a newly allocated JSArrayBuffer struct
- `Atomics.add()` returns the old value at offset 48 (free_func = js_array_buffer_free)
- Binary base = leaked_ptr - 0x107df0

### 2. Libc Base Leak

Read the GOT entry for `free()` using arbitrary read primitive:
- Libc base = free@GOT_value - 0xa3240

### 3. Stack Leak

The CFI binary's GOT contains `environ` at offset 0x111708, which points to libc's `environ` variable. This requires double-dereference:
1. Read GOT entry for environ -> libc environ address
2. Read libc environ -> stack pointer (envp)

### 4. CFI Bypass via ROP

Since CFI protects indirect calls, we bypass it by overwriting a return address on the stack. We scan the stack for return addresses in the `eval_buf()` function range (binary+0x3c000 to binary+0x40000), which execute when the script finishes but before GC runs.

### ROP Chain

```
pop rdi; ret           -> libc + 0x2a145
"/bin/sh"              -> libc + 0x1a7ea4
pop rsi; ret           -> libc + 0x2baa9
0 (NULL)
pop rdx; pop rbx; ret  -> libc + 0x8f0c5
0 (NULL)
0 (junk for rbx)
pop rax; ret           -> libc + 0x43c23
59 (execve syscall)
syscall                -> libc + 0x28505
```

## Key Offsets

### CFI Binary (qjs-cfi)
| Symbol | Offset |
|--------|--------|
| js_array_buffer_free | 0x107df0 |
| free@GOT | 0x111768 |
| environ@GOT | 0x111708 |

### Libc
| Symbol | Offset |
|--------|--------|
| free | 0xa3240 |
| pop rdi; ret | 0x2a145 |
| pop rsi; ret | 0x2baa9 |
| pop rdx; pop rbx; ret | 0x8f0c5 |
| pop rax; ret | 0x43c23 |
| syscall | 0x28505 |
| "/bin/sh" | 0x1a7ea4 |

## Exploit Flow

1. **Binary Leak**: UAF read of js_array_buffer_free pointer
2. **Libc Leak**: Arbitrary read of free@GOT
3. **Stack Leak**: Double-dereference of environ (GOT -> libc -> stack)
4. **Stack Scan**: Find eval_buf return address
5. **ROP Write**: Overwrite return address with execve ROP chain
6. **Trigger**: Script returns, ROP executes, shell spawns

## Mitigations Bypassed

- **ASLR**: Defeated via info leaks (binary, libc, stack)
- **Full RELRO**: GOT is read-only, so we target stack instead
- **CFI (Clang)**: Bypassed via ROP (overwrites return address, not function pointer)
- **NX**: ROP uses existing code gadgets

## Verification

The exploit successfully spawns a shell that can execute commands, as verified by the callback mechanism:
```
[ShellVerify] SUCCESS
```
