# Analysis of QuickJS Atomics Vulnerability for exec-shell Primitive

## Understanding the Vulnerability

The vulnerability exists in `js_atomics_op()` and `js_atomics_store()` functions in QuickJS. The key issue is:

1. A pointer to the buffer element is captured via `js_atomics_get_ptr()`
2. User-controlled code (via `valueOf()`) is executed during value conversion
3. This user code can resize the underlying ArrayBuffer, potentially freeing the original buffer
4. The stale pointer is then used for atomic operations without revalidation

## Key Observations from Testing

1. **The vulnerability is real but subtle**: Our basic triggers execute without crashing, suggesting that either:
   - The allocator doesn't immediately reuse freed memory
   - The out-of-bounds access doesn't cause immediate crashes
   - The memory layout makes exploitation non-trivial

2. **Valid indices become invalid**: We confirmed that using a valid index (like 255 in a 256-element array) that becomes out-of-bounds after resize still executes the atomic operation.

3. **No immediate crashes**: Unlike ASAN builds, the standard allocator doesn't crash on out-of-bounds access immediately, making exploitation more challenging but also more stealthy.

## Exploitation Strategy

To achieve `exec-shell` primitive, we need to:

1. **Achieve arbitrary read/write**: Use the OOB access to corrupt memory structures
2. **Gain code execution**: Overwrite function pointers or other executable structures
3. **Execute shell command**: Use the code execution to call system()

### Step 1: Understanding QuickJS Memory Layout

QuickJS uses its own memory allocator (`js_malloc`, `js_realloc`, `js_free`). From the code, we can see:
- Objects are represented as `JSObject` structures
- Arrays and TypedArrays have specific internal structures
- Function objects contain callable code pointers

### Step 2: Targeting Object Corruption

The most promising approach is to:
1. Create a vulnerable TypedArray with controlled data
2. Resize it to free the buffer
3. Allocate a target object (like a JSFunction) in the same memory location
4. Use the stale pointer to corrupt the target object's internal structure

### Step 3: Building the Exploit

We need to:
- Create precise heap grooming to ensure our target object is allocated where the freed buffer was
- Use the atomic operation to write controlled values to corrupt function pointers
- Trigger the corrupted function to achieve code execution

## Challenges

1. **Heap Grooming**: QuickJS allocator behavior needs to be understood to reliably place objects
2. **Pointer Width**: On 64-bit systems, we need to handle full pointer sizes
3. **ASLR**: Memory layout randomization may require info leaks first

## Next Steps

1. Analyze QuickJS object layouts to find corruption targets
2. Develop heap grooming primitives
3. Implement info leak if needed
4. Build ROP chain or direct function pointer overwrite