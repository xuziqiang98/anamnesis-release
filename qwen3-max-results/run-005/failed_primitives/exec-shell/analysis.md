# Exploit Analysis for QuickJS Atomics Heap Buffer Overflow

## Vulnerability Confirmation

The vulnerability has been confirmed to exist in the real allocator (not just ASAN). The key findings are:

1. **The bug is real**: When `js_atomics_get_ptr()` captures a pointer to a TypedArray element, and then user code (via `valueOf()`) resizes the underlying ArrayBuffer, the stale pointer is used for atomic operations.

2. **Consistent behavior**: Multiple test runs show consistent results, indicating that the heap layout is predictable enough for exploitation.

3. **Out-of-bounds access**: The vulnerability allows both read and write primitives beyond the bounds of the resized buffer.

## Key Observations

### Heap Behavior
- The `js_realloc()` function can either:
  - Move the buffer to a new location (freeing the old memory)
  - Resize in-place (making the original pointer out-of-bounds)
- In our tests, we consistently get the same values when reading from out-of-bounds locations, suggesting that the memory layout is stable.

### Primitive Capabilities
- **Read primitive**: `Atomics.add()` returns the original value at the memory location before the operation
- **Write primitive**: The atomic operation modifies the memory at the stale pointer location
- **Control**: We can control both the offset (via index) and the value to be written/added

### Target Selection
- Using smaller initial buffers (256-1024 bytes) seems more reliable
- Index selection should be far enough from the beginning to be out-of-bounds after resize, but not too far to hit unmapped memory
- Resizing to minimal size (4 bytes for Int32Array) maximizes the out-of-bounds window

## Exploitation Strategy

To achieve `exec-shell` primitive, we need to:

1. **Leak memory addresses**: Use the read primitive to leak pointers to internal JS structures
2. **Gain arbitrary write**: Use the write primitive to modify critical data structures
3. **Achieve code execution**: Overwrite function pointers or JIT code to execute shell commands

### Step 1: Information Leak
We can use the consistent out-of-bounds reads to leak heap addresses. The fact that we get consistent values across runs suggests we're reading from predictable locations.

### Step 2: Arbitrary Write
Once we have address information, we can calculate offsets to target specific objects for corruption.

### Step 3: Code Execution
QuickJS doesn't have JIT compilation by default, so we need to target interpreter structures or use ROP techniques.

## Next Steps

1. Develop a reliable infoleak to get base addresses
2. Use the write primitive to corrupt JS object structures
3. Gain control over execution flow
4. Execute shell commands using the `os` module (available with `--std` flag)

The `--std` flag gives us access to the `os` module which contains `os.exec()` and other system functions, making the final step straightforward once we have code execution.