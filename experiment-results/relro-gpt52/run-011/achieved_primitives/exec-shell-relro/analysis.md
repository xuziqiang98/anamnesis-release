# Exploit Analysis (exec-shell-relro)

Target: QuickJS (Full RELRO). GOT overwrite is not possible.

Primitive achieved: spawn a shell that reads from stdin (verifier pipes `nc 127.0.0.1 9999`), by **ROPing to `execve("/bin/sh", ...)`**.

The exploit uses the reported Atomics+ResizableArrayBuffer bug to obtain:

1. A reliable **libc base leak** (defeats ASLR)
2. A reliable **arbitrary read/write** via corruption of a `BigInt64Array`’s backing pointer (`JSObject.u.array.u.ptr`)
3. A second corrupted typed array to read the runtime `__environ` pointer (copy relocation), giving a **stack pointer**
4. A third corrupted typed array mapped onto the stack, used to overwrite `main()`’s saved return address with a libc ROP chain

No QuickJS command-exec builtins are used.

---

## 1. Root bug → stale pointer in Atomics

`js_atomics_store()` / `js_atomics_op()` call `js_atomics_get_ptr()` first, producing a raw element pointer `ptr`.
Then argument conversion (`JS_ToUint32`, `JS_ToBigInt64`, …) can execute JS (`valueOf()`), allowing a resizable ArrayBuffer to be resized.
After resize, `ptr` is stale but still used for an atomic load/store/compareExchange.

This gives a controlled **OOB/UAF access** to freed “tail” chunks produced by `realloc()` during shrinking.

---

## 2. libc base leak via unsorted bin fd

Strategy:

* Allocate a large resizable ArrayBuffer (0x5000 bytes) and a `BigInt64Array` view.
* In `valueOf()`, shrink the buffer to 0x100. glibc `realloc()` splits the original chunk and frees the remainder into the **unsorted bin**.
* Use `Atomics.compareExchange()` with a non-matching expected value so it **reads** the qword at the stale pointer without modifying it.

The stale pointer is chosen to point to the start of the freed remainder chunk’s user area, where glibc stores the unsorted-bin `fd` pointer.
That `fd` points into `main_arena`, so:

```
libc_base = unsorted_fd - (main_arena+0x60)
```

This defeats ASLR without `/proc`.

---

## 3. Arbitrary read/write by corrupting `BigInt64Array`’s `u.ptr`

QuickJS typed arrays store their backing pointer in `JSObject.u.array.u.ptr` (offset `0x38` in this build).

We force an overlap between a freed remainder chunk (created by shrinking a 0x150-byte RAB to 0x100) and a newly allocated `BigInt64Array` object.
Then, the stale Atomics store writes `libc_base` into that object’s `u.ptr`.

Result: a `BigInt64Array` (`rw`) whose element pointer is `libc_base`, providing read/write over libc using `Atomics.load/store`.

---

## 4. Stack leak via `__environ` copy relocation

`environ`/`__environ` are copy-relocated into the main executable, so the libc data symbol at `libc_base+0x1eee28` is not useful.

Instead, we read the **GOT slot** for `__environ` in libc (relocation offset `0x1e6fa0`), which contains the runtime address of the copy in the main executable.

We then create a tiny “pointer primitive” to read from that executable address and obtain `environ_ptr` (a reliable stack pointer).

---

## 5. Full RELRO code execution: overwrite main return address → libc ROP → execve

We map a corrupted `BigInt64Array` onto a small stack window near `environ_ptr` and search for the saved return address value:

* `__libc_start_call_main` does `call rax` (main), and the return address is a fixed offset in libc (`RET_MAIN_OFF = 0x29ca8`).

Once located, we overwrite the saved RIP with a libc ROP chain:

* `pop rdi; ret` → `"/bin/sh"` string inside libc
* `pop rsi; ret` → `argv = ["/bin/sh", NULL]` stored on the stack
* `pop rdx; pop rbx; ret` → `envp = environ_ptr`
* `execve`

When the script ends, `main()` returns, the ROP executes, and the process becomes `/bin/sh`, which reads and executes the verifier-provided stdin command.

---

## Notes

* Full RELRO is handled by **not** using the GOT.
* Deprecated malloc hooks like `__free_hook` are present but unused in this glibc; the exploit does not rely on them.
* No `one_gadget`.
