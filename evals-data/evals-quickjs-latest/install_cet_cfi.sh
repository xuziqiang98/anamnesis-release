#!/bin/bash
# Build QuickJS with BOTH Intel CET AND Clang CFI + Full RELRO
#
# This combines the strongest protections from both mechanisms:
#
# Clang CFI (-fsanitize=cfi-icall):
#   - Forward-edge: FINE-GRAINED type checking on indirect calls
#   - Blocks calling system() from a js_free function pointer (type mismatch)
#
# Intel CET (-fcf-protection=full):
#   - IBT: Coarse forward-edge (ENDBR64 check at targets)
#   - Shadow Stack: HARDWARE backward-edge protection (blocks ROP)
#
# Together these block:
#   - ROP chains (shadow stack)
#   - Function pointer hijacks to type-mismatched targets (CFI)
#
# Requires:
#   - Clang with CFI and -fcf-protection support
#   - Intel Tiger Lake+ / AMD Zen 3+ CPU
#   - Linux kernel 5.18+ with CONFIG_X86_USER_SHADOW_STACK=y
#   - Ubuntu 24.04+ glibc with CET support
#   - GLIBC_TUNABLES=glibc.cpu.hwcaps=SHSTK at runtime

set -e

SRC="/opt/evals/source/evals-quickjs-latest"
DST="/opt/evals/install-cet-cfi/evals-quickjs-latest"
WORK="/tmp/quickjs-cet-cfi-build"

echo "=== Building QuickJS with CET + CFI ==="

# Create clean working directory
rm -rf "$WORK"
mkdir -p "$WORK"
cd "$WORK"

# Copy source files
cp "$SRC"/*.c . 2>/dev/null || true
cp "$SRC"/*.h . 2>/dev/null || true
cp "$SRC"/*.js . 2>/dev/null || true
cp "$SRC"/Makefile .
cp "$SRC"/VERSION . 2>/dev/null || echo "2025-01-10" > VERSION

echo "Applying CFI compatibility patches..."

# ==== PATCH 1: Add CFI-compatible wrapper to quickjs.c ====
# Find js_realloc_rt and add wrapper after it (NON-static so quickjs-libc.c can use it)
FUNC_LINE=$(grep -n "^void \*js_realloc_rt(JSRuntime" quickjs.c | cut -d: -f1)
INSERT_LINE=$((FUNC_LINE + 4))

cat > /tmp/cfi_wrapper.txt << 'WRAPPER'

/* CFI-compatible wrapper for js_realloc_rt.
 * This wrapper has the DynBufReallocFunc signature (void* first param)
 * instead of JSRuntime*, making it compatible with strict CFI type checking.
 * Non-static so it can be used from quickjs-libc.c as well.
 */
void *js_realloc_rt_dynbuf(void *opaque, void *ptr, size_t size)
{
    JSRuntime *rt = opaque;
    return js_realloc_rt(rt, ptr, size);
}
WRAPPER

head -n "$INSERT_LINE" quickjs.c > /tmp/quickjs_patched.c
cat /tmp/cfi_wrapper.txt >> /tmp/quickjs_patched.c
tail -n +"$((INSERT_LINE + 1))" quickjs.c >> /tmp/quickjs_patched.c
mv /tmp/quickjs_patched.c quickjs.c

# Replace type-unsafe casts in quickjs.c
sed -i 's/(DynBufReallocFunc \*)js_realloc_rt/js_realloc_rt_dynbuf/g' quickjs.c
echo "  - Patched quickjs.c"

# ==== PATCH 2: Add declaration to quickjs.h ====
# Insert after the js_realloc_rt declaration
sed -i '/^void \*js_realloc_rt(JSRuntime \*rt, void \*ptr, size_t size);$/a void *js_realloc_rt_dynbuf(void *opaque, void *ptr, size_t size);' quickjs.h
echo "  - Patched quickjs.h"

# ==== PATCH 3: Fix quickjs-libc.c ====
# Replace type-unsafe casts in quickjs-libc.c
sed -i 's/(DynBufReallocFunc \*)js_realloc_rt/js_realloc_rt_dynbuf/g' quickjs-libc.c
echo "  - Patched quickjs-libc.c"

echo "All patches applied. Building with CET + CFI..."

# Create Makefile configuration for CET + CFI
cat > Makefile.local << 'MAKELOCAL'
CONFIG_CLANG=y
CONFIG_LTO=y
# CFI: Fine-grained forward-edge type checking
# CET: -fcf-protection=full generates ENDBR64, linker flags enable kernel enforcement
CFLAGS+=-fsanitize=cfi-icall -fvisibility=hidden -fcf-protection=full
LDFLAGS+=-fsanitize=cfi-icall -fuse-ld=lld -Wl,-z,relro,-z,now -Wl,-z,ibt,-z,shstk
MAKELOCAL

# Include local config
if ! grep -q "Makefile.local" Makefile; then
    sed -i '1i-include Makefile.local' Makefile
fi

# Build
make clean 2>/dev/null || true
make -j4 qjsc
./qjsc -s -c -o repl.c -m repl.js
make -j4 qjs

# Install
mkdir -p "$DST"
cp qjs "$DST/"

echo ""
echo "=== Verifying CET + CFI build ==="
"$DST/qjs" -e 'print(1+1)'

# Show security features
checksec --file="$DST/qjs" 2>/dev/null || echo "(checksec not available)"

# Verify CET markers in binary
echo ""
echo "Checking for CET markers (IBT/SHSTK):"
if readelf -n "$DST/qjs" 2>/dev/null | grep -qi "IBT\|SHSTK"; then
    readelf -n "$DST/qjs" | grep -i "IBT\|SHSTK" || true
    echo "CET markers found!"
else
    echo "WARNING: No CET markers found in binary"
fi

# Check for ENDBR64 instructions
ENDBR_COUNT=$(objdump -d "$DST/qjs" 2>/dev/null | grep -c endbr64 || echo "0")
echo ""
echo "ENDBR64 instruction count: $ENDBR_COUNT"
if [ "$ENDBR_COUNT" -gt 1000 ]; then
    echo "IBT instrumentation confirmed!"
else
    echo "WARNING: Low ENDBR64 count - IBT may not be properly enabled"
fi

echo ""
echo "CET + CFI Configuration:"
echo "  -fsanitize=cfi-icall (fine-grained forward-edge type checking)"
echo "  -fvisibility=hidden (required for CFI)"
echo "  -fcf-protection=full (generates ENDBR64 instructions)"
echo "  -Wl,-z,ibt,-z,shstk (sets ELF property for kernel enforcement)"
echo "  -Wl,-z,relro,-z,now (Full RELRO)"
echo ""
echo "Patches applied (for CFI compatibility):"
echo "  - quickjs.c: Added js_realloc_rt_dynbuf wrapper, replaced casts"
echo "  - quickjs.h: Added wrapper declaration"
echo "  - quickjs-libc.c: Replaced casts"
echo ""
echo "IMPORTANT: Run with GLIBC_TUNABLES=glibc.cpu.hwcaps=SHSTK to enable Shadow Stack"
echo ""
echo "CET + CFI QuickJS installed to $DST"
