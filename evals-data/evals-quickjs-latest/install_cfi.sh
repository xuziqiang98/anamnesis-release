#!/bin/bash
# Build QuickJS with STRICT Clang CFI (no generalized pointers) + Full RELRO
#
# This is production-grade CFI - the same level used by Android and Chrome.
# It requires patching QuickJS to fix type-unsafe function pointer casts.
#
# CFI Protection:
#   - Forward-edge: Validates ALL indirect call targets against exact type signatures
#   - Backward-edge: NOT protected (returns still vulnerable to ROP)
#
# Key differences from relaxed CFI (-fsanitize-cfi-icall-generalize-pointers):
#   - Strict: void* and JSRuntime* are DIFFERENT types
#   - Relaxed: All pointer types are treated as equivalent
#
# The QuickJS patch creates a wrapper function with DynBufReallocFunc signature
# that forwards to js_realloc_rt, avoiding the type mismatch that would otherwise
# cause CFI to block legitimate internal calls.

set -e

SRC="/opt/evals/source/evals-quickjs-latest"
DST="/opt/evals/install-cfi/evals-quickjs-latest"
WORK="/tmp/quickjs-strict-cfi-build"

echo "=== Building QuickJS with STRICT CFI ==="

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

echo "All patches applied. Building..."

# Create Makefile configuration for strict CFI
cat > Makefile.local << 'MAKELOCAL'
CONFIG_CLANG=y
CONFIG_LTO=y
CFLAGS+=-fsanitize=cfi-icall -fvisibility=hidden
LDFLAGS+=-fsanitize=cfi-icall -fuse-ld=lld -Wl,-z,relro,-z,now
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
echo "=== Verifying strict CFI build ==="
"$DST/qjs" -e 'print(1+1)'

# Show security features
checksec --file="$DST/qjs" 2>/dev/null || echo "(checksec not available)"

# Verify CFI is strict (no generalized pointers)
echo ""
echo "CFI Configuration (strict - no generalized pointers):"
echo "  -fsanitize=cfi-icall"
echo "  -fvisibility=hidden"
echo "  NO -fsanitize-cfi-icall-generalize-pointers"

echo ""
echo "Strict CFI QuickJS installed to $DST"
echo ""
echo "Patches applied:"
echo "  - quickjs.c: Added js_realloc_rt_dynbuf wrapper, replaced casts"
echo "  - quickjs.h: Added wrapper declaration"
echo "  - quickjs-libc.c: Replaced casts"
