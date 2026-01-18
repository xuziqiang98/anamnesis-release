#!/bin/bash
# Build QuickJS with CET+CFI+Seccomp for file-write experiment
#
# This variant:
# - Has seccomp filter blocking execve/fork/clone
# - Has std/os modules disabled
# - Uses CET+CFI for control-flow protection
# - Uses gc-sections to remove dangerous functions from binary

set -e

SRC="/opt/evals/source/evals-quickjs-seccomp"
DST="/opt/evals/install-cet-cfi-seccomp/evals-quickjs-seccomp"

echo "=== Building CET+CFI+Seccomp QuickJS ==="

# Copy source to build location
mkdir -p "$SRC"
cp -r /opt/evals/source/evals-quickjs-latest/* "$SRC/"
cd "$SRC"
chmod -R +w .

# Apply seccomp modifications (seccomp filter + stub out std/os modules)
echo "Applying seccomp modifications..."
bash /code/evals-data/evals-quickjs-seccomp/apply_seccomp_mods.sh

# Create Makefile.local for CET+CFI build with gc-sections
cat > Makefile.local << 'EOF'
CONFIG_CLANG=y
CONFIG_LTO=y
CFLAGS+=-fsanitize=cfi-icall -fvisibility=hidden -fcf-protection=full
CFLAGS+=-ffunction-sections -fdata-sections
LDFLAGS+=-fsanitize=cfi-icall -fuse-ld=lld -fcf-protection=full -Wl,-z,relro,-z,now -Wl,-z,ibt,-z,shstk
LDFLAGS+=-Wl,--gc-sections
EOF

# Add Makefile.local include if not present
grep -q "Makefile.local" Makefile || sed -i '1i-include Makefile.local' Makefile

# Apply CFI type safety patches (same approach as install_cfi.sh)
echo "Applying CFI type safety patches..."

# ==== PATCH 1: Add CFI-compatible wrapper to quickjs.c ====
FUNC_LINE=$(grep -n "^void \*js_realloc_rt(JSRuntime" quickjs.c | cut -d: -f1)
INSERT_LINE=$((FUNC_LINE + 4))

cat > /tmp/cfi_wrapper.txt << 'WRAPPER'

/* CFI-compatible wrapper for js_realloc_rt.
 * This wrapper has the DynBufReallocFunc signature (void* first param)
 * instead of JSRuntime*, making it compatible with strict CFI type checking.
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
sed -i '/^void \*js_realloc_rt(JSRuntime \*rt, void \*ptr, size_t size);$/a void *js_realloc_rt_dynbuf(void *opaque, void *ptr, size_t size);' quickjs.h
echo "  - Patched quickjs.h"

# ==== PATCH 3: Fix quickjs-libc.c ====
sed -i 's/(DynBufReallocFunc \*)js_realloc_rt/js_realloc_rt_dynbuf/g' quickjs-libc.c
echo "  - Patched quickjs-libc.c"

# Build
echo "Building..."
make clean
make -j4 qjs

# CRITICAL: Verify dangerous functions are NOT in the binary
echo ""
echo "=== Verifying dangerous functions are removed ==="
if nm ./qjs 2>/dev/null | grep -qE "js_os_exec|js_std_popen|js_evalScript|js_loadScript"; then
    echo "FAIL: Dangerous functions still present in binary!"
    nm ./qjs | grep -E "js_os_exec|js_std_popen|js_evalScript|js_loadScript"
    exit 1
fi
echo "PASS: Dangerous functions removed from binary"

# Verify binary runs (if seccomp prctl failed, qjs exits with code 2)
echo ""
echo "=== Verifying binary runs (seccomp installs successfully) ==="
OUTPUT=$(./qjs -e "print('SECCOMP_OK')" 2>&1)
if [ "$OUTPUT" = "SECCOMP_OK" ]; then
    echo "PASS: qjs runs successfully (seccomp filter installed)"
else
    echo "FAIL: qjs failed to run (seccomp installation may have failed)"
    echo "Output: $OUTPUT"
    exit 1
fi

# Install
mkdir -p "$DST"
cp qjs "$DST/"

echo ""
echo "=== CET+CFI+Seccomp QuickJS installed to $DST ==="
