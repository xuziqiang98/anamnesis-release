#!/bin/bash
# Build QuickJS with Intel CET (Control-flow Enforcement Technology) + Full RELRO
#
# CET provides HARDWARE-ENFORCED control flow protection:
#   - IBT (Indirect Branch Tracking): Indirect calls/jumps must target ENDBR64 instructions
#   - Shadow Stack: Return addresses validated in hardware (blocks ROP)
#
# Key difference from Clang CFI:
#   - CFI: Software-based, protects forward-edge only (indirect calls)
#   - CET: Hardware-based, protects BOTH forward-edge AND backward-edge (returns)
#
# Requires:
#   - Intel Tiger Lake (11th gen) or newer / AMD Zen 3 or newer
#   - Linux kernel 5.18+ with CONFIG_X86_USER_SHADOW_STACK=y
#   - GCC with -fcf-protection support
#
# Note: Unlike CFI, CET does NOT require source code patches for type safety.

set -e

SRC="/opt/evals/source/evals-quickjs-latest"
DST="/opt/evals/install-cet/evals-quickjs-latest"
WORK="/tmp/quickjs-cet-build"

echo "=== Building QuickJS with Intel CET ==="

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

echo "Configuring build with CET flags..."

# Create Makefile configuration for CET
# Using GCC since -fcf-protection is a GCC flag
cat > Makefile.local << 'MAKELOCAL'
# Intel CET: -fcf-protection=full enables both IBT and Shadow Stack code generation
# -Wl,-z,ibt,-z,shstk sets the ELF property notes to enable kernel enforcement
CFLAGS+=-fcf-protection=full
LDFLAGS+=-fcf-protection=full -Wl,-z,relro,-z,now -Wl,-z,ibt,-z,shstk
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
echo "=== Verifying CET build ==="
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
    echo "This may indicate:"
    echo "  - Compiler doesn't support -fcf-protection"
    echo "  - Linker doesn't support CET"
    echo "  - System libraries lack CET support"
fi

echo ""
echo "CET Configuration:"
echo "  -fcf-protection=full (generates ENDBR64 instructions)"
echo "  -Wl,-z,ibt,-z,shstk (sets ELF property for kernel enforcement)"
echo "  -Wl,-z,relro,-z,now (Full RELRO)"

echo ""
echo "CET QuickJS installed to $DST"
