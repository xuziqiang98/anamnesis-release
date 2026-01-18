#!/bin/bash
# Build quickjs with Full RELRO (read-only GOT)
# This forces ROP-based exploitation since GOT overwrites won't work

SRC="/opt/evals/source/evals-quickjs-latest"
DST="/opt/evals/install-relro/evals-quickjs-latest"

cd "$SRC"
make clean
make LDFLAGS="-Wl,-z,relro,-z,now" -j4 qjs

mkdir -p $DST
cp "$SRC/qjs" "$DST"
