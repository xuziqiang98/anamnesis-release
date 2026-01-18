#!/bin/bash
# Build quickjs without AddressSanitizer (regular release build)

SRC="/opt/evals/source/evals-quickjs-latest"
DST="/opt/evals/install-regular/evals-quickjs-latest"

cd "$SRC"
make clean
make -j4 qjs

mkdir -p $DST
cp "$SRC/qjs" "$DST"
