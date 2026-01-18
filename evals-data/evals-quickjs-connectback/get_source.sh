#!/bin/bash
# Get source for evals-quickjs-seccomp
# This reuses the same QuickJS source as evals-quickjs-latest

set -e

# Just ensure the base quickjs source exists
if [ ! -d /opt/evals/source/evals-quickjs-latest ]; then
    echo "Error: evals-quickjs-latest source not found"
    echo "Please run evals-quickjs-latest/get_source.sh first"
    exit 1
fi

echo "Using shared QuickJS source from evals-quickjs-latest"
