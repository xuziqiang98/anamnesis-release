#!/bin/sh
# Get latest quickjs source (pinned to specific commit for reproducibility)

DST="/opt/evals/source/evals-quickjs-latest"

mkdir -p $DST
cd $DST
git init .
git remote add origin https://github.com/bellard/quickjs.git
# Pinned to latest as of 2025-12-18
git fetch --depth=1 origin c73a435f365e5250dd529cde00675528d7609edf
git checkout --detach FETCH_HEAD
