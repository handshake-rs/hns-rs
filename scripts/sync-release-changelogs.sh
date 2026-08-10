#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

public_crates=$(sed \
    -e '/^[[:space:]]*#/d' \
    -e '/^[[:space:]]*$/d' \
    release/public-crates.txt)

for package in $public_crates
do
    cp -- release/CRATE-CHANGELOG.md "crates/$package/CHANGELOG.md"
done
