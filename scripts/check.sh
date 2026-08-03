#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

rust_toolchain=${RUST_TOOLCHAIN:-1.89.0}

assert_same_file() {
  canonical=$1
  package_copy=$2
  if ! cmp -s "$canonical" "$package_copy"
  then
    echo "error: package copy $package_copy differs from $canonical" >&2
    exit 1
  fi
}

public_crates="
hns-chat-protocol
hns-encoding
hns-primitives
hns-covenants
hns-dns-relay-protocol
hns-header-consensus
hns-service-authority
hns-hnsr-protocol
hns-odoh-protocol
hns-p2p-experimental
hns-urkel-proof
hns-transaction
hns-script
hns-mining
hns-swap
hns-marketplace-protocol
hns-p2p-wire
"

for package in $public_crates
do
  assert_same_file LICENSE-APACHE "crates/$package/LICENSE-APACHE"
  assert_same_file LICENSE-MIT "crates/$package/LICENSE-MIT"
done

assert_same_file fixtures/hsd/name-state-resource-v1.txt \
  crates/hns-covenants/fixtures/hsd/name-state-resource-v1.txt
assert_same_file fixtures/hsd/name-state-resource-v1.txt.sha256 \
  crates/hns-covenants/fixtures/hsd/name-state-resource-v1.txt.sha256
assert_same_file fixtures/hsd/script-tests-v1.txt \
  crates/hns-script/fixtures/hsd/script-tests-v1.txt
assert_same_file fixtures/hsd/fee-policy-v1.txt \
  crates/hns-script/fixtures/hsd/fee-policy-v1.txt
assert_same_file fixtures/hsd/fee-policy-v1.txt.sha256 \
  crates/hns-script/fixtures/hsd/fee-policy-v1.txt.sha256
assert_same_file fixtures/protocol-v1/hns-swap-v1.txt \
  crates/hns-swap/fixtures/protocol-v1/hns-swap-v1.txt
assert_same_file fixtures/protocol-v1/hns-swap-v1.txt.sha256 \
  crates/hns-swap/fixtures/protocol-v1/hns-swap-v1.txt.sha256
assert_same_file fixtures/protocol-v1/hns-marketplace-v1.txt \
  crates/hns-marketplace-protocol/fixtures/protocol-v1/hns-marketplace-v1.txt
assert_same_file fixtures/protocol-v1/hns-marketplace-v1.txt.sha256 \
  crates/hns-marketplace-protocol/fixtures/protocol-v1/hns-marketplace-v1.txt.sha256
assert_same_file fixtures/chat-v1/hns-chat-resource-v1.txt \
  crates/hns-chat-protocol/fixtures/chat-v1/hns-chat-resource-v1.txt
assert_same_file fixtures/chat-v1/hns-chat-resource-v1.txt.sha256 \
  crates/hns-chat-protocol/fixtures/chat-v1/hns-chat-resource-v1.txt.sha256
assert_same_file registry/denuo-experimental-v1.toml \
  crates/hns-p2p-experimental/registry/denuo-experimental-v1.toml
assert_same_file registry/denuo-experimental-v1.bin \
  crates/hns-p2p-experimental/registry/denuo-experimental-v1.bin
assert_same_file registry/denuo-experimental-v1.sha256 \
  crates/hns-p2p-experimental/registry/denuo-experimental-v1.sha256
assert_same_file registry/denuo-experimental-v2.toml \
  crates/hns-p2p-experimental/registry/denuo-experimental-v2.toml
assert_same_file registry/denuo-experimental-v2.bin \
  crates/hns-p2p-experimental/registry/denuo-experimental-v2.bin
assert_same_file registry/denuo-experimental-v2.sha256 \
  crates/hns-p2p-experimental/registry/denuo-experimental-v2.sha256
assert_same_file registry/hnsr-service-profiles-v1.toml \
  crates/hns-p2p-experimental/registry/hnsr-service-profiles-v1.toml
assert_same_file registry/hnsr-service-profiles-v1.bin \
  crates/hns-p2p-experimental/registry/hnsr-service-profiles-v1.bin
assert_same_file registry/hnsr-service-profiles-v1.sha256 \
  crates/hns-p2p-experimental/registry/hnsr-service-profiles-v1.sha256

PYTHONDONTWRITEBYTECODE=1 \
  python3 generators/generate-marketplace-v1-fixtures.py --check

cargo +"$rust_toolchain" metadata --locked --format-version 1 >/dev/null
cargo +"$rust_toolchain" metadata --locked --manifest-path fuzz/Cargo.toml --format-version 1 >/dev/null
cargo +"$rust_toolchain" deny --locked check
cargo +"$rust_toolchain" deny --locked --manifest-path fuzz/Cargo.toml check
cargo +"$rust_toolchain" run --locked -p hns-registry-gen -- --check
cargo +"$rust_toolchain" fmt --manifest-path Cargo.toml --all -- --check
cargo +"$rust_toolchain" fmt --manifest-path fuzz/Cargo.toml --all -- --check
cargo +"$rust_toolchain" check --locked --manifest-path fuzz/Cargo.toml --all-targets
cargo +"$rust_toolchain" clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo +"$rust_toolchain" test --locked --workspace --all-targets --all-features
cargo +"$rust_toolchain" build --locked --release --workspace --all-targets --all-features
./scripts/publish.sh --dry-run
