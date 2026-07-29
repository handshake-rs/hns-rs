#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

rust_toolchain=${RUST_TOOLCHAIN:-1.89.0}
mode=${1:---dry-run}

public_crates="
hns-encoding
hns-primitives
hns-covenants
hns-dns-relay-protocol
hns-header-consensus
hns-hnsr-protocol
hns-odoh-protocol
hns-p2p-experimental
hns-urkel-proof
hns-transaction
hns-script
hns-mining
hns-swap
hns-p2p-wire
"

assert_private() {
    package=$1
    shift
    if cargo +"$rust_toolchain" publish \
        --dry-run \
        --no-verify \
        --allow-dirty \
        "$@" \
        -p "$package" >/dev/null 2>&1
    then
        echo "error: private package $package passed the publish preflight" >&2
        exit 1
    fi
}

assert_private hns-conformance
assert_private hns-registry-gen
assert_private hns-rs-fuzz --manifest-path fuzz/Cargo.toml

dry_run_package() {
    package=$1
    shift
    cargo +"$rust_toolchain" publish \
        --locked \
        --dry-run \
        --allow-dirty \
        -p "$package" \
        "$@"
}

dry_run_with_local_dependencies() {
    package=$1
    case "$package" in
        hns-encoding|hns-primitives)
            dry_run_package "$package"
            ;;
        hns-covenants|hns-header-consensus)
            dry_run_package "$package" \
                --config 'patch.crates-io.hns-encoding.path="crates/hns-encoding"' \
                --config 'patch.crates-io.hns-primitives.path="crates/hns-primitives"'
            ;;
        hns-dns-relay-protocol|hns-hnsr-protocol|hns-odoh-protocol)
            dry_run_package "$package" \
                --config 'patch.crates-io.hns-encoding.path="crates/hns-encoding"'
            ;;
        hns-p2p-experimental)
            dry_run_package "$package" \
                --config 'patch.crates-io.hns-dns-relay-protocol.path="crates/hns-dns-relay-protocol"' \
                --config 'patch.crates-io.hns-encoding.path="crates/hns-encoding"' \
                --config 'patch.crates-io.hns-primitives.path="crates/hns-primitives"'
            ;;
        hns-urkel-proof)
            dry_run_package "$package" \
                --config 'patch.crates-io.hns-primitives.path="crates/hns-primitives"'
            ;;
        hns-transaction)
            dry_run_package "$package" \
                --config 'patch.crates-io.hns-covenants.path="crates/hns-covenants"' \
                --config 'patch.crates-io.hns-encoding.path="crates/hns-encoding"' \
                --config 'patch.crates-io.hns-primitives.path="crates/hns-primitives"'
            ;;
        hns-script)
            dry_run_package "$package" \
                --config 'patch.crates-io.hns-covenants.path="crates/hns-covenants"' \
                --config 'patch.crates-io.hns-encoding.path="crates/hns-encoding"' \
                --config 'patch.crates-io.hns-transaction.path="crates/hns-transaction"'
            ;;
        hns-mining)
            dry_run_package "$package" \
                --config 'patch.crates-io.hns-covenants.path="crates/hns-covenants"' \
                --config 'patch.crates-io.hns-encoding.path="crates/hns-encoding"' \
                --config 'patch.crates-io.hns-header-consensus.path="crates/hns-header-consensus"' \
                --config 'patch.crates-io.hns-primitives.path="crates/hns-primitives"' \
                --config 'patch.crates-io.hns-transaction.path="crates/hns-transaction"'
            ;;
        hns-swap)
            dry_run_package "$package" \
                --config 'patch.crates-io.hns-covenants.path="crates/hns-covenants"' \
                --config 'patch.crates-io.hns-encoding.path="crates/hns-encoding"' \
                --config 'patch.crates-io.hns-primitives.path="crates/hns-primitives"' \
                --config 'patch.crates-io.hns-script.path="crates/hns-script"' \
                --config 'patch.crates-io.hns-transaction.path="crates/hns-transaction"'
            ;;
        hns-p2p-wire)
            dry_run_package "$package" \
                --config 'patch.crates-io.hns-encoding.path="crates/hns-encoding"' \
                --config 'patch.crates-io.hns-header-consensus.path="crates/hns-header-consensus"' \
                --config 'patch.crates-io.hns-mining.path="crates/hns-mining"' \
                --config 'patch.crates-io.hns-primitives.path="crates/hns-primitives"' \
                --config 'patch.crates-io.hns-transaction.path="crates/hns-transaction"' \
                --config 'patch.crates-io.hns-urkel-proof.path="crates/hns-urkel-proof"'
            ;;
        *)
            echo "error: missing dry-run dependency mapping for $package" >&2
            exit 1
            ;;
    esac
}

case "$mode" in
    --dry-run)
        for package in $public_crates
        do
            dry_run_with_local_dependencies "$package"
        done
        ;;
    --execute)
        if ! git diff --quiet || ! git diff --cached --quiet
        then
            echo "error: refusing to publish from a dirty worktree" >&2
            exit 1
        fi

        cargo_home=${CARGO_HOME:-"$HOME/.cargo"}
        if [ -z "${CARGO_REGISTRY_TOKEN:-}" ] &&
            [ ! -f "$cargo_home/credentials.toml" ]
        then
            echo "error: no crates.io credential found; run cargo login" >&2
            exit 1
        fi

        for package in $public_crates
        do
            package_id=$(cargo +"$rust_toolchain" pkgid -p "$package")
            version=${package_id##*@}
            if [ "$version" = "$package_id" ]
            then
                version=${package_id##*#}
            fi

            status=$(curl \
                --silent \
                --show-error \
                --user-agent "hns-rs-release/0.1 (https://github.com/handshake-rs/hns-rs)" \
                --output /dev/null \
                --write-out '%{http_code}' \
                "https://crates.io/api/v1/crates/$package/$version")

            case "$status" in
                200)
                    echo "skipping $package $version: already published"
                    ;;
                404)
                    cargo +"$rust_toolchain" publish --locked -p "$package"
                    ;;
                *)
                    echo "error: crates.io returned HTTP $status for $package $version" >&2
                    exit 1
                    ;;
            esac
        done
        ;;
    *)
        echo "usage: $0 [--dry-run|--execute]" >&2
        exit 2
        ;;
esac
