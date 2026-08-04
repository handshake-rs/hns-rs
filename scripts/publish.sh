#!/usr/bin/env sh
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_root"

rust_toolchain=${RUST_TOOLCHAIN:-1.89.0}
mode=${1:---dry-run}
requested_package=${2:-}
release_commit=$(git rev-parse HEAD)
release_tmp=

cleanup_release_tmp() {
    if [ -n "$release_tmp" ] && [ -d "$release_tmp" ]
    then
        rm -rf -- "$release_tmp"
    fi
}

trap cleanup_release_tmp EXIT HUP INT TERM

public_crates="
hns-encoding
hns-primitives
hns-covenants
hns-dns-relay-protocol
hns-header-consensus
hns-service-authority
hns-odoh-protocol
hns-p2p-experimental
hns-urkel-proof
hns-transaction
hns-chat-protocol
hns-hnsr-protocol
hns-script
hns-mining
hns-swap
hns-marketplace-protocol
hns-p2p-wire
"

require_public_crate() {
    requested=$1
    for package in $public_crates
    do
        if [ "$package" = "$requested" ]
        then
            return
        fi
    done
    echo "error: $requested is not in the public package allowlist" >&2
    exit 2
}

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

assert_private_packages() {
    assert_private hns-conformance
    assert_private hns-registry-gen
    assert_private hns-rs-fuzz --manifest-path fuzz/Cargo.toml
}

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
        hns-dns-relay-protocol|hns-service-authority|hns-odoh-protocol)
            dry_run_package "$package" \
                --config 'patch.crates-io.hns-encoding.path="crates/hns-encoding"'
            ;;
        hns-chat-protocol)
            dry_run_package "$package" \
                --config 'patch.crates-io.hns-covenants.path="crates/hns-covenants"' \
                --config 'patch.crates-io.hns-encoding.path="crates/hns-encoding"' \
                --config 'patch.crates-io.hns-primitives.path="crates/hns-primitives"' \
                --config 'patch.crates-io.hns-service-authority.path="crates/hns-service-authority"' \
                --config 'patch.crates-io.hns-transaction.path="crates/hns-transaction"'
            ;;
        hns-hnsr-protocol)
            dry_run_package "$package" \
                --config 'patch.crates-io.hns-chat-protocol.path="crates/hns-chat-protocol"' \
                --config 'patch.crates-io.hns-covenants.path="crates/hns-covenants"' \
                --config 'patch.crates-io.hns-encoding.path="crates/hns-encoding"' \
                --config 'patch.crates-io.hns-primitives.path="crates/hns-primitives"' \
                --config 'patch.crates-io.hns-service-authority.path="crates/hns-service-authority"' \
                --config 'patch.crates-io.hns-transaction.path="crates/hns-transaction"'
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
                --config 'patch.crates-io.hns-primitives.path="crates/hns-primitives"' \
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
        hns-marketplace-protocol)
            dry_run_package "$package" \
                --config 'patch.crates-io.hns-covenants.path="crates/hns-covenants"' \
                --config 'patch.crates-io.hns-encoding.path="crates/hns-encoding"' \
                --config 'patch.crates-io.hns-p2p-experimental.path="crates/hns-p2p-experimental"' \
                --config 'patch.crates-io.hns-primitives.path="crates/hns-primitives"' \
                --config 'patch.crates-io.hns-script.path="crates/hns-script"' \
                --config 'patch.crates-io.hns-swap.path="crates/hns-swap"' \
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

package_version() {
    package=$1
    package_id=$(cargo +"$rust_toolchain" pkgid -p "$package")
    version=${package_id##*@}
    if [ "$version" = "$package_id" ]
    then
        version=${package_id##*#}
    fi
    printf '%s\n' "$version"
}

verify_chat_source_package() {
    package=hns-chat-protocol
    version=$(package_version "$package")
    package_target=${CARGO_TARGET_DIR:-target}
    archive="$package_target/package/$package-$version.crate"
    archive_root="$package-$version"

    if [ ! -f "$archive" ]
    then
        echo "error: Cargo did not create $archive" >&2
        exit 1
    fi

    archive_entries=$(tar -tf "$archive")
    for relative_path in \
        .cargo_vcs_info.json \
        Cargo.toml \
        Cargo.toml.orig \
        LICENSE-APACHE \
        LICENSE-MIT \
        README.md \
        fixtures/chat-v1/hns-chat-resource-v1.txt \
        fixtures/chat-v1/hns-chat-resource-v1.txt.sha256 \
        src/binding.rs \
        src/lib.rs \
        src/owner.rs \
        src/wire.rs \
        tests/release_source.rs
    do
        if ! printf '%s\n' "$archive_entries" | grep -Fqx "$archive_root/$relative_path"
        then
            echo "error: normalized $package package omits $relative_path" >&2
            exit 1
        fi
    done

    normalized_manifest=$(tar -xOf "$archive" "$archive_root/Cargo.toml")
    # Normalized manifests legitimately retain target paths under [lib],
    # [[test]], [[example]], and [[bench]]. Only dependency-table paths make
    # the source package depend on a sibling checkout.
    if printf '%s\n' "$normalized_manifest" |
        awk '
            /^[[:space:]]*\[/ {
                header = $0
                gsub(/[[:space:]]/, "", header)
                in_dependency_table = \
                    header ~ /^\[(dependencies|dev-dependencies|build-dependencies)(\.[^]]+)?\]$/ || \
                    header ~ /^\[target\..+\.(dependencies|dev-dependencies|build-dependencies)(\.[^]]+)?\]$/ || \
                    header ~ /^\[workspace\.(dependencies|dev-dependencies|build-dependencies)(\.[^]]+)?\]$/
                next
            }
            in_dependency_table && /(^|[[:space:]{,])path[[:space:]]*=/ {
                found = 1
                exit
            }
            END { exit found ? 0 : 1 }
        '
    then
        echo "error: normalized $package manifest retains a path dependency" >&2
        exit 1
    fi

    expected_digest=$(tar -xOf \
        "$archive" \
        "$archive_root/fixtures/chat-v1/hns-chat-resource-v1.txt.sha256" |
        awk 'NR == 1 { print $1 }')
    actual_digest=$(tar -xOf \
        "$archive" \
        "$archive_root/fixtures/chat-v1/hns-chat-resource-v1.txt" |
        sha256sum |
        awk '{ print $1 }')
    if [ "$actual_digest" != "$expected_digest" ]
    then
        echo "error: packaged HNS Chat vectors do not match their SHA-256 sidecar" >&2
        exit 1
    fi
}

verify_source_package() {
    package=$1
    case "$package" in
        hns-chat-protocol) verify_chat_source_package ;;
    esac
}

verify_published_package() {
    package=$1
    version=$2
    package_target=${CARGO_TARGET_DIR:-target}
    local_archive="$package_target/package/$package-$version.crate"

    cargo +"$rust_toolchain" package --locked --no-verify -p "$package"
    if [ ! -f "$local_archive" ]
    then
        echo "error: Cargo did not create $local_archive" >&2
        exit 1
    fi

    if [ -z "$release_tmp" ]
    then
        release_tmp=$(mktemp -d "${TMPDIR:-/tmp}/hns-rs-release.XXXXXX")
    fi
    published_archive="$release_tmp/$package-$version.crate"
    curl \
        --fail \
        --location \
        --silent \
        --show-error \
        --user-agent "hns-rs-release/0.2 (https://github.com/handshake-rs/hns-rs)" \
        --output "$published_archive" \
        "https://crates.io/api/v1/crates/$package/$version/download"

    local_checksum=$(sha256sum "$local_archive" | awk '{print $1}')
    published_checksum=$(sha256sum "$published_archive" | awk '{print $1}')
    if [ "$local_checksum" != "$published_checksum" ]
    then
        echo "error: published $package $version differs from the current source package" >&2
        echo "error: local checksum $local_checksum; published checksum $published_checksum" >&2
        exit 1
    fi

    for archive in "$local_archive" "$published_archive"
    do
        vcs_info=$(tar -xOf "$archive" "$package-$version/.cargo_vcs_info.json")
        compact_vcs_info=$(printf '%s' "$vcs_info" | tr -d '[:space:]')
        case "$compact_vcs_info" in
            *\"sha1\":\"$release_commit\"*) ;;
            *)
                echo "error: $archive does not identify release commit $release_commit" >&2
                exit 1
                ;;
        esac
    done
}

case "$mode" in
    --dry-run)
        if [ -n "$requested_package" ]
        then
            require_public_crate "$requested_package"
            dry_run_with_local_dependencies "$requested_package"
            verify_source_package "$requested_package"
        else
            assert_private_packages
            for package in $public_crates
            do
                dry_run_with_local_dependencies "$package"
                verify_source_package "$package"
            done
        fi
        ;;
    --execute)
        if [ -n "$requested_package" ]
        then
            echo "error: execution does not accept a partial package selection" >&2
            exit 2
        fi
        assert_private_packages
        if [ -n "$(git status --porcelain)" ]
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
            version=$(package_version "$package")

            status=$(curl \
                --silent \
                --show-error \
                --user-agent "hns-rs-release/0.2 (https://github.com/handshake-rs/hns-rs)" \
                --output /dev/null \
                --write-out '%{http_code}' \
                "https://crates.io/api/v1/crates/$package/$version")

            case "$status" in
                200)
                    verify_published_package "$package" "$version"
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
        echo "usage: $0 [--dry-run [PUBLIC-PACKAGE]|--execute]" >&2
        exit 2
        ;;
esac
