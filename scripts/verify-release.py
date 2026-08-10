#!/usr/bin/env python3
"""Cheap, deterministic validation of the hns-rs release graph and metadata."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tomllib
from datetime import date
from pathlib import Path


REPOSITORY = "https://github.com/handshake-rs/hns-rs"
PRIVATE_PACKAGES = {"hns-conformance", "hns-registry-gen"}


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


def cargo_metadata(repo: Path, toolchain: str, manifest: str | None = None) -> dict:
    command = [
        "cargo",
        f"+{toolchain}",
        "metadata",
        "--locked",
        "--no-deps",
        "--format-version",
        "1",
    ]
    if manifest is not None:
        command.extend(["--manifest-path", manifest])
    result = subprocess.run(
        command,
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        fail(f"Cargo metadata failed for {manifest or 'the release workspace'}")
    return json.loads(result.stdout)


def release_order(repo: Path) -> list[str]:
    path = repo / "release/public-crates.txt"
    packages = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not packages:
        fail(f"{path.relative_to(repo)} is empty")
    if len(packages) != len(set(packages)):
        fail(f"{path.relative_to(repo)} contains a duplicate package")
    for package in packages:
        if re.fullmatch(r"hns-[a-z0-9-]+", package) is None:
            fail(f"invalid public package name {package!r}")
    return packages


def verify_release_document(repo: Path, order: list[str], version: str) -> None:
    document = (repo / "docs/releasing.md").read_text(encoding="utf-8")
    documented = re.findall(r"^\d+\. `([^`]+)`$", document, flags=re.MULTILINE)
    if documented != order:
        fail("docs/releasing.md does not match release/public-crates.txt")
    execute_command = f"./scripts/publish.sh --execute --confirm-publish {version}"
    if document.count(execute_command) != 2:
        fail("docs/releasing.md does not use the current version in execute examples")

    publish_script = (repo / "scripts/publish.sh").read_text(encoding="utf-8")
    interval_match = re.search(
        r"^publish_interval_seconds=\$\{PUBLISH_INTERVAL_SECONDS-(\d+)\}$",
        publish_script,
        re.MULTILINE,
    )
    if interval_match is None:
        fail("scripts/publish.sh has no validated publication interval default")
    default_interval = interval_match.group(1)
    if f"{default_interval}-second" not in document:
        fail("docs/releasing.md omits the publication interval default")
    if f"PUBLISH_INTERVAL_SECONDS={default_interval}" not in document:
        fail("docs/releasing.md cooldown example differs from the script default")


def verify_workspace(repo: Path, metadata: dict, order: list[str]) -> tuple[str, str]:
    root_manifest = tomllib.loads((repo / "Cargo.toml").read_text(encoding="utf-8"))
    workspace_package = root_manifest["workspace"]["package"]
    version = workspace_package["version"]
    expected_publish = ["crates-io"]

    packages = {package["name"]: package for package in metadata["packages"]}
    missing = set(order) - packages.keys()
    if missing:
        fail(f"release allowlist names missing workspace packages: {sorted(missing)}")

    publishable = {
        package["name"]
        for package in metadata["packages"]
        if package.get("publish") != []
    }
    if publishable != set(order):
        fail(
            "publishable workspace packages differ from the release allowlist: "
            f"workspace={sorted(publishable)}, allowlist={sorted(order)}"
        )

    private = {
        package["name"]
        for package in metadata["packages"]
        if package.get("publish") == []
    }
    if private != PRIVATE_PACKAGES:
        fail(
            "private workspace packages differ from the expected set: "
            f"workspace={sorted(private)}, expected={sorted(PRIVATE_PACKAGES)}"
        )

    changelog = (repo / "CHANGELOG.md").read_text(encoding="utf-8")
    headings = re.findall(
        rf"^## {re.escape(version)} - (unreleased|\d{{4}}-\d{{2}}-\d{{2}})$",
        changelog,
        re.MULTILINE,
    )
    if len(headings) != 1:
        fail(
            f"CHANGELOG.md must contain exactly one {version} unreleased or dated heading"
        )
    release_label = headings[0]
    if release_label != "unreleased":
        try:
            date.fromisoformat(release_label)
        except ValueError:
            fail(f"CHANGELOG.md has an invalid release date {release_label!r}")
    expected_heading = f"## {version} - {release_label}"

    template = (repo / "release/CRATE-CHANGELOG.md").read_bytes()
    template_text = template.decode("utf-8")
    if expected_heading not in template_text:
        fail("release/CRATE-CHANGELOG.md does not match the workspace release heading")
    stable_changelog_url = (
        f"https://github.com/handshake-rs/hns-rs/blob/v{version}/CHANGELOG.md"
    )
    if stable_changelog_url not in template_text:
        fail("release/CRATE-CHANGELOG.md does not link the immutable release tag")

    positions = {package: index for index, package in enumerate(order)}
    for name in order:
        package = packages[name]
        package_root = Path(package["manifest_path"]).resolve().parent
        expected_root = (repo / "crates" / name).resolve()
        if package_root != expected_root:
            fail(f"{name} manifest is outside crates/{name}")
        if package["version"] != version:
            fail(f"{name} version {package['version']} differs from workspace {version}")
        if package.get("publish") != expected_publish:
            fail(f"{name} must publish only to crates-io")
        required_values = {
            "description": package.get("description"),
            "license": package.get("license"),
            "repository": package.get("repository"),
            "documentation": package.get("documentation"),
            "readme": package.get("readme"),
            "rust_version": package.get("rust_version"),
        }
        missing_values = [field for field, value in required_values.items() if not value]
        if missing_values:
            fail(f"{name} is missing crates.io metadata: {', '.join(missing_values)}")
        if package["license"] != workspace_package["license"]:
            fail(f"{name} license differs from [workspace.package]")
        if package["repository"] != REPOSITORY:
            fail(f"{name} repository is not {REPOSITORY}")
        if package["documentation"] != f"https://docs.rs/{name}":
            fail(f"{name} has a noncanonical docs.rs URL")
        if package["rust_version"] != workspace_package["rust-version"]:
            fail(f"{name} rust-version differs from [workspace.package]")
        if package["edition"] != workspace_package["edition"]:
            fail(f"{name} edition differs from [workspace.package]")
        if package.get("keywords") != workspace_package["keywords"]:
            fail(f"{name} keywords differ from [workspace.package]")
        if package.get("categories") != workspace_package["categories"]:
            fail(f"{name} categories differ from [workspace.package]")

        readme = package_root / package["readme"]
        if not readme.is_file() or not readme.read_text(encoding="utf-8").strip():
            fail(f"{name} readme is missing or empty")
        for license_name in ("LICENSE-APACHE", "LICENSE-MIT"):
            package_license = (package_root / license_name).read_bytes()
            workspace_license = (repo / license_name).read_bytes()
            if package_license != workspace_license:
                fail(f"{name} {license_name} differs from the workspace license")
        if (package_root / "CHANGELOG.md").read_bytes() != template:
            fail(f"{name} CHANGELOG.md differs from release/CRATE-CHANGELOG.md")

        for dependency in package["dependencies"]:
            dependency_name = dependency["name"]
            if dependency_name not in packages:
                continue
            if dependency_name not in positions:
                fail(f"public package {name} depends on private workspace package {dependency_name}")
            expected_requirement = f"^{version}"
            if dependency["req"] != expected_requirement:
                fail(
                    f"{name} requires internal {dependency_name} at {dependency['req']}, "
                    f"expected {expected_requirement}"
                )
            if positions[dependency_name] >= positions[name]:
                fail(f"{dependency_name} must precede dependent package {name}")

    return version, release_label


def verify_fuzz_private(repo: Path, toolchain: str) -> None:
    metadata = cargo_metadata(repo, toolchain, "fuzz/Cargo.toml")
    packages = {package["name"]: package for package in metadata["packages"]}
    fuzz = packages.get("hns-rs-fuzz")
    if fuzz is None or fuzz.get("publish") != []:
        fail("hns-rs-fuzz must remain private")


def verify_clean_source(repo: Path) -> None:
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    if result.stdout:
        fail("execution requires a clean worktree")
    subprocess.run(
        ["git", "rev-parse", "--verify", "HEAD^{commit}"],
        cwd=repo,
        check=True,
        stdout=subprocess.DEVNULL,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--toolchain", default="1.89.0")
    parser.add_argument("--require-clean", action="store_true")
    parser.add_argument("--expected-version")
    args = parser.parse_args()

    repo = Path(__file__).resolve().parent.parent
    order = release_order(repo)
    version, release_label = verify_workspace(
        repo, cargo_metadata(repo, args.toolchain), order
    )
    verify_release_document(repo, order, version)
    verify_fuzz_private(repo, args.toolchain)
    if args.expected_version is not None and args.expected_version != version:
        fail(
            f"confirmed version {args.expected_version} differs from workspace version {version}"
        )
    if args.require_clean:
        if release_label == "unreleased":
            fail("execution requires a dated release heading, not 'unreleased'")
        verify_clean_source(repo)
    print(f"release metadata valid for {len(order)} public crates at version {version}")


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, tomllib.TOMLDecodeError) as error:
        fail(str(error))
