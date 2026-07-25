#!/usr/bin/env sh
set -eu

cargo test -p hns-conformance deterministic_mutation_smoke_exercises_every_parser_without_panics
