# Pinned HSD fixtures

This directory holds exact differential inputs generated from the HSD revision
recorded in `docs/protocol-authority.md`.

`name-state-resource-v1.txt` contains HSD-emitted NameState value bytes and a
version-zero resource containing every assigned record type plus DNS name
compression. The adjacent `.sha256` authenticates the complete document.
Regenerate or compare it against an already-present pinned HSD source tree:

```bash
NODE_BACKEND=js node generators/generate-hsd-name-state-vectors.js --write /path/to/hsd
NODE_BACKEND=js node generators/generate-hsd-name-state-vectors.js --check /path/to/hsd
```

The generator verifies the expected HSD version and the SHA-256 hashes of the
NameState, resource, and BNS name-encoding implementations before loading the
oracle. It does not fetch HSD or any dependency.
