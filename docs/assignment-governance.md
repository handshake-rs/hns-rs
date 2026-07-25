# Experimental assignment governance

The canonical registry is append-only within version 1:

- an assigned numeric value is never reused for a different semantic meaning;
- reserved values remain unusable until a new registry version deliberately
  assigns them;
- collisions disable only the affected experimental protocol when ordinary
  Handshake P2P remains safe;
- every status surface names the registry version and fingerprint and states
  that it is not an official assignment;
- changes require deterministic vectors, bounded parsers, and compatibility
  tests before a release uses the new fingerprint.

Draft HIP or HSD pull-request branches are research references. This project
does not update, rewrite, or describe those branches as accepted standards.

