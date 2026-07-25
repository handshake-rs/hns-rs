# Draft HIP #76 compatibility

Status: **Denuo Experimental V1 — Not an official Handshake protocol
assignment**.

`hns-dns-relay-protocol` implements the bounded request and response payloads
represented by draft HIP pull request 76 and HSD pull request 958:

- HIP PR 76 at `25f6d99cdd2b766f9eb6bb3b72d9dc804efd6131`;
- HSD PR 958 at `ea31be1554f3235bfa96bdd394e6d33e7dda8080`;
- service bit `0x40000000`;
- request packet `0xf0`, encoded as nonzero `u64` request ID, `u16` DNS length,
  and at most 4096 DNS bytes;
- response packet `0xf1`, encoded as the correlated ID, one defined status,
  `u16` DNS length, and at most 65535 DNS bytes;
- little-endian packet integers and ordinary DNS network byte order;
- complete-input consumption before a message is admitted.

Successful responses require a DNS body. Error responses prohibit one. The wire
transport is untrusted: callers must correlate the DNS message and locally
validate authenticated HNS state, DNSSEC, TLSA, and DANE while ignoring the
relay's AD bit.

Requester support defaults to `Auto`; a persistent opt-out revokes in-flight
generations. A HIP-76 server sees the plaintext qname and performs the outbound
DNS lookup, so it is an output role rather than an opaque intermediary.
Serving that capacity remains a separate operator opt-in.
