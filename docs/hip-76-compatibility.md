# Draft HIP #76 compatibility

Status: **Denuo Experimental V1 — Not an official Handshake protocol
assignment**.

`hns-dns-relay-protocol` implements the bounded request and response payloads
represented by draft HIP pull request 76 and HSD pull request 958:

- HIP PR 76 at `25f6d99cdd2b766f9eb6bb3b72d9dc804efd6131`;
- HSD PR 958 at `ea31be1554f3235bfa96bdd394e6d33e7dda8080`;
- service bit `0x40000000`;
- request packet `0xf0`, encoded as nonzero `u64` request ID, `u16` DNS length,
  and at most 4096 DNS body bytes (4106 bytes for the complete payload);
- response packet `0xf1`, encoded as the correlated ID, one defined status,
  `u16` DNS length, and at most 65535 DNS body bytes (65546 bytes for the
  complete payload);
- semantic protocol version `1`, exported as `HIP_76_PROTOCOL_VERSION` and
  bound by tests to both canonical packet assignments;
- little-endian packet integers and ordinary DNS network byte order;
- complete-input consumption before a message is admitted.

The canonical registry's `maximum_payload` fields for `getdnsrelay` and
`dnsrelay` retain the draft's DNS-body maxima (4096 and 65535). Consumers that
bound a complete Handshake packet payload must instead use
`MAX_DNS_RELAY_REQUEST_PAYLOAD_SIZE` and
`MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE`.

Successful responses require a DNS body. Error responses prohibit one. The wire
transport is untrusted: callers must correlate the DNS message and locally
validate authenticated HNS state, DNSSEC, TLSA, and DANE while ignoring the
relay's AD bit.

Requester support defaults to `Auto`; a persistent opt-out revokes in-flight
generations. A HIP-76 server sees the plaintext qname and performs the outbound
DNS lookup, so it is an output role rather than an opaque intermediary.
Serving that capacity remains a separate operator opt-in.

Direction-aware peer admission preserves that boundary:

- `admit_outbound_dns_relay_request` requires an enabled requester policy,
  remote provider service advertisement, and canonical registry negotiation;
- `admit_inbound_dns_relay_request` does not require the requester to advertise
  a provider service. It requires the narrow `DnsRelayOutputPolicy` opt-in,
  local service and registry advertisement, backend readiness, and peer
  registry negotiation.

The compatibility `admit_packet` API treats `getdnsrelay` as outbound and
`dnsrelay` as inbound, matching its historical remote-provider check. It is not
authoritative for inbound HIP-76 requests. Response correlation, request
generation, deadlines, and DNS question matching belong to the live session
layer, which must use `RequestTracker` and current policy generations.

`TransportPolicy` stores opaque forwarding and output authority separately:
`OpaqueRelayRoles::default()` enables only the ODoH proxy, while
`OutputRoles::default()` enables no output. HNSR requester/client and opaque
relay roles retain independent default-on settings inside `HnsrPolicy`; its
endpoint/output role remains off. The legacy mixed `ProviderRoles` value exists
only to migrate old configuration and is not accepted by admission APIs.
