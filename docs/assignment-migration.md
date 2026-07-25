# Assignment migration

Application code addresses services and packets by semantic identity through
`WireAssignments`; persisted offers, routes, and policies never store a raw
packet number as their meaning.

If official Handshake assignments become available:

1. add an `Official(version)` assignment map backed by published authority;
2. negotiate the selected profile and write only that profile on a connection;
3. accept old and new profiles during a documented transition window;
4. add cross-profile vectors and retain rollback support;
5. deprecate, but never repurpose, Denuo v1 values;
6. migrate persisted semantic objects without rewriting their meaning.

`Auto` may select an official profile only when the implementation knows its
complete assignment map and the peer negotiates it. Unknown official versions
fail closed.

