use hns_service_authority::AuthorityRecord;
use hns_transaction::Output;
use k256::ecdsa::VerifyingKey;

use crate::{ChatIdentityBindingV1, ChatProtocolError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChatIdentityTrust {
    ResourceAuthenticated,
    CurrentOwnerVerified,
    StaleOwner,
    UnsupportedOwnerScript,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedOwnerBindingV1 {
    binding: ChatIdentityBindingV1,
    original_compressed_public_key: [u8; 33],
    trust: ChatIdentityTrust,
}

impl VerifiedOwnerBindingV1 {
    pub const fn binding(&self) -> ChatIdentityBindingV1 {
        self.binding
    }

    pub const fn original_compressed_public_key(&self) -> [u8; 33] {
        self.original_compressed_public_key
    }

    pub const fn trust(&self) -> ChatIdentityTrust {
        self.trust
    }
}

pub fn xonly_from_compressed_public_key(key: &[u8; 33]) -> Result<[u8; 32], ChatProtocolError> {
    if !matches!(key[0], 0x02 | 0x03) || VerifyingKey::from_sec1_bytes(key).is_err() {
        return Err(ChatProtocolError::Invalid(
            "invalid compressed secp256k1 public key",
        ));
    }
    let mut xonly = [0_u8; 32];
    xonly.copy_from_slice(&key[1..]);
    Ok(xonly)
}

pub fn resolve_compressed_owner_key(
    owner_output: &Output,
    xonly_public_key: &[u8; 32],
) -> Result<[u8; 33], ChatProtocolError> {
    if owner_output.address.version != 0 || owner_output.address.hash.len() != 20 {
        return Err(ChatProtocolError::UnsupportedOwnerScript);
    }

    let mut even_candidate = [0_u8; 33];
    even_candidate[0] = 0x02;
    even_candidate[1..].copy_from_slice(xonly_public_key);
    VerifyingKey::from_sec1_bytes(&even_candidate)
        .map_err(|_| ChatProtocolError::Invalid("invalid secp256k1 x-only public key"))?;

    let mut matched = None;
    for parity in [0x02, 0x03] {
        let mut candidate = [0_u8; 33];
        candidate[0] = parity;
        candidate[1..].copy_from_slice(xonly_public_key);
        if VerifyingKey::from_sec1_bytes(&candidate).is_err() {
            continue;
        }
        let candidate_address = hns_transaction::Address::from_compressed_public_key(&candidate)
            .map_err(|_| ChatProtocolError::Invalid("owner public key cannot form an address"))?;
        if candidate_address.version == owner_output.address.version
            && candidate_address.hash == owner_output.address.hash
            && matched.replace(candidate).is_some()
        {
            return Err(ChatProtocolError::AmbiguousOwnerKey);
        }
    }
    matched.ok_or(ChatProtocolError::StaleOwner)
}

pub fn verify_current_owner_binding(
    binding: &ChatIdentityBindingV1,
    owner_output: &Output,
) -> Result<VerifiedOwnerBindingV1, ChatProtocolError> {
    binding.validate()?;
    let original_compressed_public_key =
        resolve_compressed_owner_key(owner_output, &binding.xonly_public_key)?;
    Ok(VerifiedOwnerBindingV1 {
        binding: *binding,
        original_compressed_public_key,
        trust: ChatIdentityTrust::CurrentOwnerVerified,
    })
}

pub fn owner_authority_record(
    verified: &VerifiedOwnerBindingV1,
) -> Result<AuthorityRecord, ChatProtocolError> {
    if verified.trust != ChatIdentityTrust::CurrentOwnerVerified
        || verified.binding.generation == 0
        || xonly_from_compressed_public_key(&verified.original_compressed_public_key)?
            != verified.binding.xonly_public_key
    {
        return Err(ChatProtocolError::Invalid(
            "owner authority requires a current verified binding",
        ));
    }
    Ok(AuthorityRecord {
        root_key: verified.original_compressed_public_key,
        epoch: verified.binding.generation,
    })
}

#[cfg(test)]
mod tests {
    use hns_covenants::{Covenant, CovenantKind};
    use hns_primitives::Dollarydoos;
    use k256::ecdsa::SigningKey;

    use super::*;

    fn owner_output(public_key: &[u8; 33]) -> Output {
        Output {
            value: Dollarydoos::new(1),
            address: hns_transaction::Address::from_compressed_public_key(public_key)
                .expect("address"),
            covenant: Covenant {
                kind: CovenantKind::Update,
                items: Vec::new(),
            },
        }
    }

    fn public_key(private_key: [u8; 32]) -> [u8; 33] {
        SigningKey::from_bytes((&private_key).into())
            .expect("private key")
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed key")
    }

    #[test]
    fn both_original_owner_parities_are_recovered_without_normalization() {
        let mut seen_even = false;
        let mut seen_odd = false;
        for scalar in 1_u8..=32 {
            let mut private_key = [0_u8; 32];
            private_key[31] = scalar;
            let compressed = public_key(private_key);
            seen_even |= compressed[0] == 0x02;
            seen_odd |= compressed[0] == 0x03;
            let binding = ChatIdentityBindingV1 {
                key_mode: crate::ChatKeyMode::Owner,
                xonly_public_key: xonly_from_compressed_public_key(&compressed).expect("x-only"),
                generation: u32::from(scalar),
            };
            let verified = verify_current_owner_binding(&binding, &owner_output(&compressed))
                .expect("current owner");
            assert_eq!(verified.original_compressed_public_key(), compressed);
            assert_eq!(
                owner_authority_record(&verified).expect("authority"),
                AuthorityRecord {
                    root_key: compressed,
                    epoch: u32::from(scalar),
                }
            );
            if seen_even && seen_odd {
                break;
            }
        }
        assert!(seen_even && seen_odd, "test keys must cover both parities");
    }

    #[test]
    fn stale_and_script_controlled_owner_outputs_are_rejected() {
        let key = public_key([1; 32]);
        let other_key = public_key([2; 32]);
        assert_eq!(
            resolve_compressed_owner_key(
                &owner_output(&other_key),
                &xonly_from_compressed_public_key(&key).expect("x-only")
            ),
            Err(ChatProtocolError::StaleOwner)
        );
        let mut script_owner = owner_output(&key);
        script_owner.address = hns_transaction::Address::new(0, vec![1; 32]).expect("P2WSH");
        assert_eq!(
            resolve_compressed_owner_key(
                &script_owner,
                &xonly_from_compressed_public_key(&key).expect("x-only")
            ),
            Err(ChatProtocolError::UnsupportedOwnerScript)
        );
    }

    #[test]
    fn invalid_x_coordinate_is_rejected() {
        let key = public_key([3; 32]);
        assert!(resolve_compressed_owner_key(&owner_output(&key), &[0xff; 32]).is_err());
    }
}
