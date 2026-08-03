use hns_primitives::{BlockHash, Height, NameHash};

use crate::{Covenant, CovenantError, CovenantKind, NameState, hash_name, validate_name};

pub const TRANSFER_COVENANT_ITEMS: usize = 4;
pub const FINALIZE_COVENANT_ITEMS: usize = 7;
pub const MIN_TRANSFER_ADDRESS_HASH_SIZE: usize = 2;
pub const MAX_TRANSFER_ADDRESS_HASH_SIZE: usize = 40;

/// Exact fields committed by an HSD `TRANSFER` covenant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferCovenant {
    pub name_hash: NameHash,
    pub start_height: Height,
    pub recipient_version: u8,
    pub recipient_hash: Vec<u8>,
}

impl TransferCovenant {
    pub fn new(
        name_hash: NameHash,
        start_height: Height,
        recipient_version: u8,
        recipient_hash: Vec<u8>,
    ) -> Result<Self, CovenantError> {
        let transfer = Self {
            name_hash,
            start_height,
            recipient_version,
            recipient_hash,
        };
        transfer.validate()?;
        Ok(transfer)
    }

    pub fn validate(&self) -> Result<(), CovenantError> {
        if self.recipient_version > 31 {
            return Err(CovenantError::InvalidTransferCovenant(
                "recipient version exceeds 31",
            ));
        }
        if !(MIN_TRANSFER_ADDRESS_HASH_SIZE..=MAX_TRANSFER_ADDRESS_HASH_SIZE)
            .contains(&self.recipient_hash.len())
        {
            return Err(CovenantError::InvalidTransferCovenant(
                "recipient hash length is outside 2..=40",
            ));
        }
        Ok(())
    }

    pub fn to_covenant(&self) -> Result<Covenant, CovenantError> {
        self.validate()?;
        Ok(Covenant {
            kind: CovenantKind::Transfer,
            items: vec![
                self.name_hash.into_bytes().to_vec(),
                self.start_height.get().to_le_bytes().to_vec(),
                vec![self.recipient_version],
                self.recipient_hash.clone(),
            ],
        })
    }
}

impl TryFrom<&Covenant> for TransferCovenant {
    type Error = CovenantError;

    fn try_from(covenant: &Covenant) -> Result<Self, Self::Error> {
        if covenant.kind != CovenantKind::Transfer {
            return Err(CovenantError::InvalidTransferCovenant(
                "covenant kind is not TRANSFER",
            ));
        }
        let [name_hash, start_height, recipient_version, recipient_hash] =
            covenant.items.as_slice()
        else {
            return Err(CovenantError::InvalidTransferCovenant(
                "expected exactly four items",
            ));
        };
        if recipient_version.len() != 1 {
            return Err(CovenantError::InvalidTransferCovenant(
                "recipient version is not one byte",
            ));
        }
        if !(MIN_TRANSFER_ADDRESS_HASH_SIZE..=MAX_TRANSFER_ADDRESS_HASH_SIZE)
            .contains(&recipient_hash.len())
        {
            return Err(CovenantError::InvalidTransferCovenant(
                "recipient hash length is outside 2..=40",
            ));
        }
        let transfer = Self {
            name_hash: NameHash::new(name_hash.as_slice().try_into().map_err(|_| {
                CovenantError::InvalidTransferCovenant("name hash is not 32 bytes")
            })?),
            start_height: Height::new(u32::from_le_bytes(
                start_height.as_slice().try_into().map_err(|_| {
                    CovenantError::InvalidTransferCovenant("start height is not four bytes")
                })?,
            )),
            recipient_version: recipient_version[0],
            recipient_hash: recipient_hash.clone(),
        };
        transfer.validate()?;
        Ok(transfer)
    }
}

/// Exact fields committed by an HSD `FINALIZE` covenant.
///
/// Construction and strict parsing require the raw name to hash to
/// `name_hash`, preventing a consumer from accepting internally inconsistent
/// FINALIZE metadata even though the generic covenant codec remains lossless.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinalizeCovenant {
    pub name_hash: NameHash,
    pub start_height: Height,
    pub name: Vec<u8>,
    /// HSD currently consumes bit zero as the weak-claim flag. Other bits are
    /// retained when parsing consensus-valid historical covenants.
    pub flags: u8,
    pub claimed: Height,
    pub renewals: u32,
    pub renewal_block: BlockHash,
}

impl FinalizeCovenant {
    pub fn new(
        name: Vec<u8>,
        start_height: Height,
        weak: bool,
        claimed: Height,
        renewals: u32,
        renewal_block: BlockHash,
    ) -> Result<Self, CovenantError> {
        let name_hash = hash_name(&name)?;
        let finalize = Self {
            name_hash,
            start_height,
            name,
            flags: u8::from(weak),
            claimed,
            renewals,
            renewal_block,
        };
        finalize.validate()?;
        Ok(finalize)
    }

    pub fn from_name_state(
        state: &NameState,
        renewal_block: BlockHash,
    ) -> Result<Self, CovenantError> {
        if state.is_null() {
            return Err(CovenantError::InvalidFinalizeCovenant(
                "name state is null",
            ));
        }
        state.validate_key_binding()?;
        let finalize = Self {
            name_hash: state.name_hash,
            start_height: state.height,
            name: state.name.clone(),
            flags: u8::from(state.weak),
            claimed: state.claimed,
            renewals: state.renewals,
            renewal_block,
        };
        finalize.validate()?;
        Ok(finalize)
    }

    pub const fn weak(&self) -> bool {
        self.flags & 1 != 0
    }

    pub fn validate(&self) -> Result<(), CovenantError> {
        if !validate_name(&self.name) {
            return Err(CovenantError::InvalidName);
        }
        if hash_name(&self.name)? != self.name_hash {
            return Err(CovenantError::FinalizeNameHashMismatch);
        }
        Ok(())
    }

    pub fn to_covenant(&self) -> Result<Covenant, CovenantError> {
        self.validate()?;
        Ok(Covenant {
            kind: CovenantKind::Finalize,
            items: vec![
                self.name_hash.into_bytes().to_vec(),
                self.start_height.get().to_le_bytes().to_vec(),
                self.name.clone(),
                vec![self.flags],
                self.claimed.get().to_le_bytes().to_vec(),
                self.renewals.to_le_bytes().to_vec(),
                self.renewal_block.into_bytes().to_vec(),
            ],
        })
    }
}

impl TryFrom<&Covenant> for FinalizeCovenant {
    type Error = CovenantError;

    fn try_from(covenant: &Covenant) -> Result<Self, Self::Error> {
        if covenant.kind != CovenantKind::Finalize {
            return Err(CovenantError::InvalidFinalizeCovenant(
                "covenant kind is not FINALIZE",
            ));
        }
        let [name_hash, start_height, name, flags, claimed, renewals, renewal_block] =
            covenant.items.as_slice()
        else {
            return Err(CovenantError::InvalidFinalizeCovenant(
                "expected exactly seven items",
            ));
        };
        if flags.len() != 1 {
            return Err(CovenantError::InvalidFinalizeCovenant(
                "flags field is not one byte",
            ));
        }
        if !validate_name(name) {
            return Err(CovenantError::InvalidName);
        }
        let parsed_name_hash = NameHash::new(name_hash.as_slice().try_into().map_err(|_| {
            CovenantError::InvalidFinalizeCovenant("name hash is not 32 bytes")
        })?);
        if hash_name(name)? != parsed_name_hash {
            return Err(CovenantError::FinalizeNameHashMismatch);
        }
        let finalize = Self {
            name_hash: parsed_name_hash,
            start_height: Height::new(u32::from_le_bytes(
                start_height.as_slice().try_into().map_err(|_| {
                    CovenantError::InvalidFinalizeCovenant("start height is not four bytes")
                })?,
            )),
            name: name.clone(),
            flags: flags[0],
            claimed: Height::new(u32::from_le_bytes(claimed.as_slice().try_into().map_err(
                |_| CovenantError::InvalidFinalizeCovenant("claim height is not four bytes"),
            )?)),
            renewals: u32::from_le_bytes(renewals.as_slice().try_into().map_err(|_| {
                CovenantError::InvalidFinalizeCovenant("renewal count is not four bytes")
            })?),
            renewal_block: BlockHash::new(renewal_block.as_slice().try_into().map_err(|_| {
                CovenantError::InvalidFinalizeCovenant("renewal block hash is not 32 bytes")
            })?),
        };
        finalize.validate()?;
        Ok(finalize)
    }
}

#[cfg(test)]
mod tests {
    use hns_primitives::{Dollarydoos, Outpoint};

    use super::*;

    #[test]
    fn transfer_and_finalize_fields_round_trip_exactly() {
        let transfer = TransferCovenant::new(
            NameHash::new([1; 32]),
            Height::new(2),
            0,
            vec![3; 20],
        )
        .expect("transfer");
        assert_eq!(
            TransferCovenant::try_from(&transfer.to_covenant().expect("covenant"))
                .expect("parsed"),
            transfer
        );

        let name = b"handshake".to_vec();
        let finalize = FinalizeCovenant::new(
            name,
            Height::new(4),
            true,
            Height::new(5),
            6,
            BlockHash::new([7; 32]),
        )
        .expect("finalize");
        assert_eq!(
            FinalizeCovenant::try_from(&finalize.to_covenant().expect("covenant"))
                .expect("parsed"),
            finalize
        );
    }

    #[test]
    fn name_state_finalize_projection_binds_the_authenticated_name() {
        let name = b"handshake".to_vec();
        let name_hash = hash_name(&name).expect("name hash");
        let mut state = NameState::null(name_hash);
        state.name = name;
        state.height = Height::new(2);
        state.owner = Outpoint::default();
        state.value = Dollarydoos::new(1);
        let finalize = FinalizeCovenant::from_name_state(&state, BlockHash::new([3; 32]))
            .expect("finalize");
        assert_eq!(finalize.name_hash, name_hash);

        state.name.push(b'x');
        assert!(FinalizeCovenant::from_name_state(&state, BlockHash::new([3; 32])).is_err());
    }
}
