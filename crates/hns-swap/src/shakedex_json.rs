//! Shakedex v2 auction JSON.
//!
//! This is the listing format LearnHNS Market serves (`/listing/<name>/proof.json`),
//! Bob Wallet imports, and the shakedex CLI writes: one JSON object per
//! auction, carrying the lock outpoint, seller key, payment and fee
//! addresses, and one entry per presigned price step in `data`. It is a
//! different encoding from [`SwapProof::encode`], which is this crate's own
//! binary form; both describe the same presigns.
//!
//! Decoding is strict where it protects a buyer and lenient where wallets in
//! the wild disagree:
//!
//! - only `version: 2` is accepted. Version 1 (the `SHAKEDEX_PROOF:1.0.0`
//!   text format) predates the fix that made lock times real, so every bid in
//!   it was executable at once;
//! - every price step goes through [`DutchAuction::new`], so signatures must
//!   carry the HIP-0001 sighash byte and the schedule must be canonical;
//! - `feeAddr` with `fee == 0` is accepted and normalised to "no fee
//!   output", because a zero fee adds no output and the presign is identical
//!   either way. Markets publish exactly that when a fee rate rounds to zero;
//! - `expiresAt` (Unix seconds) is carried through but not enforced: it is
//!   not signed, and only a seller's cancel truly ends a listing;
//! - unknown fields are ignored, so marketplace extensions do not break
//!   decoding.

use bech32::Hrp;
use hns_primitives::{Dollarydoos, Outpoint, TransactionHash};
use hns_transaction::Address;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{COMPACT_SIGNATURE_SIZE, DutchAuction, NetworkBinding, SwapError, SwapProof};

/// The only auction JSON version this module reads or writes.
pub const SHAKEDEX_JSON_VERSION: u64 = 2;

/// Upper bound on accepted JSON input. A maximal auction is far smaller; the
/// bound exists so a hostile file cannot make the parser allocate freely.
pub const MAX_AUCTION_JSON_SIZE: usize = 256 * 1024;

/// A decoded Shakedex v2 auction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShakedexAuction {
    pub auction: DutchAuction,
    /// Listing expiry advertised by the market, in Unix seconds. Unsigned and
    /// not enforced on chain.
    pub expires_at: Option<u64>,
}

#[derive(Debug, Error)]
pub enum ShakedexJsonError {
    #[error("auction JSON is {0} bytes, over the {MAX_AUCTION_JSON_SIZE}-byte limit")]
    TooLarge(usize),
    #[error("malformed auction JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported Shakedex auction version {0}")]
    UnsupportedVersion(u64),
    #[error("{0} is not valid hex")]
    InvalidHex(&'static str),
    #[error("{0} has the wrong length")]
    InvalidLength(&'static str),
    #[error("{field} is not a valid address: {reason}")]
    InvalidAddress { field: &'static str, reason: String },
    #[error("{field} is for network {found}, expected {expected}")]
    WrongNetworkPrefix {
        field: &'static str,
        found: String,
        expected: String,
    },
    #[error("only version-0 addresses can be encoded")]
    UnsupportedAddressVersion(u8),
    #[error("lockingOutputIdx {0} does not fit in u32")]
    OutputIndexOutOfRange(u64),
    #[error("auction has no price steps")]
    NoPriceSteps,
    #[error("price steps ask for a fee but feeAddr is missing")]
    FeeWithoutAddress,
    #[error("price step is unsigned")]
    UnsignedPriceStep,
    #[error(transparent)]
    Swap(#[from] SwapError),
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuctionJson {
    name: String,
    locking_tx_hash: String,
    locking_output_idx: u64,
    public_key: String,
    payment_addr: String,
    #[serde(default)]
    fee_addr: Option<String>,
    data: Vec<PriceStepJson>,
    version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PriceStepJson {
    price: u64,
    lock_time: u64,
    signature: String,
    #[serde(default)]
    fee: u64,
}

/// Decode a Shakedex v2 auction for `network`, whose addresses use the
/// bech32 prefix `hrp` (`hs` mainnet, `ts` testnet, `rs` regtest, `ss`
/// simnet).
///
/// Structural checks only: the result has not been checked against the
/// chain. Call [`DutchAuction::verify_all_for_network`] with the lock coin
/// before relying on it.
pub fn decode_auction_json(
    json: &str,
    network: NetworkBinding,
    hrp: &str,
) -> Result<ShakedexAuction, ShakedexJsonError> {
    if json.len() > MAX_AUCTION_JSON_SIZE {
        return Err(ShakedexJsonError::TooLarge(json.len()));
    }
    let raw: AuctionJson = serde_json::from_str(json)?;
    if raw.version != SHAKEDEX_JSON_VERSION {
        return Err(ShakedexJsonError::UnsupportedVersion(raw.version));
    }
    if raw.data.is_empty() {
        return Err(ShakedexJsonError::NoPriceSteps);
    }

    let locking_outpoint = Outpoint {
        transaction_hash: TransactionHash::new(hex_array(&raw.locking_tx_hash, "lockingTxHash")?),
        index: u32::try_from(raw.locking_output_idx)
            .map_err(|_| ShakedexJsonError::OutputIndexOutOfRange(raw.locking_output_idx))?,
    };
    let seller_public_key = hex_array(&raw.public_key, "publicKey")?;
    let payment_address = decode_address(&raw.payment_addr, hrp, "paymentAddr")?;
    let fee_address = raw
        .fee_addr
        .as_deref()
        .map(|addr| decode_address(addr, hrp, "feeAddr"))
        .transpose()?;

    let proofs = raw
        .data
        .iter()
        .map(|step| {
            let fee_address = if step.fee == 0 {
                None
            } else {
                Some(
                    fee_address
                        .clone()
                        .ok_or(ShakedexJsonError::FeeWithoutAddress)?,
                )
            };
            Ok(SwapProof {
                network,
                locking_outpoint,
                name: raw.name.as_bytes().to_vec(),
                seller_public_key,
                payment_address: payment_address.clone(),
                price: Dollarydoos::new(step.price),
                lock_time_seconds: step.lock_time,
                signature: Some(hex_array::<COMPACT_SIGNATURE_SIZE>(
                    &step.signature,
                    "signature",
                )?),
                fee_address,
                fee: Dollarydoos::new(step.fee),
            })
        })
        .collect::<Result<Vec<_>, ShakedexJsonError>>()?;

    Ok(ShakedexAuction {
        auction: DutchAuction::new(proofs)?,
        expires_at: raw.expires_at,
    })
}

/// Encode an auction as Shakedex v2 JSON, with addresses under the bech32
/// prefix `hrp`.
pub fn encode_auction_json(
    auction: &ShakedexAuction,
    hrp: &str,
) -> Result<String, ShakedexJsonError> {
    let proofs = auction.auction.proofs();
    let first = proofs.first().ok_or(ShakedexJsonError::NoPriceSteps)?;
    let data = proofs
        .iter()
        .map(|proof| {
            Ok(PriceStepJson {
                price: proof.price.get(),
                lock_time: proof.lock_time_seconds,
                signature: hex::encode(
                    proof
                        .signature
                        .ok_or(ShakedexJsonError::UnsignedPriceStep)?,
                ),
                fee: proof.fee.get(),
            })
        })
        .collect::<Result<Vec<_>, ShakedexJsonError>>()?;
    let raw = AuctionJson {
        name: String::from_utf8_lossy(&first.name).into_owned(),
        locking_tx_hash: hex::encode(first.locking_outpoint.transaction_hash.as_bytes()),
        locking_output_idx: u64::from(first.locking_outpoint.index),
        public_key: hex::encode(first.seller_public_key),
        payment_addr: encode_address(&first.payment_address, hrp)?,
        fee_addr: first
            .fee_address
            .as_ref()
            .map(|addr| encode_address(addr, hrp))
            .transpose()?,
        data,
        version: SHAKEDEX_JSON_VERSION,
        expires_at: auction.expires_at,
    };
    Ok(serde_json::to_string(&raw)?)
}

fn hex_array<const N: usize>(s: &str, field: &'static str) -> Result<[u8; N], ShakedexJsonError> {
    let bytes = hex::decode(s).map_err(|_| ShakedexJsonError::InvalidHex(field))?;
    bytes
        .try_into()
        .map_err(|_| ShakedexJsonError::InvalidLength(field))
}

fn decode_address(s: &str, hrp: &str, field: &'static str) -> Result<Address, ShakedexJsonError> {
    let (found, version, program) =
        bech32::segwit::decode(s).map_err(|e| ShakedexJsonError::InvalidAddress {
            field,
            reason: e.to_string(),
        })?;
    if !found.as_str().eq_ignore_ascii_case(hrp) {
        return Err(ShakedexJsonError::WrongNetworkPrefix {
            field,
            found: found.to_string(),
            expected: hrp.to_owned(),
        });
    }
    Address::new(version.to_u8(), program).map_err(|e| ShakedexJsonError::InvalidAddress {
        field,
        reason: e.to_string(),
    })
}

fn encode_address(addr: &Address, hrp: &str) -> Result<String, ShakedexJsonError> {
    if addr.version != 0 {
        return Err(ShakedexJsonError::UnsupportedAddressVersion(addr.version));
    }
    let hrp = Hrp::parse(hrp).map_err(|e| ShakedexJsonError::InvalidAddress {
        field: "hrp",
        reason: e.to_string(),
    })?;
    bech32::segwit::encode_v0(hrp, &addr.hash).map_err(|e| ShakedexJsonError::InvalidAddress {
        field: "address",
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_primitives::BlockHash;

    const DEXREVIEWS: &str = include_str!("../fixtures/shakedex-json/proof_dexreviews.json");
    const COOLJOBS: &str = include_str!("../fixtures/shakedex-json/proof_cooljobs.json");

    fn mainnet() -> NetworkBinding {
        let genesis =
            hex::decode("5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0")
                .unwrap();
        NetworkBinding {
            magic: 0x5b6e_f2d3,
            genesis: BlockHash::new(genesis.try_into().unwrap()),
        }
    }

    fn value(json: &str) -> serde_json::Value {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn decodes_live_learnhns_listing() {
        let decoded = decode_auction_json(DEXREVIEWS, mainnet(), "hs").unwrap();
        let proofs = decoded.auction.proofs();
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].name, b"dexreviews");
        assert_eq!(proofs[0].price.get(), 435_000_000);
        assert_eq!(proofs[0].lock_time_seconds, 1_783_696_480);
        assert_eq!(proofs[0].fee_address, None);
        assert_eq!(decoded.expires_at, Some(1_815_232_480));
    }

    #[test]
    fn live_listings_round_trip_unchanged() {
        for fixture in [DEXREVIEWS, COOLJOBS] {
            let decoded = decode_auction_json(fixture, mainnet(), "hs").unwrap();
            let encoded = encode_auction_json(&decoded, "hs").unwrap();
            assert_eq!(value(&encoded), value(fixture));
        }
    }

    #[test]
    fn expires_at_is_optional() {
        let mut v = value(DEXREVIEWS);
        v.as_object_mut().unwrap().remove("expiresAt");
        let decoded = decode_auction_json(&v.to_string(), mainnet(), "hs").unwrap();
        assert_eq!(decoded.expires_at, None);
        assert!(
            !encode_auction_json(&decoded, "hs")
                .unwrap()
                .contains("expiresAt")
        );
    }

    #[test]
    fn fee_address_with_zero_fee_means_no_fee_output() {
        let mut v = value(DEXREVIEWS);
        v["feeAddr"] = v["paymentAddr"].clone();
        let decoded = decode_auction_json(&v.to_string(), mainnet(), "hs").unwrap();
        assert_eq!(decoded.auction.proofs()[0].fee_address, None);
        assert_eq!(decoded.auction.proofs()[0].fee.get(), 0);
    }

    #[test]
    fn fee_without_address_is_rejected() {
        let mut v = value(DEXREVIEWS);
        v["data"][0]["fee"] = 1_000.into();
        assert!(matches!(
            decode_auction_json(&v.to_string(), mainnet(), "hs"),
            Err(ShakedexJsonError::FeeWithoutAddress)
        ));
    }

    #[test]
    fn only_version_two_is_accepted() {
        for version in [1_u64, 3] {
            let mut v = value(DEXREVIEWS);
            v["version"] = version.into();
            assert!(matches!(
                decode_auction_json(&v.to_string(), mainnet(), "hs"),
                Err(ShakedexJsonError::UnsupportedVersion(found)) if found == version
            ));
        }
        assert!(matches!(
            decode_auction_json("SHAKEDEX_PROOF:1.0.0\n", mainnet(), "hs"),
            Err(ShakedexJsonError::Json(_))
        ));
    }

    #[test]
    fn wrong_network_prefix_is_rejected() {
        assert!(matches!(
            decode_auction_json(DEXREVIEWS, mainnet(), "rs"),
            Err(ShakedexJsonError::WrongNetworkPrefix {
                field: "paymentAddr",
                ..
            })
        ));
    }

    #[test]
    fn wrong_sighash_byte_is_rejected() {
        let mut v = value(DEXREVIEWS);
        let sig = v["data"][0]["signature"].as_str().unwrap().to_owned();
        v["data"][0]["signature"] = format!("{}01", &sig[..128]).into();
        assert!(matches!(
            decode_auction_json(&v.to_string(), mainnet(), "hs"),
            Err(ShakedexJsonError::Swap(SwapError::WrongSellerHashType(
                0x01
            )))
        ));
    }

    #[test]
    fn empty_and_oversized_input_is_rejected() {
        let mut v = value(DEXREVIEWS);
        v["data"] = serde_json::Value::Array(Vec::new());
        assert!(matches!(
            decode_auction_json(&v.to_string(), mainnet(), "hs"),
            Err(ShakedexJsonError::NoPriceSteps)
        ));
        let huge = " ".repeat(MAX_AUCTION_JSON_SIZE + 1);
        assert!(matches!(
            decode_auction_json(&huge, mainnet(), "hs"),
            Err(ShakedexJsonError::TooLarge(_))
        ));
    }

    #[test]
    fn malformed_fields_are_rejected_not_panicked_on() {
        for (field, bad) in [
            ("lockingTxHash", "zz"),
            ("publicKey", "03ab"),
            ("paymentAddr", "hs1notanaddress"),
        ] {
            let mut v = value(DEXREVIEWS);
            v[field] = bad.into();
            assert!(
                decode_auction_json(&v.to_string(), mainnet(), "hs").is_err(),
                "{field}"
            );
        }
        let mut v = value(DEXREVIEWS);
        v["lockingOutputIdx"] = (u64::from(u32::MAX) + 1).into();
        assert!(matches!(
            decode_auction_json(&v.to_string(), mainnet(), "hs"),
            Err(ShakedexJsonError::OutputIndexOutOfRange(_))
        ));
    }
}
