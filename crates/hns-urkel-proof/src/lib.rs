#![doc = "Bounded parsing and verification for HSD's Urkel proof wire format."]

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_primitives::{NameHash, TreeRoot};
use thiserror::Error;

pub const URKEL_BITS: usize = 256;
pub const EMPTY_ROOT: TreeRoot = TreeRoot::new([0; 32]);
pub const MAX_HSD_PROOF_SIZE: usize = 82_469;

const TYPE_DEADEND: u16 = 0;
const TYPE_SHORT: u16 = 1;
const TYPE_COLLISION: u16 = 2;
const TYPE_EXISTS: u16 = 3;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProofKind {
    Inclusion,
    NonInclusion,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UrkelProof {
    pub name_hash: NameHash,
    pub kind: ProofKind,
    pub raw: Vec<u8>,
}

impl UrkelProof {
    pub fn verify_hsd(&self, root: TreeRoot) -> Result<Option<Vec<u8>>, UrkelError> {
        let proof = HsdUrkelProof::decode_hsd(&self.raw)?;
        if proof.kind() != self.kind {
            return Err(UrkelError::KindMismatch);
        }
        proof.verify(root, self.name_hash)
    }

    pub fn verify_strict(&self, root: TreeRoot) -> Result<Option<Vec<u8>>, UrkelError> {
        let proof = HsdUrkelProof::decode_strict(&self.raw)?;
        if proof.kind() != self.kind {
            return Err(UrkelError::KindMismatch);
        }
        proof.verify(root, self.name_hash)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HsdUrkelProof {
    depth: u16,
    nodes: Vec<ProofNode>,
    terminal: ProofTerminal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProofNode {
    prefix: BitPrefix,
    sibling: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProofTerminal {
    DeadEnd,
    Short {
        prefix: BitPrefix,
        left: [u8; 32],
        right: [u8; 32],
    },
    Collision {
        key: NameHash,
        value_hash: [u8; 32],
    },
    Exists {
        value: Vec<u8>,
    },
}

impl HsdUrkelProof {
    /// Decode with upstream HSD/Urkel compatibility, including its behavior of
    /// ignoring trailing bytes. Use `decode_strict` at trust boundaries.
    pub fn decode_hsd(raw: &[u8]) -> Result<Self, UrkelError> {
        Self::decode_inner(raw).map(|(proof, _)| proof)
    }

    /// Decode one canonical proof and reject ignored trailing or non-minimal
    /// prefix/bitmap encodings.
    pub fn decode_strict(raw: &[u8]) -> Result<Self, UrkelError> {
        let (proof, consumed) = Self::decode_inner(raw)?;
        if consumed != raw.len() {
            return Err(UrkelError::TrailingBytes(raw.len() - consumed));
        }
        if proof.encode()? != raw {
            return Err(UrkelError::NonCanonical);
        }
        Ok(proof)
    }

    fn decode_inner(raw: &[u8]) -> Result<(Self, usize), UrkelError> {
        if raw.len() > MAX_HSD_PROOF_SIZE {
            return Err(UrkelError::TooLarge(raw.len()));
        }
        let mut reader = ProofReader::new(raw);
        let field = reader.read_u16()?;
        let proof_type = field >> 14;
        let depth = field & 0x3fff;
        if usize::from(depth) > URKEL_BITS {
            return Err(UrkelError::Depth(depth));
        }
        let count = usize::from(reader.read_u16()?);
        if count > URKEL_BITS {
            return Err(UrkelError::NodeCount(count));
        }
        let prefix_field = reader.read_vec(count.div_ceil(8))?;
        let mut nodes = Vec::with_capacity(count);
        for index in 0..count {
            let prefix = if packed_bit(&prefix_field, index) == 1 {
                let prefix = reader.read_prefix()?;
                if prefix.bit_len() == 0 {
                    return Err(UrkelError::EmptyExplicitPrefix);
                }
                prefix
            } else {
                BitPrefix::default()
            };
            nodes.push(ProofNode {
                prefix,
                sibling: reader.read_hash()?,
            });
        }
        let terminal = match proof_type {
            TYPE_DEADEND => ProofTerminal::DeadEnd,
            TYPE_SHORT => {
                let prefix = reader.read_prefix()?;
                if prefix.bit_len() == 0 {
                    return Err(UrkelError::EmptyShortPrefix);
                }
                ProofTerminal::Short {
                    prefix,
                    left: reader.read_hash()?,
                    right: reader.read_hash()?,
                }
            }
            TYPE_COLLISION => ProofTerminal::Collision {
                key: NameHash::new(reader.read_hash()?),
                value_hash: reader.read_hash()?,
            },
            TYPE_EXISTS => {
                let size = usize::from(reader.read_u16()?);
                ProofTerminal::Exists {
                    value: reader.read_vec(size)?,
                }
            }
            _ => unreachable!("two-bit proof type"),
        };
        let proof = Self {
            depth,
            nodes,
            terminal,
        };
        proof.validate()?;
        Ok((proof, reader.position()))
    }

    pub fn encode(&self) -> Result<Vec<u8>, UrkelError> {
        self.validate()?;
        let proof_type = match self.terminal {
            ProofTerminal::DeadEnd => TYPE_DEADEND,
            ProofTerminal::Short { .. } => TYPE_SHORT,
            ProofTerminal::Collision { .. } => TYPE_COLLISION,
            ProofTerminal::Exists { .. } => TYPE_EXISTS,
        };
        let mut raw = Vec::new();
        raw.extend_from_slice(&((proof_type << 14) | self.depth).to_le_bytes());
        raw.extend_from_slice(&(self.nodes.len() as u16).to_le_bytes());
        let bitmap_offset = raw.len();
        raw.resize(bitmap_offset + self.nodes.len().div_ceil(8), 0);
        for (index, node) in self.nodes.iter().enumerate() {
            if node.prefix.bit_len() != 0 {
                set_packed_bit(&mut raw[bitmap_offset..], index, 1);
                node.prefix.write_hsd(&mut raw);
            }
            raw.extend_from_slice(&node.sibling);
        }
        match &self.terminal {
            ProofTerminal::DeadEnd => {}
            ProofTerminal::Short {
                prefix,
                left,
                right,
            } => {
                prefix.write_hsd(&mut raw);
                raw.extend_from_slice(left);
                raw.extend_from_slice(right);
            }
            ProofTerminal::Collision { key, value_hash } => {
                raw.extend_from_slice(key.as_bytes());
                raw.extend_from_slice(value_hash);
            }
            ProofTerminal::Exists { value } => {
                raw.extend_from_slice(&(value.len() as u16).to_le_bytes());
                raw.extend_from_slice(value);
            }
        }
        if raw.len() > MAX_HSD_PROOF_SIZE {
            return Err(UrkelError::TooLarge(raw.len()));
        }
        Ok(raw)
    }

    pub fn kind(&self) -> ProofKind {
        match self.terminal {
            ProofTerminal::Exists { .. } => ProofKind::Inclusion,
            _ => ProofKind::NonInclusion,
        }
    }

    pub const fn depth(&self) -> u16 {
        self.depth
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn verify(
        &self,
        expected_root: TreeRoot,
        key: NameHash,
    ) -> Result<Option<Vec<u8>>, UrkelError> {
        self.validate()?;
        let key_bytes = key.as_bytes();
        let (mut hash, value) = match &self.terminal {
            ProofTerminal::DeadEnd => ([0; 32], None),
            ProofTerminal::Short {
                prefix,
                left,
                right,
            } => {
                if prefix.matches_key(key_bytes, usize::from(self.depth)) {
                    return Err(UrkelError::ShortFollowsKey);
                }
                (hash_internal(prefix, left, right), None)
            }
            ProofTerminal::Collision {
                key: collision,
                value_hash,
            } => {
                if *collision == key {
                    return Err(UrkelError::CollisionUsesKey);
                }
                (hash_leaf(collision.as_bytes(), value_hash), None)
            }
            ProofTerminal::Exists { value } => (
                hash_leaf(key_bytes, &blake2b_256(value)),
                Some(value.clone()),
            ),
        };

        let mut depth = usize::from(self.depth);
        for node in self.nodes.iter().rev() {
            let prefix_bits = node.prefix.bit_len();
            if depth < prefix_bits + 1 {
                return Err(UrkelError::AncestorDepth);
            }
            depth -= 1;
            hash = if key_bit(key_bytes, depth) == 1 {
                hash_internal(&node.prefix, &node.sibling, &hash)
            } else {
                hash_internal(&node.prefix, &hash, &node.sibling)
            };
            depth -= prefix_bits;
            if !node.prefix.matches_key(key_bytes, depth) {
                return Err(UrkelError::AncestorPrefix);
            }
        }
        if depth != 0 {
            return Err(UrkelError::IncompletePath(depth));
        }
        let actual = TreeRoot::new(hash);
        if actual != expected_root {
            return Err(UrkelError::RootMismatch {
                expected: expected_root,
                actual,
            });
        }
        Ok(value)
    }

    fn validate(&self) -> Result<(), UrkelError> {
        if usize::from(self.depth) > URKEL_BITS {
            return Err(UrkelError::Depth(self.depth));
        }
        if self.nodes.len() > URKEL_BITS {
            return Err(UrkelError::NodeCount(self.nodes.len()));
        }
        for node in &self.nodes {
            node.prefix.validate()?;
        }
        if let ProofTerminal::Short { prefix, .. } = &self.terminal {
            prefix.validate()?;
            if prefix.bit_len() == 0 {
                return Err(UrkelError::EmptyShortPrefix);
            }
        }
        if let ProofTerminal::Exists { value } = &self.terminal
            && value.len() > usize::from(u16::MAX)
        {
            return Err(UrkelError::ValueTooLarge(value.len()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct BitPrefix {
    bit_len: u16,
    bytes: Vec<u8>,
}

impl BitPrefix {
    fn bit_len(&self) -> usize {
        usize::from(self.bit_len)
    }

    fn bit(&self, index: usize) -> u8 {
        packed_bit(&self.bytes, index)
    }

    fn matches_key(&self, key: &[u8; 32], depth: usize) -> bool {
        depth
            .checked_add(self.bit_len())
            .is_some_and(|end| end <= URKEL_BITS)
            && (0..self.bit_len()).all(|offset| self.bit(offset) == key_bit(key, depth + offset))
    }

    fn validate(&self) -> Result<(), UrkelError> {
        let bit_len = self.bit_len();
        if bit_len > URKEL_BITS {
            return Err(UrkelError::PrefixLength(bit_len));
        }
        if self.bytes.len() != bit_len.div_ceil(8) {
            return Err(UrkelError::PrefixSize);
        }
        if !bit_len.is_multiple_of(8) && !self.bytes.is_empty() {
            let used = bit_len % 8;
            let trailing_mask = (1_u8 << (8 - used)) - 1;
            if self.bytes[self.bytes.len() - 1] & trailing_mask != 0 {
                return Err(UrkelError::PrefixTrailingBits);
            }
        }
        Ok(())
    }

    fn write_hsd(&self, output: &mut Vec<u8>) {
        let bit_len = self.bit_len();
        if bit_len >= 0x80 {
            output.push(0x80 | ((bit_len >> 8) as u8));
        }
        output.push(bit_len as u8);
        output.extend_from_slice(&self.bytes);
    }
}

struct ProofReader<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> ProofReader<'a> {
    const fn new(raw: &'a [u8]) -> Self {
        Self { raw, offset: 0 }
    }

    const fn position(&self) -> usize {
        self.offset
    }

    fn read_u8(&mut self) -> Result<u8, UrkelError> {
        let value = *self
            .raw
            .get(self.offset)
            .ok_or(UrkelError::UnexpectedEnd(self.offset))?;
        self.offset += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, UrkelError> {
        Ok(u16::from_le_bytes(
            self.read_slice(2)?
                .try_into()
                .expect("two-byte proof field"),
        ))
    }

    fn read_hash(&mut self) -> Result<[u8; 32], UrkelError> {
        Ok(self.read_slice(32)?.try_into().expect("32-byte proof hash"))
    }

    fn read_vec(&mut self, size: usize) -> Result<Vec<u8>, UrkelError> {
        Ok(self.read_slice(size)?.to_vec())
    }

    fn read_prefix(&mut self) -> Result<BitPrefix, UrkelError> {
        let first = self.read_u8()?;
        let bit_len = if first & 0x80 != 0 {
            (usize::from(first & 0x7f) << 8) | usize::from(self.read_u8()?)
        } else {
            usize::from(first)
        };
        if bit_len > URKEL_BITS {
            return Err(UrkelError::PrefixLength(bit_len));
        }
        let prefix = BitPrefix {
            bit_len: bit_len as u16,
            bytes: self.read_vec(bit_len.div_ceil(8))?,
        };
        prefix.validate()?;
        Ok(prefix)
    }

    fn read_slice(&mut self, size: usize) -> Result<&'a [u8], UrkelError> {
        let end = self
            .offset
            .checked_add(size)
            .ok_or(UrkelError::OffsetOverflow)?;
        let bytes = self
            .raw
            .get(self.offset..end)
            .ok_or(UrkelError::UnexpectedEnd(self.offset))?;
        self.offset = end;
        Ok(bytes)
    }
}

fn hash_leaf(key: &[u8; 32], value_hash: &[u8; 32]) -> [u8; 32] {
    blake2b_256_many(&[&[0], key, value_hash])
}

fn hash_internal(prefix: &BitPrefix, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    if prefix.bit_len() == 0 {
        return blake2b_256_many(&[&[1], left, right]);
    }
    let size = (prefix.bit_len() as u16).to_le_bytes();
    blake2b_256_many(&[&[2], &size, &prefix.bytes, left, right])
}

fn blake2b_256(input: &[u8]) -> [u8; 32] {
    blake2b_256_many(&[input])
}

fn blake2b_256_many(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output length");
    for part in parts {
        hasher.update(part);
    }
    let mut output = [0_u8; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("valid BLAKE2b output buffer");
    output
}

fn key_bit(key: &[u8; 32], index: usize) -> u8 {
    (key[index / 8] >> (7 - (index % 8))) & 1
}

fn packed_bit(bytes: &[u8], index: usize) -> u8 {
    (bytes[index / 8] >> (7 - (index % 8))) & 1
}

fn set_packed_bit(bytes: &mut [u8], index: usize, bit: u8) {
    bytes[index / 8] |= bit << (7 - (index % 8));
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum UrkelError {
    #[error("HSD proof uses {0} bytes, exceeding its configured bound")]
    TooLarge(usize),
    #[error("HSD proof depth {0} exceeds 256 bits")]
    Depth(u16),
    #[error("HSD proof node count {0} exceeds 256")]
    NodeCount(usize),
    #[error("HSD proof prefix uses {0} bits")]
    PrefixLength(usize),
    #[error("HSD proof prefix byte length is inconsistent")]
    PrefixSize,
    #[error("HSD proof prefix has nonzero unused bits")]
    PrefixTrailingBits,
    #[error("HSD proof encodes an empty explicit ancestor prefix")]
    EmptyExplicitPrefix,
    #[error("HSD short proof encodes an empty prefix")]
    EmptyShortPrefix,
    #[error("unexpected end of HSD proof at byte {0}")]
    UnexpectedEnd(usize),
    #[error("HSD proof offset overflow")]
    OffsetOverflow,
    #[error("{0} trailing HSD proof byte(s)")]
    TrailingBytes(usize),
    #[error("HSD proof is not canonically encoded")]
    NonCanonical,
    #[error("included proof value uses {0} bytes, exceeding 65535")]
    ValueTooLarge(usize),
    #[error("declared inclusion class differs from proof terminal")]
    KindMismatch,
    #[error("short proof prefix follows the requested key")]
    ShortFollowsKey,
    #[error("collision proof uses the requested key")]
    CollisionUsesKey,
    #[error("proof depth precedes a compressed ancestor")]
    AncestorDepth,
    #[error("compressed ancestor prefix differs from the requested key")]
    AncestorPrefix,
    #[error("proof path stops {0} bit(s) before the tree root")]
    IncompletePath(usize),
    #[error("Urkel proof root mismatch")]
    RootMismatch {
        expected: TreeRoot,
        actual: TreeRoot,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "961d2caeea0311f64152665755a905fed00a3dd39bfa1b1217a5bbd356586f80";
    const ALPHA_KEY: &str = "8f9ca3f331d0e099a724c861aabc1a5906f7b92f4c3b10618c791aab9d433045";
    const ALPHA_PROOF: &str = "03c003000008ccd32448dd945f74c5df7b689096a8e9b2e7556196a2ed6567379328eb210e89fdfeee71539b6fc6020cb25173cd2ec986f83abab0a9d59411893e887875d83049a050258883441796a0c2263168cf9c1143b98e25b3a86157c7045444e20b040000010203";
    const MISSING_KEY: &str = "23e587a06765c200c68c20a62f7b9c766a29dce0a572f59268e854f30118083d";
    const COLLISION_PROOF: &str = "0280020000b47b6f4bca3a4caf5304170027f760a4cced32b9739a0e580ffbd50a7c18663be4221ce21fbf13e813163c53a4efaf779f15da26ee65a4367e33291a09906f173c2bb709c7f6df963eef15c9a9b024d059f99fec904116fd5bc05726945e2df2545db83fd403da1091070a319d15d0d29faf383af24c68172bd6a565d0d71f63";
    const SHORT_KEY: &str = "e4c5923b20bd6ade4dfbc2afe74ec66d9c5aceefeb7a4905f9459b3400658037";
    const SHORT_PROOF: &str = "024002000008ccd32448dd945f74c5df7b689096a8e9b2e7556196a2ed6567379328eb210ef789264e81a9fea73d4a4306c6e87c2815f4251c6ab57f5f6436e73a1897316d0400795975f88d7a3d9faf04acb0b541c65df9308de3e3580cbce81e4ef6b5d066d51ed52b6ddb9149df707e5058baff9e22bfcb812ff8e035a2b7580bc9cd287021";

    fn root() -> TreeRoot {
        TreeRoot::from_hex(ROOT).expect("root")
    }

    #[test]
    fn exact_hsd_inclusion_and_empty_proofs_verify() {
        let raw = hex::decode(ALPHA_PROOF).expect("hex");
        let proof = HsdUrkelProof::decode_strict(&raw).expect("proof");
        assert_eq!(proof.kind(), ProofKind::Inclusion);
        assert_eq!(proof.depth(), 3);
        assert_eq!(proof.node_count(), 3);
        assert_eq!(
            proof
                .verify(root(), NameHash::from_hex(ALPHA_KEY).expect("key"))
                .expect("valid"),
            Some(vec![0, 1, 2, 3])
        );
        assert_eq!(proof.encode().expect("encoded"), raw);

        let empty = HsdUrkelProof::decode_strict(&[0, 0, 0, 0]).expect("empty");
        assert_eq!(
            empty
                .verify(EMPTY_ROOT, NameHash::new([0x55; 32]))
                .expect("valid"),
            None
        );
    }

    #[test]
    fn exact_hsd_short_and_collision_noninclusion_proofs_verify() {
        for (key, raw) in [(SHORT_KEY, SHORT_PROOF), (MISSING_KEY, COLLISION_PROOF)] {
            let raw = hex::decode(raw).expect("hex");
            let proof = HsdUrkelProof::decode_strict(&raw).expect("proof");
            assert_eq!(proof.kind(), ProofKind::NonInclusion);
            assert_eq!(
                proof
                    .verify(root(), NameHash::from_hex(key).expect("key"))
                    .expect("valid"),
                None
            );
            assert_eq!(proof.encode().expect("encoded"), raw);
        }
    }

    #[test]
    fn upstream_trailing_compatibility_is_separate_from_strict_admission() {
        let canonical = hex::decode(COLLISION_PROOF).expect("hex");
        let mut trailing = canonical.clone();
        trailing.push(0xff);
        let compatible = HsdUrkelProof::decode_hsd(&trailing).expect("HSD accepts");
        assert_eq!(compatible.encode().expect("canonical"), canonical);
        assert_eq!(
            HsdUrkelProof::decode_strict(&trailing),
            Err(UrkelError::TrailingBytes(1))
        );
    }

    #[test]
    fn wrong_root_key_and_mutated_terminal_fail_closed() {
        let raw = hex::decode(COLLISION_PROOF).expect("hex");
        let proof = HsdUrkelProof::decode_strict(&raw).expect("proof");
        assert!(
            proof
                .verify(
                    TreeRoot::new([0xa5; 32]),
                    NameHash::from_hex(MISSING_KEY).expect("key")
                )
                .is_err()
        );
        assert!(proof.verify(root(), NameHash::new([0xb5; 32])).is_err());
        let mut mutated = raw;
        *mutated.last_mut().expect("byte") ^= 1;
        let proof = HsdUrkelProof::decode_strict(&mutated).expect("structurally valid");
        assert!(
            proof
                .verify(root(), NameHash::from_hex(MISSING_KEY).expect("key"))
                .is_err()
        );
    }
}
