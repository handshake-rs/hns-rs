#![doc = "Runtime-independent Handshake block commitments and immutable mining jobs."]

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use hns_covenants::{Covenant, CovenantKind, MAX_COVENANT_ITEMS, MAX_RESOURCE_SIZE, hash_name};
use hns_encoding::{Decoder, Encoder};
use hns_header_consensus::{EXTRA_NONCE_SIZE, HEADER_SIZE, Header, Network};
use hns_primitives::{
    BlockHash, BlockTime, CompactTarget, Dollarydoos, Height, MerkleRoot, PowMask, ReservedRoot,
    TreeRoot, WitnessRoot,
};
use hns_transaction::{Address, Input, Outpoint, Transaction, Witness};
use thiserror::Error;

pub const COIN: u64 = 1_000_000;
pub const BASE_REWARD: u64 = 2_000 * COIN;
pub const MAX_MONEY: u64 = 2_040_000_000 * COIN;
pub const MAX_BLOCK_BASE_SIZE: usize = 1_000_000;
pub const MAX_BLOCK_WEIGHT: usize = 4_000_000;
pub const MAX_BLOCK_OPENS: u32 = 300;
pub const MAX_BLOCK_UPDATES: u32 = 600;
pub const MAX_BLOCK_RENEWALS: u32 = 600;
pub const MAX_COVENANT_SIZE: usize = 585;
pub const MAX_COINBASE_WITNESS_SIZE: usize = 1_000;
pub const MAX_COINBASE_CLAIM_WITNESS_ITEM_SIZE: usize = 10_000;
pub const WITNESS_SCALE_FACTOR: usize = 4;
pub const MAX_PREPARED_JOBS: usize = 16;

pub type MiningGeneration = u64;
pub type MiningJobId = [u8; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Block {
    pub header: Header,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn decode(input: &[u8]) -> Result<Self, MiningError> {
        if input.len() > MAX_BLOCK_WEIGHT {
            return Err(MiningError::InvalidBlockBody(
                "serialized block exceeds allocation bound",
            ));
        }
        let mut decoder = Decoder::new(input);
        let header = Header::decode(decoder.read_slice(HEADER_SIZE)?)?;
        let count = decoder.read_compact_usize(MAX_BLOCK_BASE_SIZE, "block transactions")?;
        let mut transactions = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            transactions.push(Transaction::decode_from(&mut decoder)?);
        }
        decoder.finish()?;
        let block = Self {
            header,
            transactions,
        };
        validate_block_limits(&block)?;
        Ok(block)
    }

    pub fn encode(&self) -> Result<Vec<u8>, MiningError> {
        let metrics = validate_block_limits(self)?;
        let mut encoder = Encoder::with_capacity(metrics.serialized_size);
        encoder.put_bytes(&self.header.encode());
        encoder.put_compact_size(self.transactions.len() as u64);
        for transaction in &self.transactions {
            encoder.put_bytes(&transaction.encode()?);
        }
        Ok(encoder.into_bytes())
    }

    pub fn decode_validated(input: &[u8]) -> Result<Self, MiningError> {
        let block = Self::decode(input)?;
        validate_block_body(&block)?;
        Ok(block)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockMetrics {
    pub base_size: usize,
    pub witness_size: usize,
    pub serialized_size: usize,
    pub weight: usize,
    pub merkle_root: MerkleRoot,
    pub witness_root: WitnessRoot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MiningSnapshot {
    pub network: Network,
    pub generation: MiningGeneration,
    pub tip_hash: BlockHash,
    pub tip_height: Height,
    pub tip_time: BlockTime,
    pub parent_median_time: BlockTime,
    pub next_tree_root: TreeRoot,
    pub expected_bits: CompactTarget,
}

impl MiningSnapshot {
    pub fn next_height(self) -> Result<Height, MiningError> {
        self.tip_height
            .get()
            .checked_add(1)
            .map(Height::new)
            .ok_or(MiningError::ArithmeticOverflow)
    }

    fn validate(self) -> Result<(), MiningError> {
        if self.generation == 0 || self.expected_bits.get() == 0 {
            return Err(MiningError::InvalidSnapshot);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiningHeaderTemplate {
    pub parent_hash: BlockHash,
    pub tree_root: TreeRoot,
    pub reserved_root: ReservedRoot,
    pub witness_root: WitnessRoot,
    pub merkle_root: MerkleRoot,
    pub version: u32,
    pub bits: CompactTarget,
    pub minimum_time: BlockTime,
    pub mask_hash: [u8; 32],
}

impl MiningHeaderTemplate {
    pub fn from_transactions(
        snapshot: MiningSnapshot,
        reserved_root: ReservedRoot,
        version: u32,
        minimum_time: BlockTime,
        mask: PowMask,
        transactions: &[Transaction],
    ) -> Result<Self, MiningError> {
        snapshot.validate()?;
        if minimum_time <= snapshot.parent_median_time || transactions.is_empty() {
            return Err(MiningError::InvalidTemplate);
        }
        Ok(Self {
            parent_hash: snapshot.tip_hash,
            tree_root: snapshot.next_tree_root,
            reserved_root,
            witness_root: block_witness_root(transactions)?,
            merkle_root: block_merkle_root(transactions)?,
            version,
            bits: snapshot.expected_bits,
            minimum_time,
            mask_hash: mask_hash(snapshot.tip_hash, mask),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedMiningJob {
    job_id: MiningJobId,
    snapshot_generation: MiningGeneration,
    network: Network,
    header: MiningHeaderTemplate,
    maximum_target_time: Option<BlockTime>,
    transactions: Arc<[Transaction]>,
}

impl PreparedMiningJob {
    pub fn new(
        snapshot: MiningSnapshot,
        header: MiningHeaderTemplate,
        transactions: Arc<[Transaction]>,
    ) -> Result<Self, MiningError> {
        snapshot.validate()?;
        if header.parent_hash != snapshot.tip_hash
            || header.tree_root != snapshot.next_tree_root
            || header.minimum_time <= snapshot.parent_median_time
            || header.bits != snapshot.expected_bits
            || transactions.is_empty()
        {
            return Err(MiningError::InvalidJob);
        }
        let provisional = Block {
            header: Header {
                time: header.minimum_time,
                previous_block: header.parent_hash,
                tree_root: header.tree_root,
                reserved_root: header.reserved_root,
                witness_root: header.witness_root,
                merkle_root: header.merkle_root,
                version: header.version,
                bits: header.bits,
                ..Header::default()
            },
            transactions: transactions.to_vec(),
        };
        validate_block_body(&provisional)?;
        if provisional.transactions[0].locktime != snapshot.next_height()?.get() {
            return Err(MiningError::InvalidCoinbaseHeight);
        }
        let parameters = snapshot.network.parameters().pow;
        let maximum_target_time =
            (parameters.target_reset && header.bits != parameters.bits).then(|| {
                BlockTime::new(
                    snapshot
                        .tip_time
                        .get()
                        .saturating_add(u64::from(parameters.target_spacing).saturating_mul(2)),
                )
            });
        if maximum_target_time.is_some_and(|maximum| header.minimum_time > maximum) {
            return Err(MiningError::InvalidJob);
        }
        let job_id = job_id(snapshot, &header, &transactions)?;
        Ok(Self {
            job_id,
            snapshot_generation: snapshot.generation,
            network: snapshot.network,
            header,
            maximum_target_time,
            transactions,
        })
    }

    pub fn prepare(
        snapshot: MiningSnapshot,
        reserved_root: ReservedRoot,
        version: u32,
        minimum_time: BlockTime,
        mask: PowMask,
        transactions: Arc<[Transaction]>,
    ) -> Result<Self, MiningError> {
        let header = MiningHeaderTemplate::from_transactions(
            snapshot,
            reserved_root,
            version,
            minimum_time,
            mask,
            &transactions,
        )?;
        Self::new(snapshot, header, transactions)
    }

    pub const fn job_id(&self) -> MiningJobId {
        self.job_id
    }

    pub const fn snapshot_generation(&self) -> MiningGeneration {
        self.snapshot_generation
    }

    pub const fn header(&self) -> &MiningHeaderTemplate {
        &self.header
    }

    pub const fn maximum_target_time(&self) -> Option<BlockTime> {
        self.maximum_target_time
    }

    pub fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }

    pub fn validate_for_snapshot(&self, snapshot: MiningSnapshot) -> Result<(), MiningError> {
        snapshot.validate().map_err(|_| MiningError::StaleJob)?;
        let parameters = snapshot.network.parameters().pow;
        let expected_maximum = (parameters.target_reset && self.header.bits != parameters.bits)
            .then(|| {
                BlockTime::new(
                    snapshot
                        .tip_time
                        .get()
                        .saturating_add(u64::from(parameters.target_spacing).saturating_mul(2)),
                )
            });
        if self.network != snapshot.network
            || self.snapshot_generation != snapshot.generation
            || self.header.parent_hash != snapshot.tip_hash
            || self.header.tree_root != snapshot.next_tree_root
            || self.header.bits != snapshot.expected_bits
            || self.header.minimum_time <= snapshot.parent_median_time
            || self.maximum_target_time != expected_maximum
            || self.job_id != job_id(snapshot, &self.header, &self.transactions)?
        {
            return Err(MiningError::StaleJob);
        }
        Ok(())
    }

    pub fn reconstruct(
        &self,
        nonce: u32,
        time: BlockTime,
        extra_nonce: [u8; EXTRA_NONCE_SIZE],
        mask: PowMask,
    ) -> Result<Block, MiningError> {
        if time < self.header.minimum_time
            || self
                .maximum_target_time
                .is_some_and(|maximum| time > maximum)
            || mask_hash(self.header.parent_hash, mask) != self.header.mask_hash
        {
            return Err(MiningError::InvalidReconstruction);
        }
        let block = Block {
            header: Header {
                nonce,
                time,
                previous_block: self.header.parent_hash,
                tree_root: self.header.tree_root,
                extra_nonce,
                reserved_root: self.header.reserved_root,
                witness_root: self.header.witness_root,
                merkle_root: self.header.merkle_root,
                version: self.header.version,
                bits: self.header.bits,
                mask,
            },
            transactions: self.transactions.to_vec(),
        };
        validate_block_body(&block).map_err(|_| MiningError::InvalidReconstruction)?;
        if block.header.mask_hash() != self.header.mask_hash {
            return Err(MiningError::InvalidReconstruction);
        }
        Ok(block)
    }

    pub fn admit_solution(
        &self,
        snapshot: MiningSnapshot,
        nonce: u32,
        time: BlockTime,
        extra_nonce: [u8; EXTRA_NONCE_SIZE],
        mask: PowMask,
    ) -> Result<SolvedMiningCandidate, MiningError> {
        self.validate_for_snapshot(snapshot)?;
        let block = self.reconstruct(nonce, time, extra_nonce, mask)?;
        if !block.header.verify_pow() {
            return Err(MiningError::InsufficientProofOfWork);
        }
        Ok(SolvedMiningCandidate {
            job_id: self.job_id,
            snapshot_generation: self.snapshot_generation,
            parent_height: snapshot.tip_height,
            block,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SolvedMiningCandidate {
    job_id: MiningJobId,
    snapshot_generation: MiningGeneration,
    parent_height: Height,
    block: Block,
}

impl SolvedMiningCandidate {
    pub const fn job_id(&self) -> MiningJobId {
        self.job_id
    }

    pub const fn snapshot_generation(&self) -> MiningGeneration {
        self.snapshot_generation
    }

    pub const fn parent_height(&self) -> Height {
        self.parent_height
    }

    pub const fn block(&self) -> &Block {
        &self.block
    }

    pub fn into_block(self) -> Block {
        self.block
    }
}

#[derive(Clone, Debug, Default)]
pub struct PreparedJobSet {
    jobs: BTreeMap<MiningJobId, Arc<PreparedMiningJob>>,
}

impl PreparedJobSet {
    pub fn insert(
        &mut self,
        job: PreparedMiningJob,
    ) -> Result<Arc<PreparedMiningJob>, MiningError> {
        if let Some(existing) = self.jobs.get(&job.job_id) {
            if existing.as_ref() == &job {
                return Ok(Arc::clone(existing));
            }
            return Err(MiningError::JobConflict);
        }
        if self.jobs.len() >= MAX_PREPARED_JOBS {
            return Err(MiningError::JobCapacity);
        }
        let job = Arc::new(job);
        self.jobs.insert(job.job_id, Arc::clone(&job));
        Ok(job)
    }

    pub fn activate(
        &mut self,
        job_id: MiningJobId,
        snapshot: MiningSnapshot,
    ) -> Result<Arc<PreparedMiningJob>, MiningError> {
        let job = self
            .jobs
            .get(&job_id)
            .cloned()
            .ok_or(MiningError::UnknownJob)?;
        job.validate_for_snapshot(snapshot)?;
        self.jobs.retain(|_, candidate| {
            candidate.snapshot_generation == snapshot.generation
                && candidate.network == snapshot.network
        });
        Ok(job)
    }

    pub fn retain_generation(&mut self, generation: MiningGeneration) {
        self.jobs
            .retain(|_, candidate| candidate.snapshot_generation == generation);
    }

    pub fn clear(&mut self) {
        self.jobs.clear();
    }

    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.jobs.is_empty()
    }
}

pub fn block_subsidy(height: Height, halving_interval: u32) -> Result<Dollarydoos, MiningError> {
    if halving_interval == 0 {
        return Err(MiningError::InvalidHalvingInterval);
    }
    let halvings = height.get() / halving_interval;
    Ok(Dollarydoos::new(if halvings >= 52 {
        0
    } else {
        BASE_REWARD >> halvings
    }))
}

pub const fn halving_interval(network: Network) -> u32 {
    match network {
        Network::Regtest => 2_500,
        Network::Mainnet | Network::Testnet | Network::Simnet => 170_000,
    }
}

pub fn create_coinbase(
    height: Height,
    generation: MiningGeneration,
    subsidy: Dollarydoos,
    fees: Dollarydoos,
    payout_address: Address,
    coinbase_flags: Vec<u8>,
) -> Result<Transaction, MiningError> {
    payout_address.validate()?;
    let reward = subsidy.checked_add(fees)?;
    if reward.get() > MAX_MONEY {
        return Err(MiningError::OutputValue);
    }
    let generation =
        u32::try_from(generation).map_err(|_| MiningError::GenerationOutOfRange(generation))?;
    let transaction = Transaction {
        version: 0,
        inputs: vec![Input {
            previous_output: Outpoint::NULL,
            sequence: generation,
            witness: Witness {
                items: vec![coinbase_flags, vec![0; 8], vec![0; 8]],
            },
        }],
        outputs: vec![hns_transaction::Output {
            value: reward,
            address: payout_address,
            covenant: Covenant::default(),
        }],
        locktime: height.get(),
    };
    validate_transaction_sanity(&transaction)?;
    Ok(transaction)
}

pub fn merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    let sentinel = blake2b_256(&[]);
    let mut nodes = hashes
        .iter()
        .map(|hash| blake2b_256_many(&[&[0], hash]))
        .collect::<Vec<_>>();
    if nodes.is_empty() {
        return sentinel;
    }
    while nodes.len() > 1 {
        let mut next = Vec::with_capacity(nodes.len().div_ceil(2));
        for pair in nodes.chunks(2) {
            let right = pair.get(1).unwrap_or(&sentinel);
            next.push(blake2b_256_many(&[&[1], &pair[0], right]));
        }
        nodes = next;
    }
    nodes[0]
}

pub fn block_merkle_root(transactions: &[Transaction]) -> Result<MerkleRoot, MiningError> {
    let hashes = transactions
        .iter()
        .map(|transaction| transaction.transaction_hash().map(|hash| hash.into_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(MerkleRoot::new(merkle_root(&hashes)))
}

pub fn block_witness_root(transactions: &[Transaction]) -> Result<WitnessRoot, MiningError> {
    let hashes = transactions
        .iter()
        .map(Transaction::witness_hash)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(WitnessRoot::new(merkle_root(&hashes)))
}

pub fn validate_block_body(block: &Block) -> Result<BlockMetrics, MiningError> {
    let metrics = validate_block_limits(block)?;
    if block.transactions.is_empty() {
        return Err(MiningError::InvalidBlockBody("invalid transaction count"));
    }
    if metrics.merkle_root.as_bytes() == &[0; 32] {
        return Err(MiningError::InvalidBlockBody("zero merkle root"));
    }
    if metrics.merkle_root != block.header.merkle_root {
        return Err(MiningError::InvalidBlockBody("merkle root mismatch"));
    }
    if metrics.witness_root != block.header.witness_root {
        return Err(MiningError::InvalidBlockBody("witness root mismatch"));
    }
    if !block.transactions[0].is_coinbase() {
        return Err(MiningError::InvalidBlockBody(
            "first transaction is not coinbase",
        ));
    }
    for (index, transaction) in block.transactions.iter().enumerate() {
        validate_transaction_sanity(transaction)?;
        if index != 0 && transaction.is_coinbase() {
            return Err(MiningError::InvalidBlockBody(
                "block contains multiple coinbase transactions",
            ));
        }
    }
    validate_block_covenant_limits(block)?;
    Ok(metrics)
}

fn validate_block_limits(block: &Block) -> Result<BlockMetrics, MiningError> {
    if block.transactions.len() > MAX_BLOCK_BASE_SIZE {
        return Err(MiningError::InvalidBlockBody("invalid transaction count"));
    }
    let metrics = block_metrics(&block.transactions)?;
    if metrics.base_size > MAX_BLOCK_BASE_SIZE {
        return Err(MiningError::InvalidBlockBody("base size exceeds limit"));
    }
    if metrics.weight > MAX_BLOCK_WEIGHT {
        return Err(MiningError::InvalidBlockBody("weight exceeds limit"));
    }
    Ok(metrics)
}

pub fn block_metrics(transactions: &[Transaction]) -> Result<BlockMetrics, MiningError> {
    let count_size = compact_size_len(transactions.len() as u64);
    let mut base_size = HEADER_SIZE
        .checked_add(count_size)
        .ok_or(MiningError::ArithmeticOverflow)?;
    let mut witness_size = 0_usize;
    for transaction in transactions {
        base_size = base_size
            .checked_add(transaction.base_size()?)
            .ok_or(MiningError::ArithmeticOverflow)?;
        witness_size = witness_size
            .checked_add(transaction.witness_encode()?.len())
            .ok_or(MiningError::ArithmeticOverflow)?;
    }
    let serialized_size = base_size
        .checked_add(witness_size)
        .ok_or(MiningError::ArithmeticOverflow)?;
    let weight = base_size
        .checked_mul(WITNESS_SCALE_FACTOR)
        .and_then(|base| base.checked_add(witness_size))
        .ok_or(MiningError::ArithmeticOverflow)?;
    Ok(BlockMetrics {
        base_size,
        witness_size,
        serialized_size,
        weight,
        merkle_root: block_merkle_root(transactions)?,
        witness_root: block_witness_root(transactions)?,
    })
}

pub fn validate_transaction_sanity(transaction: &Transaction) -> Result<(), MiningError> {
    if transaction.inputs.is_empty() {
        return Err(MiningError::InvalidTransaction("transaction has no inputs"));
    }
    if transaction.outputs.is_empty() {
        return Err(MiningError::InvalidTransaction(
            "transaction has no outputs",
        ));
    }
    if transaction.base_size()? > MAX_BLOCK_BASE_SIZE || transaction.weight()? > MAX_BLOCK_WEIGHT {
        return Err(MiningError::InvalidTransaction(
            "transaction exceeds consensus size",
        ));
    }
    let name_operations = count_name_operations(transaction);
    if name_operations.opens > MAX_BLOCK_OPENS {
        return Err(MiningError::InvalidTransaction(
            "transaction open limit exceeded",
        ));
    }
    if name_operations.updates > MAX_BLOCK_UPDATES {
        return Err(MiningError::InvalidTransaction(
            "transaction update limit exceeded",
        ));
    }
    if name_operations.renewals > MAX_BLOCK_RENEWALS {
        return Err(MiningError::InvalidTransaction(
            "transaction renewal limit exceeded",
        ));
    }
    let mut total = 0_u64;
    for output in &transaction.outputs {
        output.address.validate()?;
        total = total
            .checked_add(output.value.get())
            .ok_or(MiningError::OutputValue)?;
        if total > MAX_MONEY {
            return Err(MiningError::OutputValue);
        }
    }
    if transaction.is_coinbase() {
        if witness_size(&transaction.inputs[0].witness) > MAX_COINBASE_WITNESS_SIZE {
            return Err(MiningError::InvalidTransaction(
                "coinbase witness exceeds limit",
            ));
        }
        for input in transaction.inputs.iter().skip(1) {
            if !input.previous_output.is_null() {
                return Err(MiningError::InvalidTransaction(
                    "coinbase claim input is not null",
                ));
            }
            if input.witness.items.len() != 1 {
                return Err(MiningError::InvalidTransaction(
                    "coinbase claim input must have one witness item",
                ));
            }
            if input.witness.items[0].len() > MAX_COINBASE_CLAIM_WITNESS_ITEM_SIZE {
                return Err(MiningError::InvalidTransaction(
                    "coinbase claim witness item exceeds limit",
                ));
            }
        }
    } else {
        let mut inputs = HashSet::with_capacity(transaction.inputs.len());
        for input in &transaction.inputs {
            if input.previous_output.is_null() {
                return Err(MiningError::InvalidTransaction(
                    "non-coinbase spends null outpoint",
                ));
            }
            if !inputs.insert(input.previous_output) {
                return Err(MiningError::InvalidTransaction(
                    "transaction contains duplicate inputs",
                ));
            }
        }
    }
    if !has_sane_covenants(transaction) {
        return Err(MiningError::InvalidTransaction(
            "transaction covenants are structurally invalid",
        ));
    }
    Ok(())
}

fn validate_block_covenant_limits(block: &Block) -> Result<(), MiningError> {
    let mut opens = 0_u32;
    let mut updates = 0_u32;
    let mut renewals = 0_u32;
    let mut exclusive_names = HashSet::new();
    for transaction in &block.transactions {
        let name_operations = count_name_operations(transaction);
        opens = opens.saturating_add(name_operations.opens);
        updates = updates.saturating_add(name_operations.updates);
        renewals = renewals.saturating_add(name_operations.renewals);

        // HSD permits repeated exclusive covenants within one transaction but
        // rejects the same name when it appears in a later transaction.
        let mut transaction_exclusive_names = HashSet::new();
        for output in &transaction.outputs {
            if matches!(
                output.covenant.kind,
                CovenantKind::Claim
                    | CovenantKind::Open
                    | CovenantKind::Register
                    | CovenantKind::Update
                    | CovenantKind::Renew
                    | CovenantKind::Transfer
                    | CovenantKind::Finalize
                    | CovenantKind::Revoke
            ) {
                let name_hash: [u8; 32] = output
                    .covenant
                    .item(0)
                    .and_then(|item| item.try_into().ok())
                    .ok_or(MiningError::InvalidBlockBody(
                        "name covenant hash has invalid length",
                    ))?;
                if exclusive_names.contains(&name_hash) {
                    return Err(MiningError::InvalidBlockBody(
                        "block contains duplicate exclusive name updates",
                    ));
                }
                transaction_exclusive_names.insert(name_hash);
            }
        }
        exclusive_names.extend(transaction_exclusive_names);
    }
    if opens > MAX_BLOCK_OPENS {
        return Err(MiningError::InvalidBlockBody("block open limit exceeded"));
    }
    if updates > MAX_BLOCK_UPDATES {
        return Err(MiningError::InvalidBlockBody("block update limit exceeded"));
    }
    if renewals > MAX_BLOCK_RENEWALS {
        return Err(MiningError::InvalidBlockBody(
            "block renewal limit exceeded",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct NameOperationCounts {
    opens: u32,
    updates: u32,
    renewals: u32,
}

fn count_name_operations(transaction: &Transaction) -> NameOperationCounts {
    let mut counts = NameOperationCounts::default();
    for output in &transaction.outputs {
        match output.covenant.kind {
            CovenantKind::Open => {
                counts.opens = counts.opens.saturating_add(1);
                counts.updates = counts.updates.saturating_add(1);
            }
            CovenantKind::Claim
            | CovenantKind::Update
            | CovenantKind::Transfer
            | CovenantKind::Revoke => {
                counts.updates = counts.updates.saturating_add(1);
            }
            CovenantKind::Register | CovenantKind::Renew | CovenantKind::Finalize => {
                counts.renewals = counts.renewals.saturating_add(1);
            }
            _ => {}
        }
    }
    counts
}

fn has_sane_covenants(transaction: &Transaction) -> bool {
    if transaction.is_coinbase() {
        if transaction.inputs.len() > transaction.outputs.len() {
            return false;
        }
        for (index, output) in transaction.outputs.iter().enumerate() {
            match output.covenant.kind {
                CovenantKind::None => {
                    if !output.covenant.items.is_empty() {
                        return false;
                    }
                }
                CovenantKind::Claim => {
                    let items = &output.covenant.items;
                    if index == 0
                        || index >= transaction.inputs.len()
                        || transaction.inputs[index].witness.items.len() != 1
                        || !item_lengths(items, &[32, 4, usize::MAX, 1, 32, 4])
                        || !valid_name_hash(&items[0], &items[2])
                    {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        return true;
    }

    for (index, output) in transaction.outputs.iter().enumerate() {
        let items = &output.covenant.items;
        let linked = index < transaction.inputs.len();
        let sane = match output.covenant.kind {
            CovenantKind::None => items.is_empty(),
            CovenantKind::Claim => false,
            CovenantKind::Open => {
                item_lengths(items, &[32, 4, usize::MAX])
                    && item_u32(items, 1) == Some(0)
                    && valid_name_hash(&items[0], &items[2])
            }
            CovenantKind::Bid => {
                item_lengths(items, &[32, 4, usize::MAX, 32])
                    && valid_name_hash(&items[0], &items[2])
            }
            CovenantKind::Reveal => linked && item_lengths(items, &[32, 4, 32]),
            CovenantKind::Redeem => linked && item_lengths(items, &[32, 4]),
            CovenantKind::Register => {
                linked
                    && item_lengths(items, &[32, 4, usize::MAX, 32])
                    && items[2].len() <= MAX_RESOURCE_SIZE
            }
            CovenantKind::Update => {
                linked
                    && item_lengths(items, &[32, 4, usize::MAX])
                    && items[2].len() <= MAX_RESOURCE_SIZE
            }
            CovenantKind::Renew => linked && item_lengths(items, &[32, 4, 32]),
            CovenantKind::Transfer => {
                linked
                    && item_lengths(items, &[32, 4, 1, usize::MAX])
                    && items[2][0] <= 31
                    && (2..=40).contains(&items[3].len())
            }
            CovenantKind::Finalize => {
                linked
                    && item_lengths(items, &[32, 4, usize::MAX, 1, 4, 4, 32])
                    && valid_name_hash(&items[0], &items[2])
            }
            CovenantKind::Revoke => linked && item_lengths(items, &[32, 4]),
            CovenantKind::Unknown(_) => {
                items.len() <= MAX_COVENANT_ITEMS
                    && output
                        .covenant
                        .encode()
                        .is_ok_and(|encoded| encoded.len() <= MAX_COVENANT_SIZE)
            }
        };
        if !sane {
            return false;
        }
    }
    true
}

fn item_lengths(items: &[Vec<u8>], expected: &[usize]) -> bool {
    items.len() == expected.len()
        && items
            .iter()
            .zip(expected)
            .all(|(item, length)| *length == usize::MAX || item.len() == *length)
}

fn item_u32(items: &[Vec<u8>], index: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        items.get(index)?.as_slice().try_into().ok()?,
    ))
}

fn valid_name_hash(hash: &[u8], name: &[u8]) -> bool {
    hash_name(name)
        .map(|expected| expected.as_bytes() == hash)
        .unwrap_or(false)
}

fn witness_size(witness: &Witness) -> usize {
    compact_size_len(witness.items.len() as u64).saturating_add(
        witness
            .items
            .iter()
            .map(|item| compact_size_len(item.len() as u64).saturating_add(item.len()))
            .sum::<usize>(),
    )
}

fn compact_size_len(value: u64) -> usize {
    match value {
        0..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

fn mask_hash(parent: BlockHash, mask: PowMask) -> [u8; 32] {
    blake2b_256_many(&[parent.as_bytes(), mask.as_bytes()])
}

fn job_id(
    snapshot: MiningSnapshot,
    header: &MiningHeaderTemplate,
    transactions: &[Transaction],
) -> Result<MiningJobId, MiningError> {
    let mut body = Encoder::new();
    body.put_u64_le(transactions.len() as u64);
    for transaction in transactions {
        let encoded = transaction.encode()?;
        body.put_u64_le(encoded.len() as u64);
        body.put_bytes(&encoded);
    }
    Ok(blake2b_256_many(&[
        b"hsrd/mining-job/v1",
        &[snapshot.network.id()],
        &snapshot.generation.to_le_bytes(),
        header.parent_hash.as_bytes(),
        header.tree_root.as_bytes(),
        header.reserved_root.as_bytes(),
        header.witness_root.as_bytes(),
        header.merkle_root.as_bytes(),
        &header.version.to_le_bytes(),
        &header.bits.get().to_le_bytes(),
        &header.minimum_time.get().to_le_bytes(),
        &header.mask_hash,
        &body.into_bytes(),
    ]))
}

fn blake2b_256(input: &[u8]) -> [u8; 32] {
    blake2b_256_many(&[input])
}

fn blake2b_256_many(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output length");
    for part in parts {
        hasher.update(part);
    }
    let mut output = [0; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("valid BLAKE2b output buffer");
    output
}

#[derive(Debug, Error)]
pub enum MiningError {
    #[error(transparent)]
    Decode(#[from] hns_encoding::DecodeError),
    #[error(transparent)]
    Header(#[from] hns_header_consensus::HeaderError),
    #[error(transparent)]
    Transaction(#[from] hns_transaction::TransactionError),
    #[error(transparent)]
    Arithmetic(#[from] hns_primitives::ArithmeticError),
    #[error("mining snapshot is zero, stale, or inconsistent")]
    InvalidSnapshot,
    #[error("mining template is inconsistent with its snapshot or body")]
    InvalidTemplate,
    #[error("prepared mining job is inconsistent with its snapshot or body")]
    InvalidJob,
    #[error("candidate coinbase does not commit the next height")]
    InvalidCoinbaseHeight,
    #[error("prepared mining job is stale")]
    StaleJob,
    #[error("opened-mask block reconstruction is invalid")]
    InvalidReconstruction,
    #[error("opened-mask mining result does not meet the network target")]
    InsufficientProofOfWork,
    #[error("prepared mining job ID conflicts with different bytes")]
    JobConflict,
    #[error("prepared mining job capacity is exhausted")]
    JobCapacity,
    #[error("prepared mining job is unknown")]
    UnknownJob,
    #[error("halving interval must be nonzero")]
    InvalidHalvingInterval,
    #[error("mining generation {0} cannot be encoded in the coinbase sequence")]
    GenerationOutOfRange(MiningGeneration),
    #[error("numeric overflow while building mining data")]
    ArithmeticOverflow,
    #[error("transaction output amount is invalid")]
    OutputValue,
    #[error("invalid transaction: {0}")]
    InvalidTransaction(&'static str),
    #[error("invalid block body: {0}")]
    InvalidBlockBody(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    const COINBASE_RAW: &str = "00000000010000000000000000000000000000000000000000000000000000000000000000ffffffff07000000013c943577000000000014090909090909090909090909090909090909090900000b000000030468737264080000000000000000080000000000000000";

    fn fixture_coinbase() -> Transaction {
        create_coinbase(
            Height::new(11),
            7,
            block_subsidy(Height::new(11), 2_500).unwrap(),
            Dollarydoos::new(60),
            Address::new(0, vec![9; 20]).unwrap(),
            b"hsrd".to_vec(),
        )
        .unwrap()
    }

    fn snapshot(generation: u64, marker: u8) -> MiningSnapshot {
        MiningSnapshot {
            network: Network::Regtest,
            generation,
            tip_hash: BlockHash::new([marker; 32]),
            tip_height: Height::new(10),
            tip_time: BlockTime::new(100),
            parent_median_time: BlockTime::new(99),
            next_tree_root: TreeRoot::new([marker.wrapping_add(1); 32]),
            expected_bits: Network::Regtest.parameters().pow.bits,
        }
    }

    fn prepared(snapshot: MiningSnapshot, mask: PowMask) -> PreparedMiningJob {
        PreparedMiningJob::prepare(
            snapshot,
            ReservedRoot::new([3; 32]),
            1,
            BlockTime::new(101),
            mask,
            Arc::from(vec![fixture_coinbase()]),
        )
        .unwrap()
    }

    #[test]
    fn subsidy_and_coinbase_match_hsd_template_fixture() {
        let cases = [
            (0, 170_000, 2_000_000_000),
            (169_999, 170_000, 2_000_000_000),
            (170_000, 170_000, 1_000_000_000),
            (340_000, 170_000, 500_000_000),
            (8_670_000, 170_000, 0),
            (2_499, 2_500, 2_000_000_000),
            (2_500, 2_500, 1_000_000_000),
            (5_000, 2_500, 500_000_000),
            (127_500, 2_500, 0),
        ];
        for (height, interval, expected) in cases {
            assert_eq!(
                block_subsidy(Height::new(height), interval).unwrap().get(),
                expected
            );
        }
        let transaction = fixture_coinbase();
        assert_eq!(
            transaction.encode().unwrap(),
            hex::decode(COINBASE_RAW).unwrap()
        );
        assert_eq!(
            transaction.transaction_hash().unwrap().to_string(),
            "34108e299d22a4114526b0d191780ca77f795430b48f1951e3e318731931078a"
        );
        assert_eq!(
            hex::encode(transaction.witness_hash().unwrap()),
            "3cd20aa3dd6ede9246e5827cd0c8bd10367dd5da1eb7d29fee04edab473fec4a"
        );
        assert_eq!(transaction.base_size().unwrap(), 82);
        assert_eq!(transaction.witness_encode().unwrap().len(), 24);
        assert_eq!(transaction.weight().unwrap(), 352);
        assert!(matches!(
            create_coinbase(
                Height::new(11),
                u64::from(u32::MAX) + 1,
                Dollarydoos::new(1),
                Dollarydoos::new(0),
                Address::new(0, vec![9; 20]).unwrap(),
                Vec::new(),
            ),
            Err(MiningError::GenerationOutOfRange(_))
        ));
    }

    #[test]
    fn merkle_and_witness_roots_match_hsd_domain_separation() {
        let transaction = fixture_coinbase();
        assert_eq!(
            block_merkle_root(std::slice::from_ref(&transaction))
                .unwrap()
                .to_string(),
            "5a88b64fe244a4b3adbb73e9ae7983e62f66bf154ceea5180efcb7214b11e949"
        );
        assert_eq!(
            block_witness_root(&[transaction]).unwrap().to_string(),
            "223cf6dbd896ecb22a504884606f20e0b8d70fda48b65bc8cfb9a6be5f6798b1"
        );
        assert_eq!(merkle_root(&[]), blake2b_256(&[]));
        let hsd_vectors = [
            (
                1,
                "6bf22d230bc6f17e2dc9bdce220e8696630a067ab5029fb66d91e6ecd74c7c54",
            ),
            (
                2,
                "e7ee5228698f31758aa7e13445bc54d4c4b37303a90d5ca4677fad9976d1187b",
            ),
            (
                3,
                "7511ad764e06d5f02ea56d142da5e920242a39cfc4f4631c2597760d3fc81123",
            ),
            (
                5,
                "45148643ac4aa66c59361ab95443c0bdcc49c000d7f1365413de7a9d39be8f1c",
            ),
        ];
        for (count, expected) in hsd_vectors {
            let leaves = (1..=count)
                .map(|marker| [marker as u8; 32])
                .collect::<Vec<_>>();
            assert_eq!(hex::encode(merkle_root(&leaves)), expected);
        }
    }

    #[test]
    fn immutable_job_reconstructs_and_stale_bindings_fail() {
        let current = snapshot(1, 1);
        let mask = PowMask::new([9; 32]);
        let job = prepared(current, mask);
        let block = job
            .reconstruct(7, BlockTime::new(101), [8; EXTRA_NONCE_SIZE], mask)
            .unwrap();
        assert_eq!(block.header.mask_hash(), job.header().mask_hash);
        assert_eq!(block.transactions[0].locktime, 11);
        assert!(validate_block_body(&block).is_ok());
        assert_eq!(
            Block::decode_validated(&block.encode().unwrap()).unwrap(),
            block
        );
        assert!(matches!(
            job.validate_for_snapshot(snapshot(2, 1)),
            Err(MiningError::StaleJob)
        ));
        assert!(matches!(
            job.reconstruct(7, BlockTime::new(100), [8; EXTRA_NONCE_SIZE], mask),
            Err(MiningError::InvalidReconstruction)
        ));
        assert!(matches!(
            job.reconstruct(
                7,
                BlockTime::new(101),
                [8; EXTRA_NONCE_SIZE],
                PowMask::new([8; 32])
            ),
            Err(MiningError::InvalidReconstruction)
        ));
    }

    #[test]
    fn solution_admission_requires_current_generation_and_pow() {
        let current = snapshot(1, 1);
        let mask = PowMask::new([9; 32]);
        let job = prepared(current, mask);
        let mut nonce = 0_u32;
        let solved = loop {
            match job.admit_solution(
                current,
                nonce,
                BlockTime::new(101),
                [7; EXTRA_NONCE_SIZE],
                mask,
            ) {
                Ok(candidate) => break candidate,
                Err(MiningError::InsufficientProofOfWork) => {
                    nonce = nonce.checked_add(1).expect("regtest solution")
                }
                Err(error) => panic!("unexpected solution error: {error}"),
            }
        };
        assert_eq!(solved.job_id(), job.job_id());
        assert_eq!(solved.snapshot_generation(), 1);
        assert!(solved.block().header.verify_pow());
    }

    #[test]
    fn testnet_target_reset_time_bounds_prepared_work() {
        let mut current = snapshot(1, 1);
        current.network = Network::Testnet;
        current.expected_bits = CompactTarget::new(0x1d00_fffe);
        let mask = PowMask::new([7; 32]);
        let transactions: Arc<[Transaction]> = Arc::from(vec![fixture_coinbase()]);
        let header = MiningHeaderTemplate::from_transactions(
            current,
            ReservedRoot::new([3; 32]),
            0,
            BlockTime::new(101),
            mask,
            &transactions,
        )
        .unwrap();
        let job = PreparedMiningJob::new(current, header, transactions).unwrap();
        let boundary = current
            .tip_time
            .get()
            .saturating_add(u64::from(Network::Testnet.parameters().pow.target_spacing) * 2);
        assert_eq!(job.maximum_target_time(), Some(BlockTime::new(boundary)));
        assert!(
            job.reconstruct(1, BlockTime::new(boundary), [0; EXTRA_NONCE_SIZE], mask)
                .is_ok()
        );
        assert!(matches!(
            job.reconstruct(1, BlockTime::new(boundary + 1), [0; EXTRA_NONCE_SIZE], mask),
            Err(MiningError::InvalidReconstruction)
        ));
    }

    #[test]
    fn body_and_job_identity_fail_closed() {
        let current = snapshot(1, 1);
        let mask = PowMask::new([9; 32]);
        let one = prepared(current, mask);
        let mut altered_coinbase = fixture_coinbase();
        altered_coinbase.outputs[0].value = Dollarydoos::new(1);
        let transactions: Arc<[Transaction]> = Arc::from(vec![altered_coinbase]);
        let header = MiningHeaderTemplate::from_transactions(
            current,
            ReservedRoot::new([3; 32]),
            1,
            BlockTime::new(101),
            mask,
            &transactions,
        )
        .unwrap();
        let two = PreparedMiningJob::new(current, header, transactions).unwrap();
        assert_ne!(one.job_id(), two.job_id());

        let mut invalid = one
            .reconstruct(0, BlockTime::new(101), [0; EXTRA_NONCE_SIZE], mask)
            .unwrap();
        invalid.header.merkle_root = MerkleRoot::new([0; 32]);
        assert!(matches!(
            validate_block_body(&invalid),
            Err(MiningError::InvalidBlockBody("merkle root mismatch"))
        ));

        let mut jobs = PreparedJobSet::default();
        let id = one.job_id();
        jobs.insert(one).unwrap();
        assert_eq!(jobs.activate(id, current).unwrap().job_id(), id);
        assert!(matches!(
            jobs.activate(id, snapshot(2, 1)),
            Err(MiningError::StaleJob)
        ));

        let mut claim_coinbase = fixture_coinbase();
        claim_coinbase.inputs.push(Input {
            previous_output: Outpoint::NULL,
            sequence: u32::MAX,
            witness: Witness {
                items: vec![vec![1, 2, 3]],
            },
        });
        assert!(claim_coinbase.is_coinbase());
        assert!(matches!(
            validate_transaction_sanity(&claim_coinbase),
            Err(MiningError::InvalidTransaction(
                "transaction covenants are structurally invalid"
            ))
        ));
        let name = b"claimname";
        claim_coinbase.outputs.push(hns_transaction::Output {
            value: Dollarydoos::new(0),
            address: Address::new(0, vec![7; 20]).unwrap(),
            covenant: Covenant {
                kind: CovenantKind::Claim,
                items: vec![
                    hash_name(name).unwrap().into_bytes().to_vec(),
                    1_u32.to_le_bytes().to_vec(),
                    name.to_vec(),
                    vec![0],
                    vec![2; 32],
                    1_u32.to_le_bytes().to_vec(),
                ],
            },
        });
        validate_transaction_sanity(&claim_coinbase).unwrap();
    }

    #[test]
    fn covenant_shapes_and_name_operation_limits_match_hsd() {
        let name = b"boundedname";
        let name_hash = hash_name(name).unwrap().into_bytes().to_vec();
        let input = Input {
            previous_output: Outpoint {
                transaction_hash: fixture_coinbase().transaction_hash().unwrap(),
                index: 0,
            },
            sequence: u32::MAX,
            witness: Witness::default(),
        };
        let open_output = hns_transaction::Output {
            value: Dollarydoos::new(0),
            address: Address::new(0, vec![4; 20]).unwrap(),
            covenant: Covenant {
                kind: CovenantKind::Open,
                items: vec![
                    name_hash.clone(),
                    0_u32.to_le_bytes().to_vec(),
                    name.to_vec(),
                ],
            },
        };
        let valid_open = Transaction {
            version: 0,
            inputs: vec![input.clone()],
            outputs: vec![open_output.clone()],
            locktime: 0,
        };
        validate_transaction_sanity(&valid_open).unwrap();

        let mut wrong_hash = valid_open.clone();
        wrong_hash.outputs[0].covenant.items[0][0] ^= 1;
        assert!(validate_transaction_sanity(&wrong_hash).is_err());

        let too_many_opens = Transaction {
            version: 0,
            inputs: vec![input],
            outputs: vec![open_output; MAX_BLOCK_OPENS as usize + 1],
            locktime: 0,
        };
        assert!(matches!(
            validate_transaction_sanity(&too_many_opens),
            Err(MiningError::InvalidTransaction(
                "transaction open limit exceeded"
            ))
        ));
    }

    #[test]
    fn exclusive_name_updates_may_repeat_only_within_one_transaction() {
        let name_hash = hash_name(b"exclusive").unwrap().into_bytes().to_vec();
        let update = |index| Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint {
                    transaction_hash: fixture_coinbase().transaction_hash().unwrap(),
                    index,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![hns_transaction::Output {
                value: Dollarydoos::new(0),
                address: Address::new(0, vec![5; 20]).unwrap(),
                covenant: Covenant {
                    kind: CovenantKind::Update,
                    items: vec![name_hash.clone(), 1_u32.to_le_bytes().to_vec(), vec![0]],
                },
            }],
            locktime: 0,
        };
        let first = update(1);
        let second = update(2);
        validate_transaction_sanity(&first).unwrap();
        validate_transaction_sanity(&second).unwrap();
        let header = prepared(snapshot(1, 1), PowMask::new([9; 32]))
            .reconstruct(
                0,
                BlockTime::new(101),
                [0; EXTRA_NONCE_SIZE],
                PowMask::new([9; 32]),
            )
            .unwrap()
            .header;
        let duplicated_across_transactions = Block {
            header: header.clone(),
            transactions: vec![first.clone(), second],
        };
        assert!(matches!(
            validate_block_covenant_limits(&duplicated_across_transactions),
            Err(MiningError::InvalidBlockBody(
                "block contains duplicate exclusive name updates"
            ))
        ));

        let mut repeated_within_transaction = first;
        repeated_within_transaction
            .outputs
            .push(repeated_within_transaction.outputs[0].clone());
        let permitted = Block {
            header,
            transactions: vec![repeated_within_transaction],
        };
        validate_block_covenant_limits(&permitted).unwrap();
    }
}
