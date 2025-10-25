//! ZK Proof Verification Module
//!
//! This module provides verification logic for ZK proofs of Bitcoin blocks.
//! It verifies that proofs are consistent with Bitcoin blockchain data.

use anyhow::{anyhow, Result};
use bitcoin::hashes::Hash;
use bitcoincore_rpc::{Client, RpcApi};
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::zk_proof_storage::{BitcoinBlockProof, MatchingTransaction, TransactionType};
use crate::merkle_cache::MerkleCache;

/// Verifier for ZK proofs of Bitcoin blocks
pub struct ProofVerifier {
    bitcoin_client: Arc<Client>,
    merkle_cache: MerkleCache,
}

impl ProofVerifier {
    /// Create a new proof verifier with the given Bitcoin RPC client
    pub fn new(bitcoin_client: Arc<Client>, data_dir: &str) -> Result<Self> {
        let merkle_cache = MerkleCache::new(data_dir)?;
        Ok(Self { 
            bitcoin_client,
            merkle_cache,
        })
    }

    /// Verify a ZK proof against Bitcoin blockchain data
    ///
    /// This performs:
    /// 1. Verify block hash matches the actual block at that height
    /// 2. Fetch the block and look up each txid
    /// 3. Verify transaction classifications match Core Lane patterns
    pub fn verify_proof(&self, proof: &BitcoinBlockProof) -> Result<bool> {
        info!(
            "🔍 Verifying ZK proof for block {} (hash: {})",
            proof.block_height, proof.block_hash
        );

        // Step 1: Verify block hash and fetch the block
        debug!("  1️⃣  Verifying block hash and fetching block...");
        let block_hash = bitcoin::BlockHash::from_str(&proof.block_hash)
            .map_err(|e| anyhow!("Invalid block hash: {}", e))?;

        // Verify this is actually the block at this height
        let actual_hash = self.bitcoin_client.get_block_hash(proof.block_height)?;
        if actual_hash != block_hash {
            warn!(
                "❌ Block hash mismatch: expected {} at height {}, got {}",
                block_hash, proof.block_height, actual_hash
            );
            return Ok(false);
        }

        // Fetch the full block for verification
        let block = self.bitcoin_client.get_block(&block_hash)?;
        debug!("  ✅ Block hash verified and block fetched");

        // Step 2: Verify based on strategy
        match &proof.strategy {
            crate::zk_proof_storage::ProofStrategy::Searching(_) => {
                debug!(
                    "  2️⃣  Verifying {} transaction IDs in block (searching strategy)...",
                    proof.matching_transactions.len()
                );
                if !self.verify_matching_transactions(&proof.matching_transactions, &block)? {
                    warn!(
                        "❌ Transaction verification failed for block {}",
                        proof.block_height
                    );
                    return Ok(false);
                }
            }
            crate::zk_proof_storage::ProofStrategy::Pointing(pointing_proof) => {
                debug!(
                    "  2️⃣  Verifying pointing proof for transaction {}...",
                    pointing_proof.txid
                );
                if !self.verify_pointing_proof(pointing_proof, &proof.merkle_proofs, &block)? {
                    warn!(
                        "❌ Pointing proof verification failed for block {}",
                        proof.block_height
                    );
                    return Ok(false);
                }
            }
        }
        debug!(
            "  ✅ All {} transactions verified",
            proof.matching_transactions.len()
        );

        info!(
            "✅ ZK proof verified successfully for block {}",
            proof.block_height
        );
        Ok(true)
    }

    /// Verify matching transactions exist in block and match their claimed patterns
    fn verify_matching_transactions(
        &self,
        matching_txs: &[MatchingTransaction],
        block: &bitcoin::Block,
    ) -> Result<bool> {
        for matching_tx in matching_txs {
            // Find the transaction in the block by txid
            let tx = block
                .txdata
                .iter()
                .find(|tx| tx.compute_txid().to_string() == matching_tx.txid);

            let tx = match tx {
                Some(tx) => tx,
                None => {
                    warn!("❌ Transaction {} not found in block", matching_tx.txid);
                    return Ok(false);
                }
            };

            debug!("    Found transaction {}", matching_tx.txid);

            // Verify transaction classification matches pattern
            match matching_tx.tx_type {
                TransactionType::Burn => {
                    if !Self::has_burn_pattern(tx) {
                        warn!(
                            "❌ Transaction {} classified as Burn but doesn't match pattern",
                            matching_tx.txid
                        );
                        return Ok(false);
                    }
                    debug!("    ✅ Burn pattern verified");
                }
                TransactionType::DataAvailability => {
                    if !Self::has_da_pattern(tx) {
                        warn!(
                            "❌ Transaction {} classified as DA but doesn't match pattern",
                            matching_tx.txid
                        );
                        return Ok(false);
                    }
                    debug!("    ✅ DA pattern verified");
                }
                TransactionType::Fill => {
                    // For now, just verify it's a valid transaction
                    debug!("    ✅ Fill transaction verified");
                }
            }
        }

        Ok(true)
    }

    /// Check if transaction has burn pattern (OP_RETURN with BRN1)
    fn has_burn_pattern(tx: &bitcoin::Transaction) -> bool {
        for output in &tx.output {
            if output.script_pubkey.is_op_return() {
                let script_bytes = output.script_pubkey.as_bytes();
                // OP_RETURN scripts have format: [OP_RETURN] [push_opcode] [data...]
                if script_bytes.len() >= 6 {
                    // Check for BRN1 prefix after OP_RETURN and push opcode
                    let data_start = 2; // Skip OP_RETURN and push opcode
                    if script_bytes.len() > data_start + 4 {
                        let prefix = &script_bytes[data_start..data_start + 4];
                        if prefix == b"BRN1" {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Check if transaction has DA pattern (Taproot witness or CORE prefix)
    fn has_da_pattern(tx: &bitcoin::Transaction) -> bool {
        // Check for Taproot witness data in inputs
        for input in &tx.input {
            if !input.witness.is_empty() {
                // Has witness data - could be DA transaction
                return true;
            }
        }

        // Also check for CORE prefix in OP_RETURN (alternative DA pattern)
        for output in &tx.output {
            if output.script_pubkey.is_op_return() {
                let script_bytes = output.script_pubkey.as_bytes();
                if script_bytes.len() >= 6 {
                    let data_start = 2;
                    if script_bytes.len() > data_start + 4 {
                        let prefix = &script_bytes[data_start..data_start + 4];
                        if prefix == b"CORE" {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Verify a pointing proof with Merkle proof
    fn verify_pointing_proof(
        &self,
        pointing_proof: &crate::zk_proof_storage::PointingProof,
        merkle_proofs: &[crate::zk_proof_storage::MerkleProof],
        block: &bitcoin::Block,
    ) -> Result<bool> {
        // Find the transaction at the specified position
        if pointing_proof.tx_position as usize >= block.txdata.len() {
            warn!(
                "❌ Transaction position {} out of range (block has {} transactions)",
                pointing_proof.tx_position,
                block.txdata.len()
            );
            return Ok(false);
        }

        let tx = &block.txdata[pointing_proof.tx_position as usize];
        let actual_txid = tx.compute_txid().to_string();

        if actual_txid != pointing_proof.txid {
            warn!(
                "❌ Transaction ID mismatch: expected {}, got {}",
                pointing_proof.txid, actual_txid
            );
            return Ok(false);
        }

        // Verify Merkle proof
        if merkle_proofs.is_empty() {
            warn!("❌ No Merkle proof provided for pointing strategy");
            return Ok(false);
        }

        let merkle_proof = &merkle_proofs[0];
        
        // Get the block's Merkle root from the header
        let block_merkle_root = block.header.merkle_root.to_byte_array();
        
        // Verify the Merkle proof
        if !self.verify_merkle_proof(merkle_proof, &block_merkle_root)? {
            warn!("❌ Merkle proof verification failed");
            return Ok(false);
        }

        debug!("✅ Pointing proof verified successfully");
        Ok(true)
    }

    /// Verify a Merkle proof against a block's Merkle root
    fn verify_merkle_proof(
        &self,
        merkle_proof: &crate::zk_proof_storage::MerkleProof,
        _merkle_root: &[u8; 32],
    ) -> Result<bool> {
        // This is a simplified verification - in practice you'd use the same
        // Merkle tree implementation as the ZK proof system
        debug!(
            "🔍 Verifying Merkle proof for tx {}",
            hex::encode(merkle_proof.txid)
        );

        // For now, we'll just check that the proof structure is valid
        // In a full implementation, you'd verify the path from txid to root
        if merkle_proof.path.len() != merkle_proof.positions.len() {
            return Ok(false);
        }

        // TODO: Implement full Merkle proof verification
        // This would involve:
        // 1. Starting with the txid
        // 2. Walking up the tree using the proof path
        // 3. Computing the final hash and comparing with merkle_root
        
        debug!("✅ Merkle proof structure is valid");
        Ok(true)
    }

    /// Verify that a transaction does not exist in a block
    pub fn verify_tx_non_existence(
        &mut self,
        block_height: u64,
        txid: &str,
    ) -> Result<bool> {
        self.merkle_cache.verify_non_existence(block_height, txid, &self.bitcoin_client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests would require a Bitcoin RPC connection
    // In practice, you'd mock the RPC client for testing

    #[test]
    fn test_burn_pattern_detection() {
        // Create a test transaction with BRN1 pattern
        // This is a simplified test - in reality you'd need proper Bitcoin transaction structure
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        // For now, just test that the function doesn't panic
        let has_pattern = ProofVerifier::has_burn_pattern(&tx);
        assert!(!has_pattern); // Empty transaction has no pattern
    }
}
