//! ZK Proof Storage Module
//!
//! This module provides storage and retrieval for ZK proofs of Bitcoin blocks.
//! Proofs are stored locally in JSON format for compatibility and ease of debugging.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Re-export proof types from bitcoin-zk-proofs
/// These types are defined in the bitcoin-zk-proofs guest program
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransactionType {
    Burn,
    DataAvailability,
    Fill,
}

/// Proof strategy for processing Bitcoin blocks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofStrategy {
    /// Search for transactions matching patterns (burns, DA)
    Searching(SearchingProof),
    /// Point to a specific transaction with Merkle proof
    Pointing(PointingProof),
}

/// Input for searching strategy - find transactions by pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchingProof {
    /// Pattern to search for (burns, DA, fills)
    pub pattern: TransactionPattern,
}

/// Input for pointing strategy - prove specific transaction exists
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointingProof {
    /// Transaction ID to prove
    pub txid: String,
    /// Expected position in block
    pub tx_position: u32,
    /// Expected transaction type
    pub expected_type: TransactionType,
}

/// Transaction patterns to match during searching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionPattern {
    /// Find all burn transactions (BRN1 prefix)
    Burns,
    /// Find all DA transactions (CORE_LANE prefix)
    DataAvailability,
    /// Find all fill transactions
    Fills,
    /// Find all Core Lane transactions (burns + DA + fills)
    All,
}

/// A Merkle proof path from a transaction to the root
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The transaction ID being proven
    pub txid: [u8; 32],
    /// Path from leaf to root - each element is a sibling hash
    pub path: Vec<[u8; 32]>,
    /// Position indicators: true = right sibling, false = left sibling
    pub positions: Vec<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchingTransaction {
    pub txid: String,
    pub tx_type: TransactionType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinBlockProof {
    /// Block hash (committed in ZK proof)
    pub block_hash: String,
    /// Block height
    pub block_height: u64,
    /// Strategy used to generate this proof
    pub strategy: ProofStrategy,
    /// Matching transaction IDs (each committed in ZK proof)
    pub matching_transactions: Vec<MatchingTransaction>,
    /// Merkle proofs for pointed transactions (only for pointing strategy)
    pub merkle_proofs: Vec<MerkleProof>,
    /// Total number of transactions in the block
    pub total_transactions: u32,
    /// Number of matching transactions found
    pub matching_count: u32,
}

impl BitcoinBlockProof {
    /// Serialize to CBOR format for efficient storage
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        ciborium::into_writer(self, &mut buffer)
            .map_err(|e| anyhow!("CBOR serialization failed: {}", e))?;
        Ok(buffer)
    }

    /// Deserialize from CBOR format
    pub fn from_cbor(data: &[u8]) -> Result<Self> {
        ciborium::from_reader(data).map_err(|e| anyhow!("CBOR deserialization failed: {}", e))
    }
}

/// Metadata about a stored proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// When the proof was generated
    pub generated_at: u64,
    /// Whether the proof has been verified
    pub verified: bool,
    /// Size of the proof file in bytes
    pub size_bytes: u64,
}

/// Cache for ZK proofs with local file storage
pub struct ProofCache {
    /// Directory where proofs are stored
    cache_dir: PathBuf,
}

impl ProofCache {
    /// Create a new proof cache with the given directory
    pub fn new(data_dir: &str) -> Result<Self> {
        let cache_dir = Path::new(data_dir).join("zk_proofs");

        // Create directory if it doesn't exist
        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir)?;
            info!(
                "📁 Created ZK proof cache directory: {}",
                cache_dir.display()
            );
        }

        Ok(Self { cache_dir })
    }

    /// Get proof file path for a given block height
    fn proof_path(&self, block_height: u64) -> PathBuf {
        self.cache_dir.join(format!("{}.json", block_height))
    }

    /// Get metadata file path for a given block height
    fn metadata_path(&self, block_height: u64) -> PathBuf {
        self.cache_dir
            .join(format!("{}.metadata.json", block_height))
    }

    /// Check if a proof exists for the given block height
    pub fn has_proof(&self, block_height: u64) -> bool {
        self.proof_path(block_height).exists()
    }

    /// Get a proof for the given block height
    pub fn get_proof(&self, block_height: u64) -> Result<Option<BitcoinBlockProof>> {
        let proof_path = self.proof_path(block_height);

        if !proof_path.exists() {
            debug!("No ZK proof found for block {}", block_height);
            return Ok(None);
        }

        debug!(
            "Loading ZK proof for block {} from {}",
            block_height,
            proof_path.display()
        );

        let proof_data = fs::read_to_string(&proof_path)?;
        let proof: BitcoinBlockProof = serde_json::from_str(&proof_data)?;

        info!(
            "✅ Loaded ZK proof for block {} ({} matching transactions)",
            block_height, proof.matching_count
        );

        Ok(Some(proof))
    }

    /// Get metadata for a proof
    pub fn get_metadata(&self, block_height: u64) -> Result<Option<ProofMetadata>> {
        let metadata_path = self.metadata_path(block_height);

        if !metadata_path.exists() {
            return Ok(None);
        }

        let metadata_data = fs::read_to_string(&metadata_path)?;
        let metadata: ProofMetadata = serde_json::from_str(&metadata_data)?;

        Ok(Some(metadata))
    }

    /// Store a proof for the given block height
    pub fn store_proof(&self, proof: &BitcoinBlockProof) -> Result<()> {
        let block_height = proof.block_height;
        let proof_path = self.proof_path(block_height);

        debug!(
            "Storing ZK proof for block {} to {}",
            block_height,
            proof_path.display()
        );

        // Serialize proof to JSON
        let proof_data = serde_json::to_string_pretty(&proof)?;

        // Write to file
        fs::write(&proof_path, proof_data.as_bytes())?;

        // Create metadata
        let metadata = ProofMetadata {
            generated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            verified: false, // Will be set to true after verification
            size_bytes: proof_data.len() as u64,
        };

        // Write metadata
        let metadata_path = self.metadata_path(block_height);
        let metadata_data = serde_json::to_string_pretty(&metadata)?;
        fs::write(&metadata_path, metadata_data)?;

        info!(
            "💾 Stored ZK proof for block {} ({} bytes, {} matching transactions)",
            block_height, metadata.size_bytes, proof.matching_count
        );

        Ok(())
    }

    /// Mark a proof as verified
    pub fn mark_verified(&self, block_height: u64) -> Result<()> {
        if let Some(mut metadata) = self.get_metadata(block_height)? {
            metadata.verified = true;

            let metadata_path = self.metadata_path(block_height);
            let metadata_data = serde_json::to_string_pretty(&metadata)?;
            fs::write(&metadata_path, metadata_data)?;

            debug!("✅ Marked proof for block {} as verified", block_height);
        } else {
            warn!(
                "⚠️  Cannot mark proof as verified: no metadata found for block {}",
                block_height
            );
        }

        Ok(())
    }

    /// Get statistics about the proof cache
    pub fn get_stats(&self) -> Result<CacheStats> {
        let mut total_proofs = 0;
        let mut total_size = 0u64;
        let mut verified_proofs = 0;

        if let Ok(entries) = fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json")
                    && !path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .contains("metadata")
                {
                    total_proofs += 1;
                    if let Ok(metadata) = fs::metadata(&path) {
                        total_size += metadata.len();
                    }

                    // Check if verified
                    if let Ok(file_name) = path.file_stem().and_then(|s| s.to_str()).ok_or(()) {
                        if let Ok(height) = file_name.parse::<u64>() {
                            if let Ok(Some(meta)) = self.get_metadata(height) {
                                if meta.verified {
                                    verified_proofs += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(CacheStats {
            total_proofs,
            verified_proofs,
            total_size_bytes: total_size,
        })
    }

    /// Delete a proof (useful for re-generation)
    pub fn delete_proof(&self, block_height: u64) -> Result<()> {
        let proof_path = self.proof_path(block_height);
        let metadata_path = self.metadata_path(block_height);

        if proof_path.exists() {
            fs::remove_file(&proof_path)?;
            debug!("🗑️  Deleted proof for block {}", block_height);
        }

        if metadata_path.exists() {
            fs::remove_file(&metadata_path)?;
        }

        Ok(())
    }
}

/// Statistics about the proof cache
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_proofs: u64,
    pub verified_proofs: u64,
    pub total_size_bytes: u64,
}

impl CacheStats {
    pub fn to_human_readable(&self) -> String {
        let size_mb = self.total_size_bytes as f64 / 1_048_576.0;
        format!(
            "{} proofs ({} verified), {:.2} MB total",
            self.total_proofs, self.verified_proofs, size_mb
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_cache_basic() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache = ProofCache::new(temp_dir.path().to_str().unwrap()).unwrap();

        // Create a test proof
        let proof = BitcoinBlockProof {
            block_hash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
                .to_string(),
            block_height: 100,
            matching_transactions: vec![],
            total_transactions: 10,
            matching_count: 0,
        };

        // Store proof
        cache.store_proof(&proof).unwrap();

        // Verify it exists
        assert!(cache.has_proof(100));

        // Retrieve proof
        let retrieved = cache.get_proof(100).unwrap().unwrap();
        assert_eq!(retrieved.block_height, 100);
        assert_eq!(retrieved.block_hash, proof.block_hash);

        // Mark as verified
        cache.mark_verified(100).unwrap();
        let metadata = cache.get_metadata(100).unwrap().unwrap();
        assert!(metadata.verified);

        // Get stats
        let stats = cache.get_stats().unwrap();
        assert_eq!(stats.total_proofs, 1);
        assert_eq!(stats.verified_proofs, 1);

        // Delete proof
        cache.delete_proof(100).unwrap();
        assert!(!cache.has_proof(100));
    }
}
