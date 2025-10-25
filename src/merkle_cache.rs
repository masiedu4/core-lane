//! Merkle Cache Module
//!
//! This module provides local caching of Merkle trees for Bitcoin blocks,
//! enabling efficient non-existence verification without repeatedly downloading
//! all transaction IDs for the same block.

use anyhow::{anyhow, Result};
use bitcoincore_rpc::{Client, RpcApi};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// A local Merkle tree for a Bitcoin block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalMerkleTree {
    /// All transaction IDs in the block
    pub txids: Vec<String>,
    /// The Merkle root of the block
    pub merkle_root: [u8; 32],
    /// Block height
    pub block_height: u64,
    /// Block hash
    pub block_hash: String,
}

/// Cache for Merkle trees with local file storage
pub struct MerkleCache {
    /// Directory where Merkle trees are cached
    cache_dir: PathBuf,
    /// In-memory cache for frequently accessed trees
    memory_cache: HashMap<u64, LocalMerkleTree>,
}

impl MerkleCache {
    /// Create a new Merkle cache with the given directory
    pub fn new(data_dir: &str) -> Result<Self> {
        let cache_dir = Path::new(data_dir).join("merkle_cache");

        // Create directory if it doesn't exist
        if !cache_dir.exists() {
            fs::create_dir_all(&cache_dir)?;
            info!("📁 Created Merkle cache directory: {}", cache_dir.display());
        }

        Ok(Self {
            cache_dir,
            memory_cache: HashMap::new(),
        })
    }

    /// Get or build a Merkle tree for the given block height
    pub fn get_or_build(
        &mut self,
        block_height: u64,
        bitcoin_client: &Client,
    ) -> Result<LocalMerkleTree> {
        // Check memory cache first
        if let Some(tree) = self.memory_cache.get(&block_height) {
            debug!(
                "📋 Found Merkle tree for block {} in memory cache",
                block_height
            );
            return Ok(tree.clone());
        }

        // Check disk cache
        if let Some(tree) = self.load_from_disk(block_height)? {
            debug!("💾 Found Merkle tree for block {} on disk", block_height);
            // Add to memory cache
            self.memory_cache.insert(block_height, tree.clone());
            return Ok(tree);
        }

        // Build new tree
        info!("🔨 Building Merkle tree for block {}", block_height);
        let tree = self.build_merkle_tree(block_height, bitcoin_client)?;

        // Save to disk
        self.save_to_disk(&tree)?;

        // Add to memory cache
        self.memory_cache.insert(block_height, tree.clone());

        Ok(tree)
    }

    /// Check if a Merkle tree is cached for the given block height
    pub fn has_cache(&self, block_height: u64) -> bool {
        self.memory_cache.contains_key(&block_height) || self.cache_file_path(block_height).exists()
    }

    /// Verify that a transaction does not exist in a block
    pub fn verify_non_existence(
        &mut self,
        block_height: u64,
        txid: &str,
        bitcoin_client: &Client,
    ) -> Result<bool> {
        let tree = self.get_or_build(block_height, bitcoin_client)?;

        // Check if txid exists in the tree
        let exists = tree.txids.contains(&txid.to_string());

        debug!(
            "🔍 Transaction {} {} in block {}",
            txid,
            if exists { "exists" } else { "does not exist" },
            block_height
        );

        Ok(!exists)
    }

    /// Build a Merkle tree for a block by downloading all transaction IDs
    fn build_merkle_tree(
        &self,
        block_height: u64,
        bitcoin_client: &Client,
    ) -> Result<LocalMerkleTree> {
        // Get block hash
        let block_hash = bitcoin_client.get_block_hash(block_height)?;

        // Get block with transaction list (verbosity=1 returns txids only)
        let block_info = bitcoin_client.get_block_info(&block_hash)?;

        // Get all transaction IDs
        let txids: Vec<String> = block_info.tx.iter().map(|tx| tx.to_string()).collect();

        info!(
            "📦 Downloaded {} transaction IDs for block {}",
            txids.len(),
            block_height
        );

        // Build Merkle tree (simplified - in practice you'd use the actual Merkle tree implementation)
        // For now, we'll just store the txids and compute a simple hash
        let merkle_root = self.compute_simple_merkle_root(&txids);

        Ok(LocalMerkleTree {
            txids,
            merkle_root,
            block_height,
            block_hash: block_hash.to_string(),
        })
    }

    /// Compute a simple Merkle root (placeholder implementation)
    /// In practice, this should use the same algorithm as the ZK proof system
    fn compute_simple_merkle_root(&self, txids: &[String]) -> [u8; 32] {
        use bitcoin::hashes::{sha256, Hash, HashEngine};

        if txids.is_empty() {
            return [0u8; 32];
        }

        if txids.len() == 1 {
            let mut engine = sha256::HashEngine::default();
            engine.input(txids[0].as_bytes());
            let hash = sha256::Hash::from_engine(engine);
            return hash.to_byte_array();
        }

        // Simple binary tree construction
        let mut current_level = txids.to_vec();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for i in (0..current_level.len()).step_by(2) {
                let left = &current_level[i];
                let right = if i + 1 < current_level.len() {
                    &current_level[i + 1]
                } else {
                    &current_level[i] // Duplicate last element if odd
                };

                let mut engine = sha256::HashEngine::default();
                engine.input(left.as_bytes());
                engine.input(right.as_bytes());
                let hash = sha256::Hash::from_engine(engine);
                next_level.push(hex::encode(hash.to_byte_array()));
            }

            current_level = next_level;
        }

        // Convert final hash to [u8; 32]
        let final_hash = match hex::decode(&current_level[0]) {
            Ok(hash) => hash,
            Err(e) => {
                warn!("Failed to decode hash: {}", e);
                return [0u8; 32];
            }
        };

        if final_hash.len() != 32 {
            return [0u8; 32];
        }

        let mut result = [0u8; 32];
        result.copy_from_slice(&final_hash);
        result
    }

    /// Get cache file path for a block height
    fn cache_file_path(&self, block_height: u64) -> PathBuf {
        self.cache_dir.join(format!("{}.json", block_height))
    }

    /// Load Merkle tree from disk
    fn load_from_disk(&self, block_height: u64) -> Result<Option<LocalMerkleTree>> {
        let path = self.cache_file_path(block_height);

        if !path.exists() {
            return Ok(None);
        }

        let data = fs::read_to_string(&path)?;
        let tree: LocalMerkleTree = serde_json::from_str(&data)
            .map_err(|e| anyhow!("Failed to deserialize Merkle tree: {}", e))?;

        Ok(Some(tree))
    }

    /// Save Merkle tree to disk
    fn save_to_disk(&self, tree: &LocalMerkleTree) -> Result<()> {
        let path = self.cache_file_path(tree.block_height);

        let data = serde_json::to_string_pretty(tree)
            .map_err(|e| anyhow!("Failed to serialize Merkle tree: {}", e))?;

        fs::write(&path, data)?;

        debug!(
            "💾 Saved Merkle tree for block {} to {}",
            tree.block_height,
            path.display()
        );

        Ok(())
    }

    /// Get cache statistics
    pub fn get_stats(&self) -> Result<CacheStats> {
        let mut total_trees = 0;
        let mut total_size = 0u64;

        if let Ok(entries) = fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("json") {
                    total_trees += 1;
                    if let Ok(metadata) = fs::metadata(&path) {
                        total_size += metadata.len();
                    }
                }
            }
        }

        Ok(CacheStats {
            total_trees,
            memory_cached: self.memory_cache.len() as u64,
            total_size_bytes: total_size,
        })
    }

    /// Clear memory cache
    pub fn clear_memory_cache(&mut self) {
        self.memory_cache.clear();
        info!("🧹 Cleared Merkle tree memory cache");
    }
}

/// Statistics about the Merkle cache
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_trees: u64,
    pub memory_cached: u64,
    pub total_size_bytes: u64,
}

impl CacheStats {
    pub fn to_human_readable(&self) -> String {
        let size_mb = self.total_size_bytes as f64 / 1_048_576.0;
        format!(
            "{} trees cached ({} in memory), {:.2} MB total",
            self.total_trees, self.memory_cached, size_mb
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_merkle_cache_basic() {
        let temp_dir = std::env::temp_dir().join("merkle_cache_test");
        fs::create_dir_all(&temp_dir).unwrap();

        let mut cache = MerkleCache::new(temp_dir.to_str().unwrap()).unwrap();

        // Test cache stats
        let stats = cache.get_stats().unwrap();
        assert_eq!(stats.total_trees, 0);
        assert_eq!(stats.memory_cached, 0);

        // Test non-existence check (would need mock Bitcoin client)
        // For now, just test that the cache can be created
        assert!(!cache.has_cache(100));

        // Clean up
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
