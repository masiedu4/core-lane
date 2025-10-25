//! ZK Proof Integration Module
//!
//! This module integrates ZK proof verification into Core Lane's block processing.
//! It checks for proofs before falling back to full block processing.

use anyhow::Result;
use bitcoincore_rpc::{Client, RpcApi};
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::block::CoreLaneBlockParsed;
use crate::zk_proof_storage::{BitcoinBlockProof, ProofCache, TransactionType};
use crate::zk_proof_verifier::ProofVerifier;

/// Process a Bitcoin block, using ZK proof if available
pub fn process_block_with_proof(
    bitcoin_client: Arc<Client>,
    height: u64,
    proof_cache: &ProofCache,
    proof_verifier: &mut ProofVerifier,
) -> Result<CoreLaneBlockParsed> {
    debug!("Processing block {} (checking for ZK proof first)", height);

    // Step 1: Check if we have a ZK proof for this block
    if let Some(proof) = proof_cache.get_proof(height)? {
        info!("📋 Found ZK proof for block {}", height);

        // Step 2: Verify the proof
        match proof_verifier.verify_proof(&proof) {
            Ok(true) => {
                info!("✅ ZK proof verified for block {}", height);

                // Step 3: Build CoreLaneBlockParsed from proof
                return build_block_from_proof(bitcoin_client, proof);
            }
            Ok(false) => {
                warn!("❌ ZK proof verification failed for block {}", height);
                warn!("   Falling back to full block processing");
            }
            Err(e) => {
                warn!("⚠️  Error verifying ZK proof for block {}: {}", height, e);
                warn!("   Falling back to full block processing");
            }
        }
    } else {
        debug!(
            "No ZK proof found for block {}, using full processing",
            height
        );
    }

    // Fallback: Process full block
    crate::bitcoin_block::process_bitcoin_block(bitcoin_client, height)
}

/// Build CoreLaneBlockParsed from a verified ZK proof
fn build_block_from_proof(
    bitcoin_client: Arc<Client>,
    proof: BitcoinBlockProof,
) -> Result<CoreLaneBlockParsed> {
    info!(
        "🚀 Building block from ZK proof ({} matching transactions)",
        proof.matching_count
    );

    // Parse block hash
    let block_hash = bitcoin::BlockHash::from_str(&proof.block_hash)?;

    // Fetch the block to get transactions and timestamp
    let block = bitcoin_client.get_block(&block_hash)?;

    // Get parent hash and block hash as bytes
    let parent_hash_bytes: Vec<u8> = block.header.prev_blockhash[..].to_vec();
    let block_hash_bytes: Vec<u8> = block_hash[..].to_vec();

    // Create the parsed block
    let mut parsed_block = CoreLaneBlockParsed::new(
        block_hash_bytes,
        block.header.time as u64,
        proof.block_height,
        parent_hash_bytes,
    );

            // Process each matching transaction from the proof
            for matching_tx in proof.matching_transactions {
                // Find the transaction in the block
                let tx = block
                    .txdata
                    .iter()
                    .find(|tx| tx.compute_txid().to_string() == matching_tx.txid);

                if let Some(tx) = tx {
                    // Process based on transaction type
                    match matching_tx.tx_type {
                        TransactionType::Burn => {
                            debug!("   Processing burn transaction: {}", matching_tx.txid);
                            if let Some((payload, burn_value)) = extract_burn_from_tx(tx) {
                                if let Ok(burn) =
                                    process_burn_transaction(payload, burn_value, matching_tx.txid.clone())
                                {
                                    parsed_block.add_burn(burn);
                                }
                            }
                        }
                        TransactionType::DataAvailability => {
                            debug!("   Processing DA transaction: {}", matching_tx.txid);
                            if let Some(lane_tx) = extract_da_from_tx(tx) {
                                if let Some((tx_env, sender)) = crate::block::decode_tx_envelope(&lane_tx) {
                                    parsed_block.add_bundle_from_single_tx(tx_env, sender, lane_tx);
                                }
                            }
                        }
                        TransactionType::Fill => {
                            debug!("   Processing fill transaction: {}", matching_tx.txid);
                            if let Some(fill_data) = extract_fill_from_tx(tx) {
                                if let Ok(_fill) = process_fill_transaction(fill_data, matching_tx.txid.clone()) {
                                    // TODO: Add fill to parsed_block when CoreLaneBlockParsed supports it
                                    debug!("   Fill transaction processed: {}", matching_tx.txid);
                                }
                            }
                        }
                    }
                } else {
                    warn!(
                        "⚠️  Transaction {} not found in block (this shouldn't happen after verification)",
                        matching_tx.txid
                    );
                }
            }

    info!(
        "✅ Built block from ZK proof: {} burns, {} bundles",
        parsed_block.burns.len(),
        parsed_block.bundles.len()
    );

    Ok(parsed_block)
}

/// Extract burn transaction data
fn extract_burn_from_tx(tx: &bitcoin::Transaction) -> Option<(Vec<u8>, u64)> {
    let mut p2wsh_burn_value = 0u64;
    let mut brn1_payload = None;

    for output in &tx.output {
        // Check for P2WSH burn outputs
        let script_bytes = output.script_pubkey.as_bytes();
        if script_bytes.len() == 34 && script_bytes[0] == 0x00 {
            p2wsh_burn_value = output.value.to_sat();
        }

        // Check for OP_RETURN with BRN1 data
        if output.script_pubkey.is_op_return() {
            let payload_bytes = output.script_pubkey.as_bytes();
            if payload_bytes.len() >= 30 && payload_bytes[0] == 0x6a {
                let data = &payload_bytes[2..];
                if data.len() >= 28 && &data[0..4] == b"BRN1" {
                    let mut payload = Vec::with_capacity(28);
                    payload.extend_from_slice(b"BRN1");
                    payload.extend_from_slice(&data[4..8]);
                    payload.extend_from_slice(&data[8..28]);
                    brn1_payload = Some(payload);
                }
            }
        }
    }

    if p2wsh_burn_value > 0 {
        if let Some(payload) = brn1_payload {
            return Some((payload, p2wsh_burn_value));
        }
    }

    None
}

/// Extract DA transaction data
fn extract_da_from_tx(tx: &bitcoin::Transaction) -> Option<Vec<u8>> {
    use bitcoin::opcodes::all::{OP_ENDIF, OP_IF};
    use bitcoin::opcodes::{OP_FALSE, OP_TRUE};
    use bitcoin::script::Instruction;
    use bitcoin::Script;

    // Check inputs for witness data (revealed Taproot envelopes)
    for input in &tx.input {
        if input.witness.len() >= 2 {
            if let Some(script_bytes) = input.witness.to_vec().first() {
                let script = Script::from_bytes(script_bytes);

                // Extract envelope data
                let mut instr = script.instructions();

                let first = instr.next().and_then(|r| r.ok());
                if first != Some(Instruction::Op(OP_FALSE))
                    && first
                        != Some(Instruction::PushBytes(
                            bitcoin::blockdata::script::PushBytes::empty(),
                        ))
                {
                    continue;
                }

                if instr.next().and_then(|r| r.ok()) != Some(Instruction::Op(OP_IF)) {
                    continue;
                }

                let mut push_operations: Vec<Vec<u8>> = Vec::new();
                loop {
                    match instr.next().and_then(|r| r.ok()) {
                        Some(Instruction::Op(OP_ENDIF)) => break,
                        Some(Instruction::PushBytes(b)) => {
                            push_operations.push(b.as_bytes().to_vec());
                        }
                        _ => break,
                    }
                }

                let last = instr.next().and_then(|r| r.ok());
                if last != Some(Instruction::Op(OP_TRUE))
                    && last
                        != Some(Instruction::Op(
                            bitcoin::blockdata::opcodes::all::OP_PUSHNUM_1,
                        ))
                {
                    continue;
                }

                // Concatenate all push operations
                let mut data: Vec<u8> = Vec::new();
                for push_op in push_operations {
                    data.extend_from_slice(&push_op);
                }

                // Check for CORE_LANE prefix
                if data.starts_with(b"CORE_LANE") {
                    let tx_data = &data[9..];

                    // Remove padding
                    let mut clean_end = tx_data.len();
                    for i in (0..tx_data.len()).rev() {
                        if tx_data[i] == 0xf0 {
                            clean_end = i;
                        } else {
                            break;
                        }
                    }

                    return Some(tx_data[..clean_end].to_vec());
                }
            }
        }
    }

    None
}

/// Process burn transaction payload
fn process_burn_transaction(
    payload: Vec<u8>,
    burn_value: u64,
    _txid: String,
) -> Result<crate::block::CoreLaneBurn> {
    use alloy_primitives::{Address, U256};

    if payload.len() >= 28 && &payload[0..4] == b"BRN1" {
        let chain_id = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let eth_address_bytes = &payload[8..28];
        let eth_address = Address::from_slice(eth_address_bytes);

        if chain_id == 1 {
            let conversion_factor = U256::from(10_000_000_000u64);
            let mint_amount = U256::from(burn_value) * conversion_factor;

            info!(
                "   🔥 Burn: {} sats -> {} tokens to {}",
                burn_value, mint_amount, eth_address
            );

            return Ok(crate::block::CoreLaneBurn::new(mint_amount, eth_address));
        } else {
            return Err(anyhow::anyhow!(
                "Burn for different chain ID ({})",
                chain_id
            ));
        }
    }

    Err(anyhow::anyhow!("Invalid BRN1 payload format"))
}

/// Extract fill transaction data
fn extract_fill_from_tx(tx: &bitcoin::Transaction) -> Option<FillData> {
    // Look for OP_RETURN with FILL data
    for output in &tx.output {
        if output.script_pubkey.is_op_return() {
            let script_bytes = output.script_pubkey.as_bytes();
            if script_bytes.len() >= 6 {
                let data_start = 2; // Skip OP_RETURN and push opcode
                if script_bytes.len() > data_start + 4 {
                    let prefix = &script_bytes[data_start..data_start + 4];
                    if prefix == b"FILL" {
                        // Extract fill data (simplified)
                        let fill_data = &script_bytes[data_start + 4..];
                        return Some(FillData {
                            bitcoin_address: "".to_string(), // Would extract from fill data
                            amount: output.value.to_sat(),
                            fill_data: fill_data.to_vec(),
                        });
                    }
                }
            }
        }
    }
    None
}

/// Process fill transaction
fn process_fill_transaction(fill_data: FillData, _txid: String) -> Result<CoreLaneFill> {
    // In practice, this would match against pending intents
    // and mark them as filled
    Ok(CoreLaneFill {
        bitcoin_address: fill_data.bitcoin_address,
        amount: fill_data.amount,
        fill_data: fill_data.fill_data,
    })
}

/// Data extracted from a fill transaction
#[derive(Debug, Clone)]
struct FillData {
    bitcoin_address: String,
    amount: u64,
    fill_data: Vec<u8>,
}

/// Core Lane fill transaction
#[derive(Debug, Clone)]
pub struct CoreLaneFill {
    pub bitcoin_address: String,
    pub amount: u64,
    pub fill_data: Vec<u8>,
}

/// Verify that a transaction does not exist in a block
pub fn verify_tx_non_existence(
    block_height: u64,
    txid: &str,
    proof_verifier: &mut ProofVerifier,
) -> Result<bool> {
    info!("🔍 Verifying non-existence of transaction {} in block {}", txid, block_height);
    
    let non_existent = proof_verifier.verify_tx_non_existence(block_height, txid)?;
    
    if non_existent {
        info!("✅ Confirmed: transaction {} does not exist in block {}", txid, block_height);
    } else {
        info!("❌ Transaction {} exists in block {}", txid, block_height);
    }
    
    Ok(non_existent)
}
