# Core Lane Node

Bitcoin-anchored execution environment that processes Bitcoin burns and Core Lane DA transactions with ZK proof integration.

## Features

- **Bitcoin Integration**: Connects to Bitcoin RPC for block processing
- **ZK Proof Support**: Uses zero-knowledge proofs for efficient block verification
- **Merkle Proof Verification**: Supports both searching and pointing proof strategies
- **Non-Existence Verification**: Local Merkle tree caching for transaction verification
- **Intent Processing**: Handles burns, DA transactions, and fill transactions
- **Ethereum Compatibility**: Provides JSON-RPC at port 8545

## ZK Proof Integration

Core Lane automatically uses ZK proofs when available, falling back to full block processing when not.

### Proof Strategies

1. **Searching Strategy**: Finds all Core Lane transactions in a block
2. **Pointing Strategy**: Proves specific transaction exists with Merkle proof
3. **Non-Existence Verification**: Verifies transactions don't exist using local Merkle trees

## End-to-End Testing

### Prerequisites

1. **Clone the repositories**:

   ```bash
   git clone https://github.com/masiedu4/core-lane.git
   git clone https://github.com/masiedu4/bitcoin-zk-proofs.git
   ```

2. **Build the projects**:
   ```bash
   cd bitcoin-zk-proofs && cargo build --release
   cd ../core-lane && cargo build
   ```

### Step 1: Test ZK Proof Generation

```bash
cd bitcoin-zk-proofs

# Test searching strategy (finds all Core Lane transactions)
./target/release/host prove --height 916201 --output test_searching.json --strategy searching

# Test pointing strategy (proves specific transaction with Merkle proof)
./target/release/host prove --height 916201 --output test_pointing.json \
  --strategy "pointing:69c4106b6c0d9ec67b7a0cfa54aed07f202ce99fdabf40e721000f2d4b71ae86:0:da"

# Test with recent blocks
./target/release/host prove --height 916202 --output test_916202.json --strategy searching
./target/release/host prove --height 916203 --output test_916203.json --strategy searching
```

**Expected Results**:

- ✅ Proofs generated in 8-10 seconds
- ✅ Searching proof: ~540 bytes
- ✅ Pointing proof: ~7KB (includes Merkle proof data)
- ✅ 99.97% size reduction vs full blocks (1.7MB)

### Step 2: Test Core Lane Integration

```bash
cd ../core-lane

# Checkout the ZK proof integration branch
git checkout feature/zk-proof-integration

# Project already built in prerequisites

# Copy generated proofs for testing
cp ../bitcoin-zk-proofs/test_searching.json proof_916201.json
cp ../bitcoin-zk-proofs/test_pointing.json proof_916201_pointing.json

# Test ZK proof verification
cargo run --example test_zk_proof

# Test with pointing proof
cargo run --example test_zk_proof proof_916201_pointing.json
```

**Expected Results**:

- ✅ Proofs loaded and parsed successfully
- ✅ Proof verification structure working
- ✅ Proof caching functional
- ✅ Size reduction confirmed

### Step 3: Test Non-Existence Verification

```bash
# Test MerkleCache for non-existence verification
cargo run --example test_non_existence
```

**Expected Results**:

- ✅ MerkleCache creation successful
- ✅ Non-existence verification structure working
- ✅ Cache persistence functional

### Step 4: Performance Benchmarking

```bash
cd ../bitcoin-zk-proofs

# Test with different block sizes
echo "Testing block 1 (genesis):"
./target/release/host prove --height 1 --output genesis.json --strategy searching

echo "Testing block 916201 (Core Lane genesis):"
./target/release/host prove --height 916201 --output large.json --strategy searching

echo "Testing block 916202 (recent):"
./target/release/host prove --height 916202 --output recent.json --strategy searching

# Check proof sizes
ls -la *.json
```

**Expected Performance**:

- **Genesis block**: 280 bytes, ~2 seconds
- **Large blocks**: 540 bytes, ~8 seconds
- **Size reduction**: 99.97% vs full blocks
- **Speed improvement**: 75x faster than local processing

### Step 5: Integration Testing

```bash
cd ../core-lane

# Test end-to-end workflow
cargo run --example test_zk_proof ../bitcoin-zk-proofs/test_searching.json
cargo run --example test_zk_proof ../bitcoin-zk-proofs/test_pointing.json

# Verify proof caching
ls -la /tmp/core_lane_test_proofs/
```





## Troubleshooting

### RPC Connection Issues

If you see "JSON-RPC error: transport error: unexpected HTTP code: 400", this is expected with public Bitcoin RPC endpoints. The proof structure validation will still work.

### Missing Dependencies

Ensure all dependencies are installed:

```bash
cargo build --release
```

### Build Issues

Make sure you have the latest Rust toolchain:

```bash
rustup update
cargo clean
cargo build --release
```

## Contributing

This is an early implementation. The architecture and APIs may change significantly as development progresses.

## License

All rights reserved for now
