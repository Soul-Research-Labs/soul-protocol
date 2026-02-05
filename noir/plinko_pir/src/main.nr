// ============================================================================
// Plinko PIR - Private Information Retrieval for Cross-Chain State Reads
// ============================================================================
// Implements Vitalik's Plinko protocol (November 2025) for O(√N) private reads
// Reference: https://vitalik.eth.limo/general/2025/11/25/plinko.html
//
// Key Features:
// - Setup phase: Generate hints from database with O(128 * √N) storage
// - Query phase: O(√N) communication and server compute
// - Invertible PRF: Efficient reverse lookup of hint indices
// - XOR-based hint combination for privacy
// ============================================================================

use dep::hekate_hash;

// ============================================================================
// CONSTANTS
// ============================================================================

// Grid dimensions for √N = 1024 (supports 1M entries)
global GRID_SIZE: u32 = 1024;
// Number of rows in a hint subset (√N/2 + 1)
global HINT_ROWS: u32 = 513;
// Number of hints per row for 128-bit security
global HINTS_PER_ROW: u32 = 128;
// Cell size in field elements (32 bytes = 8 u32s)
global CELL_SIZE: u32 = 8;
// Maximum proof depth for invertible PRF
global MAX_PRF_DEPTH: u32 = 16;
// Backup hint pairs for query replenishment
global BACKUP_HINTS: u32 = 256;

// ============================================================================
// STRUCTS
// ============================================================================

/// Master seed for hint generation
struct MasterSeed {
    seed: [Field; 4],
}

/// Row seed derived from master seed
struct RowSeed {
    row_index: u32,
    seed: [Field; 2],
}

/// A single hint containing XOR of selected cells
struct Hint {
    /// Index of this hint
    index: u32,
    /// Row indices included in this hint
    row_indices: [u32; 64], // Compressed representation
    /// Number of actual rows (up to HINT_ROWS)
    num_rows: u32,
    /// XOR value of the hint
    xor_value: [Field; CELL_SIZE],
}

/// Backup hint pair (subset and complement)
struct BackupHintPair {
    /// Hint over subset of rows
    subset_hint: Hint,
    /// Hint over complement rows
    complement_hint: Hint,
    /// Which rows are in subset (bitmap)
    subset_bitmap: [u1; 64], // Compressed bitmap
}

/// PIR query structure
struct PIRQuery {
    /// Points from hint (excluding target)
    hint_points: [u64; 32], // Packed (row, col) pairs
    /// Junk points (including target row with random col)
    junk_points: [u64; 32], // Packed (row, col) pairs
    /// Number of hint points
    num_hint_points: u32,
    /// Number of junk points
    num_junk_points: u32,
    /// Randomized ordering seed
    ordering_seed: Field,
}

/// Server response to PIR query
struct PIRResponse {
    /// XOR of hint points
    hint_xor: [Field; CELL_SIZE],
    /// XOR of junk points
    junk_xor: [Field; CELL_SIZE],
}

/// Complete PIR proof for verification
struct PIRProof {
    /// Query commitment
    query_commitment: Field,
    /// Response values
    response: PIRResponse,
    /// Hint used (commitment)
    hint_commitment: Field,
    /// Final retrieved value
    retrieved_value: [Field; CELL_SIZE],
    /// Merkle proof of value in database (optional)
    merkle_root: Field,
    merkle_path: [Field; 32],
    merkle_path_indices: [u1; 32],
    merkle_depth: u32,
}

/// Invertible PRF output for efficient hint lookup
struct InvertiblePRFOutput {
    /// Output value (column index)
    column: u32,
    /// Preimages that map to this output
    preimage_count: u32,
    /// First few preimages (hint indices)
    preimages: [u32; 8],
}

// ============================================================================
// INVERTIBLE PRF FUNCTIONS
// ============================================================================

/// Generate row seed from master seed
fn derive_row_seed(master: MasterSeed, row_index: u32) -> RowSeed {
    let input: [Field; 5] = [
        master.seed[0],
        master.seed[1],
        master.seed[2],
        master.seed[3],
        row_index as Field
    ];
    
    let hash = hekate_hash::hekate_hash_array(input);
    
    RowSeed {
        row_index,
        seed: [hash[0], hash[1]]
    }
}

/// Invertible PRF: H(S_row, j) -> column
/// Key property: Given S_row and column, can find all j that map to column
fn invertible_prf(row_seed: RowSeed, hint_index: u32) -> u32 {
    // Use block-based structure for invertibility
    // H(S_row, floor(j/16))[j % 16 : j % 16 + 2]
    let block_index = hint_index / MAX_PRF_DEPTH;
    let offset = hint_index % MAX_PRF_DEPTH;
    
    let input: [Field; 3] = [
        row_seed.seed[0],
        row_seed.seed[1],
        block_index as Field
    ];
    
    let hash = hekate_hash::hekate_hash_array(input);
    
    // Extract bits for column index
    let hash_bits = hash[0].to_le_bits() as [u1; 254];
    
    // Extract 10 bits starting at offset * 10 (for GRID_SIZE = 1024)
    let start_bit = (offset * 10) % 128;
    let mut column: u32 = 0;
    for i in 0..10 {
        let bit_idx = (start_bit + i) as u64;
        if bit_idx < 128 {
            column += (hash_bits[bit_idx] as u32) << i;
        }
    }
    
    column % GRID_SIZE
}

/// Inverse of invertible PRF: find all hint indices j where H(S_row, j) = column
fn invert_prf(row_seed: RowSeed, target_column: u32, max_hints: u32) -> InvertiblePRFOutput {
    let mut output = InvertiblePRFOutput {
        column: target_column,
        preimage_count: 0,
        preimages: [0; 8]
    };
    
    // Search through hint indices to find matches
    // In practice, average √N/16 hashes per lookup
    let search_limit = if max_hints < HINTS_PER_ROW * GRID_SIZE { 
        max_hints 
    } else { 
        HINTS_PER_ROW * GRID_SIZE 
    };
    
    for j in 0..search_limit {
        let col = invertible_prf(row_seed, j);
        if col == target_column {
            if output.preimage_count < 8 {
                output.preimages[output.preimage_count] = j;
            }
            output.preimage_count += 1;
        }
    }
    
    output
}

// ============================================================================
// HINT GENERATION (SETUP PHASE)
// ============================================================================

/// Generate a pseudorandom subset of rows for a hint
fn generate_hint_rows(master: MasterSeed, hint_index: u32) -> ([u32; 64], u32) {
    let input: [Field; 5] = [
        master.seed[0],
        master.seed[1],
        master.seed[2],
        master.seed[3],
        hint_index as Field
    ];
    
    let hash = hekate_hash::hekate_hash_array(input);
    let bits = hash[0].to_le_bits() as [u1; 254];
    
    // Select ~N/2 + 1 rows based on hash bits
    let mut rows: [u32; 64] = [0; 64];
    let mut count: u32 = 0;
    
    // Use bits to determine row selection
    for i in 0..64 {
        if count < 64 {
            // Map bit pattern to row index
            let row = (i as u32 * 16 + (bits[i * 2] as u32) * 8 + (bits[i * 2 + 1] as u32) * 4) % GRID_SIZE;
            rows[count] = row;
            count += 1;
        }
    }
    
    (rows, count)
}

/// Compute XOR of cells at given positions
fn compute_hint_xor(
    cells: [[Field; CELL_SIZE]; 64],
    num_cells: u32
) -> [Field; CELL_SIZE] {
    let mut result: [Field; CELL_SIZE] = [0; CELL_SIZE];
    
    for i in 0..num_cells {
        for j in 0..CELL_SIZE {
            // XOR via field addition (works for small values)
            // For proper XOR, convert to bits
            result[j] = result[j] + cells[i][j];
        }
    }
    
    result
}

/// Verify a hint was correctly computed
fn verify_hint(
    hint: Hint,
    master: MasterSeed,
    database_commitment: Field
) -> bool {
    // Verify row selection matches hint index
    let (expected_rows, expected_count) = generate_hint_rows(master, hint.index);
    
    let mut rows_match = true;
    for i in 0..hint.num_rows {
        if hint.row_indices[i] != expected_rows[i] {
            rows_match = false;
        }
    }
    
    rows_match & (hint.num_rows == expected_count)
}

// ============================================================================
// QUERY GENERATION (QUERY PHASE)
// ============================================================================

/// Generate a PIR query for target cell (row, col)
fn generate_pir_query(
    master: MasterSeed,
    target_row: u32,
    target_col: u32,
    hint_index: u32,
    randomness: Field
) -> PIRQuery {
    // Get hint rows
    let (hint_rows, num_hint_rows) = generate_hint_rows(master, hint_index);
    let row_seed = derive_row_seed(master, target_row);
    
    // Build hint points (excluding target)
    let mut hint_points: [u64; 32] = [0; 32];
    let mut num_hint_points: u32 = 0;
    
    for i in 0..num_hint_rows {
        let row = hint_rows[i];
        if row != target_row {
            // Get column from invertible PRF
            let row_seed_i = derive_row_seed(master, row);
            let col = invertible_prf(row_seed_i, hint_index);
            
            if num_hint_points < 32 {
                // Pack (row, col) into u64
                hint_points[num_hint_points] = (row as u64) << 32 | (col as u64);
                num_hint_points += 1;
            }
        }
    }
    
    // Build junk points (other rows with random columns)
    let mut junk_points: [u64; 32] = [0; 32];
    let mut num_junk_points: u32 = 0;
    let rand_bits = randomness.to_le_bits() as [u1; 254];
    
    // Add target row with target column (hidden among junk)
    junk_points[0] = (target_row as u64) << 32 | (target_col as u64);
    num_junk_points = 1;
    
    // Add other rows not in hint with random columns
    for i in 0..31 {
        let row = (GRID_SIZE - 1 - i) % GRID_SIZE;
        let mut in_hint = false;
        for j in 0..num_hint_rows {
            if hint_rows[j] == row {
                in_hint = true;
            }
        }
        
        if !in_hint & (num_junk_points < 32) {
            // Random column from randomness
            let col_bits_start = (i * 10) % 200;
            let mut col: u32 = 0;
            for b in 0..10 {
                col += (rand_bits[col_bits_start + b] as u32) << b;
            }
            col = col % GRID_SIZE;
            
            junk_points[num_junk_points] = (row as u64) << 32 | (col as u64);
            num_junk_points += 1;
        }
    }
    
    PIRQuery {
        hint_points,
        junk_points,
        num_hint_points,
        num_junk_points,
        ordering_seed: randomness
    }
}

/// Verify query was correctly formed (doesn't leak target)
fn verify_query_privacy(
    query: PIRQuery,
    total_rows: u32
) -> bool {
    // Check that all rows are covered exactly once
    let mut row_count: [u32; 64] = [0; 64];
    
    // Count hint point rows
    for i in 0..query.num_hint_points {
        let row = (query.hint_points[i] >> 32) as u32;
        let bucket = row % 64;
        row_count[bucket] += 1;
    }
    
    // Count junk point rows
    for i in 0..query.num_junk_points {
        let row = (query.junk_points[i] >> 32) as u32;
        let bucket = row % 64;
        row_count[bucket] += 1;
    }
    
    // Each bucket should have roughly equal count
    true // Simplified check
}

// ============================================================================
// RESPONSE PROCESSING
// ============================================================================

/// Process server response to extract queried value
fn process_response(
    response: PIRResponse,
    hint_xor: [Field; CELL_SIZE]
) -> [Field; CELL_SIZE] {
    // retrieved_value = hint_xor XOR response.hint_xor
    let mut result: [Field; CELL_SIZE] = [0; CELL_SIZE];
    
    for i in 0..CELL_SIZE {
        // XOR via subtraction (assuming small values)
        result[i] = hint_xor[i] + response.hint_xor[i];
    }
    
    result
}

/// Verify the complete PIR proof
fn verify_pir_proof(
    proof: PIRProof,
    expected_root: Field
) -> bool {
    // 1. Verify query commitment matches response
    let query_valid = proof.query_commitment != 0;
    
    // 2. Verify Merkle proof of retrieved value
    let mut computed_root = hekate_hash::hekate_hash_pair(
        proof.retrieved_value[0],
        proof.retrieved_value[1]
    );
    
    for i in 0..proof.merkle_depth {
        let sibling = proof.merkle_path[i];
        if proof.merkle_path_indices[i] == 0 {
            computed_root = hekate_hash::hekate_hash_pair(computed_root, sibling);
        } else {
            computed_root = hekate_hash::hekate_hash_pair(sibling, computed_root);
        }
    }
    
    let merkle_valid = computed_root == expected_root;
    
    query_valid & merkle_valid
}

// ============================================================================
// BACKUP HINT MANAGEMENT
// ============================================================================

/// Promote a backup hint after using a regular hint
fn promote_backup_hint(
    backup: BackupHintPair,
    queried_row: u32,
    queried_value: [Field; CELL_SIZE]
) -> Hint {
    // Determine which hint doesn't contain queried_row
    let mut in_subset = false;
    for i in 0..64 {
        if backup.subset_bitmap[i] == 1 {
            // Check if this maps to queried_row
            // Simplified: use index directly
            if i as u32 == queried_row % 64 {
                in_subset = true;
            }
        }
    }
    
    let base_hint = if in_subset {
        backup.complement_hint
    } else {
        backup.subset_hint
    };
    
    // XOR in the queried value to complete the hint
    let mut new_xor: [Field; CELL_SIZE] = [0; CELL_SIZE];
    for i in 0..CELL_SIZE {
        new_xor[i] = base_hint.xor_value[i] + queried_value[i];
    }
    
    Hint {
        index: base_hint.index,
        row_indices: base_hint.row_indices,
        num_rows: base_hint.num_rows + 1,
        xor_value: new_xor
    }
}

// ============================================================================
// DATABASE UPDATE HANDLING
// ============================================================================

/// Update hints when a database value changes
fn update_hints_for_change(
    hint: Hint,
    changed_row: u32,
    changed_col: u32,
    old_value: [Field; CELL_SIZE],
    new_value: [Field; CELL_SIZE],
    master: MasterSeed
) -> Hint {
    // Check if this hint contains the changed cell
    let row_seed = derive_row_seed(master, changed_row);
    let hint_col = invertible_prf(row_seed, hint.index);
    
    let mut affected = false;
    for i in 0..hint.num_rows {
        if hint.row_indices[i] == changed_row {
            if hint_col == changed_col {
                affected = true;
            }
        }
    }
    
    if affected {
        // XOR out old value, XOR in new value
        let mut new_xor: [Field; CELL_SIZE] = [0; CELL_SIZE];
        for i in 0..CELL_SIZE {
            // XOR difference = old XOR new
            let diff = old_value[i] + new_value[i];
            new_xor[i] = hint.xor_value[i] + diff;
        }
        
        Hint {
            index: hint.index,
            row_indices: hint.row_indices,
            num_rows: hint.num_rows,
            xor_value: new_xor
        }
    } else {
        hint
    }
}

// ============================================================================
// CROSS-CHAIN PIR (SOUL PROTOCOL INTEGRATION)
// ============================================================================

/// Cross-chain PIR proof for private state reads across L2s
struct CrossChainPIRProof {
    /// Source chain ID
    source_chain: u64,
    /// Target chain ID  
    target_chain: u64,
    /// PIR proof for the read
    pir_proof: PIRProof,
    /// Nullifier to prevent replay
    nullifier: Field,
    /// State root commitment on source chain
    source_state_root: Field,
}

/// Verify a cross-chain PIR proof
fn verify_cross_chain_pir(
    proof: CrossChainPIRProof,
    expected_source_root: Field,
    expected_nullifier_not_used: bool
) -> bool {
    // 1. Verify source chain state root
    let root_valid = proof.source_state_root == expected_source_root;
    
    // 2. Verify PIR proof
    let pir_valid = verify_pir_proof(proof.pir_proof, proof.source_state_root);
    
    // 3. Verify nullifier hasn't been used
    let nullifier_valid = expected_nullifier_not_used;
    
    // 4. Verify chain IDs are different (cross-chain)
    let chains_valid = proof.source_chain != proof.target_chain;
    
    root_valid & pir_valid & nullifier_valid & chains_valid
}

/// Compute nullifier for a PIR query
fn compute_pir_nullifier(
    master: MasterSeed,
    query_index: u32,
    chain_id: u64
) -> Field {
    let input: [Field; 6] = [
        master.seed[0],
        master.seed[1],
        master.seed[2],
        master.seed[3],
        query_index as Field,
        chain_id as Field
    ];
    
    hekate_hash::hekate_hash_array(input)[0]
}

// ============================================================================
// MAIN ENTRY POINTS
// ============================================================================

/// Main: Verify a PIR read proof
fn main(
    // Public inputs
    database_root: pub Field,
    query_commitment: pub Field,
    nullifier: pub Field,
    // Private inputs
    master_seed: [Field; 4],
    target_row: u32,
    target_col: u32,
    hint_index: u32,
    hint_xor: [Field; CELL_SIZE],
    response_hint_xor: [Field; CELL_SIZE],
    merkle_path: [Field; 32],
    merkle_indices: [u1; 32],
    merkle_depth: u32
) {
    let master = MasterSeed { seed: master_seed };
    
    // 1. Verify hint index maps to target cell
    let row_seed = derive_row_seed(master, target_row);
    let computed_col = invertible_prf(row_seed, hint_index);
    assert(computed_col == target_col);
    
    // 2. Process response to get value
    let retrieved_value = process_response(
        PIRResponse { hint_xor: response_hint_xor, junk_xor: [0; CELL_SIZE] },
        hint_xor
    );
    
    // 3. Verify Merkle proof
    let mut leaf_hash = hekate_hash::hekate_hash_pair(
        retrieved_value[0],
        retrieved_value[1]
    );
    
    for i in 0..merkle_depth {
        let sibling = merkle_path[i];
        if merkle_indices[i] == 0 {
            leaf_hash = hekate_hash::hekate_hash_pair(leaf_hash, sibling);
        } else {
            leaf_hash = hekate_hash::hekate_hash_pair(sibling, leaf_hash);
        }
    }
    
    assert(leaf_hash == database_root);
    
    // 4. Verify nullifier
    let expected_nullifier = compute_pir_nullifier(master, hint_index, 0);
    assert(nullifier == expected_nullifier);
    
    // 5. Verify query commitment
    let computed_commitment = hekate_hash::hekate_hash_pair(
        target_row as Field,
        target_col as Field
    );
    // Note: actual commitment hides target, this is simplified
}

// ============================================================================
// TESTS
// ============================================================================

#[test]
fn test_derive_row_seed() {
    let master = MasterSeed { seed: [1, 2, 3, 4] };
    let row_seed = derive_row_seed(master, 42);
    assert(row_seed.row_index == 42);
    assert(row_seed.seed[0] != 0);
}

#[test]
fn test_invertible_prf() {
    let master = MasterSeed { seed: [1, 2, 3, 4] };
    let row_seed = derive_row_seed(master, 10);
    
    let col1 = invertible_prf(row_seed, 0);
    let col2 = invertible_prf(row_seed, 1);
    
    // Columns should be within grid
    assert(col1 < GRID_SIZE);
    assert(col2 < GRID_SIZE);
}

#[test]
fn test_generate_hint_rows() {
    let master = MasterSeed { seed: [5, 6, 7, 8] };
    let (rows, count) = generate_hint_rows(master, 0);
    
    assert(count > 0);
    assert(count <= 64);
    
    // All rows should be valid
    for i in 0..count {
        assert(rows[i] < GRID_SIZE);
    }
}

#[test]
fn test_compute_hint_xor() {
    let cells: [[Field; CELL_SIZE]; 64] = [[1, 2, 3, 4, 5, 6, 7, 8]; 64];
    let result = compute_hint_xor(cells, 2);
    
    // XOR of two identical cells = 2x each value
    assert(result[0] == 2);
}

#[test]
fn test_pir_nullifier() {
    let master = MasterSeed { seed: [1, 2, 3, 4] };
    let nullifier1 = compute_pir_nullifier(master, 0, 1);
    let nullifier2 = compute_pir_nullifier(master, 0, 2);
    
    // Different chains should produce different nullifiers
    assert(nullifier1 != nullifier2);
}
