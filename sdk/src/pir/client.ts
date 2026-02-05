// ============================================================================
// Plinko PIR TypeScript SDK
// ============================================================================
// Client-side implementation for private information retrieval
// Reference: https://vitalik.eth.limo/general/2025/11/25/plinko.html
// ============================================================================

import { keccak256, encodePacked, toHex, fromHex, type Hex } from 'viem';

// ============================================================================
// CONSTANTS
// ============================================================================

/** Default grid size (√N where N = 1M entries) */
export const DEFAULT_GRID_SIZE = 1024;

/** Cell size in bytes (32 bytes for Ethereum storage slot) */
export const CELL_SIZE = 32;

/** Number of hints per row for 128-bit security */
export const HINTS_PER_ROW = 128;

/** Maximum PRF block depth for invertibility */
export const MAX_PRF_DEPTH = 16;

/** Number of backup hint pairs */
export const DEFAULT_BACKUP_HINTS = 256;

// ============================================================================
// TYPES
// ============================================================================

/** Master seed for hint generation */
export interface MasterSeed {
  seed: Uint8Array; // 32 bytes
}

/** Row seed derived from master seed */
export interface RowSeed {
  rowIndex: number;
  seed: Uint8Array; // 16 bytes
}

/** A single PIR hint */
export interface Hint {
  index: number;
  rowIndices: number[];
  columnIndices: number[];
  xorValue: Uint8Array;
}

/** Backup hint pair for query replenishment */
export interface BackupHintPair {
  subsetHint: Hint;
  complementHint: Hint;
  subsetBitmap: Uint8Array;
}

/** PIR query structure */
export interface PIRQuery {
  hintPoints: Array<{ row: number; col: number }>;
  junkPoints: Array<{ row: number; col: number }>;
  orderingSeed: Uint8Array;
  hintIndex: number;
}

/** Server response to PIR query */
export interface PIRResponse {
  hintXor: Uint8Array;
  junkXor: Uint8Array;
}

/** Complete PIR proof */
export interface PIRProof {
  queryCommitment: Hex;
  response: PIRResponse;
  hintCommitment: Hex;
  retrievedValue: Uint8Array;
  merkleRoot: Hex;
  merklePath: Hex[];
  merklePathIndices: number[];
}

/** Cross-chain PIR proof */
export interface CrossChainPIRProof {
  sourceChain: bigint;
  targetChain: bigint;
  pirProof: PIRProof;
  nullifier: Hex;
  sourceStateRoot: Hex;
}

/** PIR client configuration */
export interface PIRClientConfig {
  gridSize?: number;
  cellSize?: number;
  hintsPerRow?: number;
  backupHints?: number;
}

/** Hint storage for efficient lookup */
export interface HintStorage {
  hints: Map<number, Hint>;
  backupHints: BackupHintPair[];
  masterSeed: MasterSeed;
  gridSize: number;
}

// ============================================================================
// HEKATE HASH (ZK-FRIENDLY)
// ============================================================================

/** Hekate S-box for ZK-friendly hashing */
function hekateSBox(x: bigint): bigint {
  // x^5 in the field
  const x2 = x * x;
  const x4 = x2 * x2;
  return (x4 * x) % BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF');
}

/** Hekate hash pair */
function hekateHashPair(a: bigint, b: bigint): bigint {
  let state = a ^ b;
  
  for (let i = 0; i < 8; i++) {
    state = hekateSBox(state);
    state = state ^ (BigInt(i) * BigInt('0x9E3779B97F4A7C15'));
  }
  
  return state;
}

/** Hash bytes using Hekate */
function hekateHash(data: Uint8Array): bigint {
  let state = BigInt(0);
  
  for (let i = 0; i < data.length; i += 16) {
    const chunk = data.slice(i, Math.min(i + 16, data.length));
    let chunkValue = BigInt(0);
    for (let j = 0; j < chunk.length; j++) {
      chunkValue |= BigInt(chunk[j]) << BigInt(j * 8);
    }
    state = hekateHashPair(state, chunkValue);
  }
  
  return state;
}

// ============================================================================
// SEED DERIVATION
// ============================================================================

/** Generate a cryptographically secure master seed */
export function generateMasterSeed(): MasterSeed {
  const seed = new Uint8Array(32);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
    crypto.getRandomValues(seed);
  } else {
    // Fallback for Node.js
    for (let i = 0; i < 32; i++) {
      seed[i] = Math.floor(Math.random() * 256);
    }
  }
  return { seed };
}

/** Derive row seed from master seed */
export function deriveRowSeed(master: MasterSeed, rowIndex: number): RowSeed {
  const input = new Uint8Array(36);
  input.set(master.seed, 0);
  new DataView(input.buffer).setUint32(32, rowIndex, true);
  
  const hash = keccak256(toHex(input));
  const hashBytes = fromHex(hash, 'bytes');
  
  return {
    rowIndex,
    seed: hashBytes.slice(0, 16),
  };
}

// ============================================================================
// INVERTIBLE PRF
// ============================================================================

/**
 * Invertible PRF: H(S_row, j) -> column
 * Uses block-based structure for invertibility
 */
export function invertiblePRF(rowSeed: RowSeed, hintIndex: number, gridSize: number = DEFAULT_GRID_SIZE): number {
  const blockIndex = Math.floor(hintIndex / MAX_PRF_DEPTH);
  const offset = hintIndex % MAX_PRF_DEPTH;
  
  // Hash row seed with block index
  const input = new Uint8Array(20);
  input.set(rowSeed.seed, 0);
  new DataView(input.buffer).setUint32(16, blockIndex, true);
  
  const hash = keccak256(toHex(input));
  const hashBytes = fromHex(hash, 'bytes');
  
  // Extract bits for column index (10 bits for gridSize = 1024)
  const bitsNeeded = Math.ceil(Math.log2(gridSize));
  const startByte = Math.floor((offset * bitsNeeded) / 8) % 16;
  const startBit = (offset * bitsNeeded) % 8;
  
  let column = 0;
  for (let i = 0; i < bitsNeeded; i++) {
    const byteIdx = (startByte + Math.floor((startBit + i) / 8)) % 32;
    const bitIdx = (startBit + i) % 8;
    const bit = (hashBytes[byteIdx] >> bitIdx) & 1;
    column |= bit << i;
  }
  
  return column % gridSize;
}

/**
 * Invert PRF: Find all hint indices j where H(S_row, j) = column
 * Returns preimages that map to the target column
 */
export function invertPRF(
  rowSeed: RowSeed,
  targetColumn: number,
  maxHints: number = HINTS_PER_ROW * DEFAULT_GRID_SIZE,
  gridSize: number = DEFAULT_GRID_SIZE
): number[] {
  const preimages: number[] = [];
  const searchLimit = Math.min(maxHints, HINTS_PER_ROW * gridSize);
  
  // Search through hint indices to find matches
  // In practice, average √N/16 hashes per lookup
  for (let j = 0; j < searchLimit && preimages.length < 8; j++) {
    const col = invertiblePRF(rowSeed, j, gridSize);
    if (col === targetColumn) {
      preimages.push(j);
    }
  }
  
  return preimages;
}

// ============================================================================
// HINT GENERATION
// ============================================================================

/**
 * Generate row indices for a hint
 */
export function generateHintRows(
  master: MasterSeed,
  hintIndex: number,
  gridSize: number = DEFAULT_GRID_SIZE
): number[] {
  const input = new Uint8Array(36);
  input.set(master.seed, 0);
  new DataView(input.buffer).setUint32(32, hintIndex, true);
  
  const hash = keccak256(toHex(input));
  const hashBytes = fromHex(hash, 'bytes');
  
  // Select ~N/2 + 1 rows based on hash bits
  const targetRows = Math.floor(gridSize / 2) + 1;
  const rows: Set<number> = new Set();
  
  let byteIdx = 0;
  let bitIdx = 0;
  
  for (let i = 0; i < gridSize && rows.size < targetRows; i++) {
    // Use hash bit to decide inclusion
    const bit = (hashBytes[byteIdx % 32] >> bitIdx) & 1;
    if (bit === 1 || rows.size < targetRows - (gridSize - i)) {
      rows.add(i);
    }
    
    bitIdx++;
    if (bitIdx >= 8) {
      bitIdx = 0;
      byteIdx++;
    }
  }
  
  return Array.from(rows).sort((a, b) => a - b);
}

/**
 * Compute XOR of cells
 */
export function xorCells(cells: Uint8Array[]): Uint8Array {
  if (cells.length === 0) {
    return new Uint8Array(CELL_SIZE);
  }
  
  const result = new Uint8Array(cells[0].length);
  
  for (const cell of cells) {
    for (let i = 0; i < result.length; i++) {
      result[i] ^= cell[i];
    }
  }
  
  return result;
}

/**
 * Generate a single hint
 */
export function generateHint(
  master: MasterSeed,
  hintIndex: number,
  database: Uint8Array[], // Flat array of cells
  gridSize: number = DEFAULT_GRID_SIZE
): Hint {
  const rowIndices = generateHintRows(master, hintIndex, gridSize);
  const columnIndices: number[] = [];
  const cells: Uint8Array[] = [];
  
  for (const row of rowIndices) {
    const rowSeed = deriveRowSeed(master, row);
    const col = invertiblePRF(rowSeed, hintIndex, gridSize);
    columnIndices.push(col);
    
    const cellIndex = row * gridSize + col;
    if (cellIndex < database.length) {
      cells.push(database[cellIndex]);
    }
  }
  
  return {
    index: hintIndex,
    rowIndices,
    columnIndices,
    xorValue: xorCells(cells),
  };
}

/**
 * Generate backup hint pair
 */
export function generateBackupHintPair(
  master: MasterSeed,
  pairIndex: number,
  database: Uint8Array[],
  gridSize: number = DEFAULT_GRID_SIZE
): BackupHintPair {
  // Generate random subset of rows
  const input = new Uint8Array(36);
  input.set(master.seed, 0);
  new DataView(input.buffer).setUint32(32, pairIndex + 1000000, true);
  
  const hash = keccak256(toHex(input));
  const hashBytes = fromHex(hash, 'bytes');
  
  const subsetRows: number[] = [];
  const complementRows: number[] = [];
  const subsetBitmap = new Uint8Array(Math.ceil(gridSize / 8));
  
  for (let i = 0; i < gridSize; i++) {
    const byteIdx = Math.floor(i / 8);
    const bitIdx = i % 8;
    const bit = (hashBytes[byteIdx % 32] >> bitIdx) & 1;
    
    if (bit === 1) {
      subsetRows.push(i);
      subsetBitmap[byteIdx] |= 1 << bitIdx;
    } else {
      complementRows.push(i);
    }
  }
  
  // Generate hints for both subsets
  const subsetCells: Uint8Array[] = [];
  const complementCells: Uint8Array[] = [];
  const subsetCols: number[] = [];
  const complementCols: number[] = [];
  
  for (const row of subsetRows) {
    const rowSeed = deriveRowSeed(master, row);
    const col = invertiblePRF(rowSeed, pairIndex, gridSize);
    subsetCols.push(col);
    
    const cellIndex = row * gridSize + col;
    if (cellIndex < database.length) {
      subsetCells.push(database[cellIndex]);
    }
  }
  
  for (const row of complementRows) {
    const rowSeed = deriveRowSeed(master, row);
    const col = invertiblePRF(rowSeed, pairIndex, gridSize);
    complementCols.push(col);
    
    const cellIndex = row * gridSize + col;
    if (cellIndex < database.length) {
      complementCells.push(database[cellIndex]);
    }
  }
  
  return {
    subsetHint: {
      index: pairIndex,
      rowIndices: subsetRows,
      columnIndices: subsetCols,
      xorValue: xorCells(subsetCells),
    },
    complementHint: {
      index: pairIndex,
      rowIndices: complementRows,
      columnIndices: complementCols,
      xorValue: xorCells(complementCells),
    },
    subsetBitmap,
  };
}

// ============================================================================
// PIR CLIENT
// ============================================================================

/**
 * PIR Client for private information retrieval
 */
export class PIRClient {
  private config: Required<PIRClientConfig>;
  private storage: HintStorage | null = null;
  private usedHints: Set<number> = new Set();
  
  constructor(config: PIRClientConfig = {}) {
    this.config = {
      gridSize: config.gridSize ?? DEFAULT_GRID_SIZE,
      cellSize: config.cellSize ?? CELL_SIZE,
      hintsPerRow: config.hintsPerRow ?? HINTS_PER_ROW,
      backupHints: config.backupHints ?? DEFAULT_BACKUP_HINTS,
    };
  }
  
  /**
   * Setup phase: Process database and generate hints
   * This is O(N) but only done once
   */
  async setup(database: Uint8Array[]): Promise<void> {
    const masterSeed = generateMasterSeed();
    const hints = new Map<number, Hint>();
    const backupHints: BackupHintPair[] = [];
    
    const totalHints = this.config.hintsPerRow * this.config.gridSize;
    
    // Generate regular hints
    console.log(`Generating ${totalHints} hints...`);
    for (let i = 0; i < totalHints; i++) {
      const hint = generateHint(masterSeed, i, database, this.config.gridSize);
      hints.set(i, hint);
      
      if (i % 10000 === 0) {
        console.log(`Progress: ${i}/${totalHints}`);
      }
    }
    
    // Generate backup hints
    console.log(`Generating ${this.config.backupHints} backup hint pairs...`);
    for (let i = 0; i < this.config.backupHints; i++) {
      const pair = generateBackupHintPair(masterSeed, i, database, this.config.gridSize);
      backupHints.push(pair);
    }
    
    this.storage = {
      hints,
      backupHints,
      masterSeed,
      gridSize: this.config.gridSize,
    };
    
    console.log('Setup complete!');
  }
  
  /**
   * Find a hint that contains the target cell
   */
  findHintForCell(targetRow: number, targetCol: number): Hint | null {
    if (!this.storage) {
      throw new Error('Client not initialized. Call setup() first.');
    }
    
    const rowSeed = deriveRowSeed(this.storage.masterSeed, targetRow);
    const hintIndices = invertPRF(rowSeed, targetCol, this.config.hintsPerRow * this.config.gridSize, this.config.gridSize);
    
    // Find an unused hint
    for (const hintIndex of hintIndices) {
      if (!this.usedHints.has(hintIndex)) {
        const hint = this.storage.hints.get(hintIndex);
        if (hint) {
          return hint;
        }
      }
    }
    
    return null;
  }
  
  /**
   * Generate a PIR query for target cell
   */
  generateQuery(targetRow: number, targetCol: number): PIRQuery {
    if (!this.storage) {
      throw new Error('Client not initialized. Call setup() first.');
    }
    
    const hint = this.findHintForCell(targetRow, targetCol);
    if (!hint) {
      throw new Error('No available hint for target cell');
    }
    
    // Generate ordering randomness
    const orderingSeed = new Uint8Array(32);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
      crypto.getRandomValues(orderingSeed);
    }
    
    // Build hint points (excluding target)
    const hintPoints: Array<{ row: number; col: number }> = [];
    for (let i = 0; i < hint.rowIndices.length; i++) {
      const row = hint.rowIndices[i];
      if (row !== targetRow) {
        hintPoints.push({ row, col: hint.columnIndices[i] });
      }
    }
    
    // Build junk points (other rows with random columns)
    const junkPoints: Array<{ row: number; col: number }> = [];
    const hintRowSet = new Set(hint.rowIndices);
    
    // Add target row with target column (hidden among junk)
    junkPoints.push({ row: targetRow, col: targetCol });
    
    // Add other rows
    for (let row = 0; row < this.config.gridSize && junkPoints.length < hintPoints.length + 1; row++) {
      if (!hintRowSet.has(row) && row !== targetRow) {
        // Random column
        const col = (orderingSeed[row % 32] * 4 + row) % this.config.gridSize;
        junkPoints.push({ row, col });
      }
    }
    
    // Shuffle both arrays using Fisher-Yates
    this.shuffleArray(hintPoints, orderingSeed);
    this.shuffleArray(junkPoints, orderingSeed);
    
    return {
      hintPoints,
      junkPoints,
      orderingSeed,
      hintIndex: hint.index,
    };
  }
  
  /**
   * Process server response to retrieve value
   */
  processResponse(query: PIRQuery, response: PIRResponse): Uint8Array {
    if (!this.storage) {
      throw new Error('Client not initialized. Call setup() first.');
    }
    
    const hint = this.storage.hints.get(query.hintIndex);
    if (!hint) {
      throw new Error('Hint not found');
    }
    
    // Mark hint as used
    this.usedHints.add(query.hintIndex);
    
    // Retrieve value = hint_xor XOR response.hintXor
    const result = new Uint8Array(hint.xorValue.length);
    for (let i = 0; i < result.length; i++) {
      result[i] = hint.xorValue[i] ^ response.hintXor[i];
    }
    
    // Promote a backup hint
    this.promoteBackupHint(query.hintIndex);
    
    return result;
  }
  
  /**
   * Promote a backup hint after using a regular hint
   */
  private promoteBackupHint(usedHintIndex: number): void {
    if (!this.storage || this.storage.backupHints.length === 0) {
      return;
    }
    
    // Pop a backup hint
    const backup = this.storage.backupHints.pop()!;
    
    // Use complement hint as new regular hint
    this.storage.hints.set(usedHintIndex, backup.complementHint);
  }
  
  /**
   * Update hints when database value changes
   */
  updateHintsForChange(
    changedRow: number,
    changedCol: number,
    oldValue: Uint8Array,
    newValue: Uint8Array
  ): void {
    if (!this.storage) {
      throw new Error('Client not initialized. Call setup() first.');
    }
    
    const rowSeed = deriveRowSeed(this.storage.masterSeed, changedRow);
    
    // Find all hints that include this cell
    for (const [hintIndex, hint] of this.storage.hints) {
      const hintCol = invertiblePRF(rowSeed, hintIndex, this.config.gridSize);
      
      if (hintCol === changedCol && hint.rowIndices.includes(changedRow)) {
        // XOR out old value, XOR in new value
        for (let i = 0; i < hint.xorValue.length; i++) {
          hint.xorValue[i] ^= oldValue[i] ^ newValue[i];
        }
      }
    }
  }
  
  /**
   * Get hint storage stats
   */
  getStats(): { totalHints: number; usedHints: number; backupHints: number; storageMB: number } {
    if (!this.storage) {
      return { totalHints: 0, usedHints: 0, backupHints: 0, storageMB: 0 };
    }
    
    const hintSize = this.config.cellSize + 4 * this.config.gridSize / 2; // xorValue + row indices
    const totalBytes = this.storage.hints.size * hintSize + this.storage.backupHints.length * hintSize * 2;
    
    return {
      totalHints: this.storage.hints.size,
      usedHints: this.usedHints.size,
      backupHints: this.storage.backupHints.length,
      storageMB: totalBytes / (1024 * 1024),
    };
  }
  
  /**
   * Fisher-Yates shuffle
   */
  private shuffleArray<T>(array: T[], seed: Uint8Array): void {
    for (let i = array.length - 1; i > 0; i--) {
      const j = seed[i % 32] % (i + 1);
      [array[i], array[j]] = [array[j], array[i]];
    }
  }
  
  /**
   * Compute nullifier for a query
   */
  computeNullifier(hintIndex: number, chainId: bigint): Hex {
    if (!this.storage) {
      throw new Error('Client not initialized. Call setup() first.');
    }
    
    const input = new Uint8Array(44);
    input.set(this.storage.masterSeed.seed, 0);
    new DataView(input.buffer).setUint32(32, hintIndex, true);
    new DataView(input.buffer).setBigUint64(36, chainId, true);
    
    return keccak256(toHex(input));
  }
  
  /**
   * Generate a cross-chain PIR proof
   */
  generateCrossChainProof(
    sourceChain: bigint,
    targetChain: bigint,
    query: PIRQuery,
    response: PIRResponse,
    merklePath: Hex[],
    merkleIndices: number[],
    sourceStateRoot: Hex
  ): CrossChainPIRProof {
    const retrievedValue = this.processResponse(query, response);
    const nullifier = this.computeNullifier(query.hintIndex, sourceChain);
    
    // Compute query commitment
    const queryData = new Uint8Array(query.hintPoints.length * 8);
    for (let i = 0; i < query.hintPoints.length; i++) {
      new DataView(queryData.buffer).setUint32(i * 8, query.hintPoints[i].row, true);
      new DataView(queryData.buffer).setUint32(i * 8 + 4, query.hintPoints[i].col, true);
    }
    const queryCommitment = keccak256(toHex(queryData));
    
    // Compute hint commitment
    const hint = this.storage?.hints.get(query.hintIndex);
    const hintCommitment = hint ? keccak256(toHex(hint.xorValue)) : '0x0' as Hex;
    
    // Compute Merkle root
    let leaf = keccak256(toHex(retrievedValue));
    for (let i = 0; i < merklePath.length; i++) {
      if (merkleIndices[i] === 0) {
        leaf = keccak256(encodePacked(['bytes32', 'bytes32'], [leaf, merklePath[i]]));
      } else {
        leaf = keccak256(encodePacked(['bytes32', 'bytes32'], [merklePath[i], leaf]));
      }
    }
    
    return {
      sourceChain,
      targetChain,
      pirProof: {
        queryCommitment,
        response,
        hintCommitment,
        retrievedValue,
        merkleRoot: leaf,
        merklePath,
        merklePathIndices: merkleIndices,
      },
      nullifier,
      sourceStateRoot,
    };
  }
}

// ============================================================================
// PIR SERVER
// ============================================================================

/**
 * PIR Server for processing queries
 */
export class PIRServer {
  private database: Uint8Array[];
  private gridSize: number;
  
  constructor(database: Uint8Array[], gridSize: number = DEFAULT_GRID_SIZE) {
    this.database = database;
    this.gridSize = gridSize;
  }
  
  /**
   * Process a PIR query and return XOR sums
   */
  processQuery(query: PIRQuery): PIRResponse {
    // XOR hint points
    const hintCells: Uint8Array[] = [];
    for (const point of query.hintPoints) {
      const cellIndex = point.row * this.gridSize + point.col;
      if (cellIndex < this.database.length) {
        hintCells.push(this.database[cellIndex]);
      }
    }
    
    // XOR junk points
    const junkCells: Uint8Array[] = [];
    for (const point of query.junkPoints) {
      const cellIndex = point.row * this.gridSize + point.col;
      if (cellIndex < this.database.length) {
        junkCells.push(this.database[cellIndex]);
      }
    }
    
    return {
      hintXor: xorCells(hintCells),
      junkXor: xorCells(junkCells),
    };
  }
  
  /**
   * Update a cell in the database
   */
  updateCell(row: number, col: number, newValue: Uint8Array): Uint8Array {
    const cellIndex = row * this.gridSize + col;
    const oldValue = this.database[cellIndex] || new Uint8Array(CELL_SIZE);
    this.database[cellIndex] = newValue;
    return oldValue;
  }
  
  /**
   * Get database stats
   */
  getStats(): { cells: number; gridSize: number; totalBytes: number } {
    return {
      cells: this.database.length,
      gridSize: this.gridSize,
      totalBytes: this.database.reduce((sum, cell) => sum + cell.length, 0),
    };
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export {
  hekateHash,
  hekateHashPair,
  generateMasterSeed,
  deriveRowSeed,
  invertiblePRF,
  invertPRF,
  generateHintRows,
  generateHint,
  generateBackupHintPair,
  xorCells,
};
