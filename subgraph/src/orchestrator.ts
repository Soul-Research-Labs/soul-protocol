import { BigInt, Bytes } from "@graphprotocol/graph-ts";
import {
  OperationExecuted,
  PrimitiveUpdated,
  PrimitiveStatusChanged,
} from "../generated/PILv2Orchestrator/PILv2Orchestrator";
import {
  Operation,
  User,
  PrimitiveStatus,
  SystemStats,
} from "../generated/schema";

/**
 * Get or create system stats singleton
 */
function getOrCreateStats(): SystemStats {
  let stats = SystemStats.load("stats");
  if (stats == null) {
    stats = new SystemStats("stats");
    stats.totalContainers = BigInt.fromI32(0);
    stats.totalVerified = BigInt.fromI32(0);
    stats.totalConsumed = BigInt.fromI32(0);
    stats.totalPolicies = BigInt.fromI32(0);
    stats.activePolicies = BigInt.fromI32(0);
    stats.totalCommitments = BigInt.fromI32(0);
    stats.totalNullifiers = BigInt.fromI32(0);
    stats.totalOperations = BigInt.fromI32(0);
    stats.successfulOperations = BigInt.fromI32(0);
    stats.totalUsers = BigInt.fromI32(0);
    stats.lastUpdated = BigInt.fromI32(0);
  }
  return stats;
}

/**
 * Get or create user entity
 */
function getOrCreateUser(address: Bytes): User {
  let user = User.load(address.toHexString());
  if (user == null) {
    user = new User(address.toHexString());
    user.totalOperations = BigInt.fromI32(0);
    user.successfulOperations = BigInt.fromI32(0);
    user.failedOperations = BigInt.fromI32(0);
    user.containersCreated = [];
    
    // Update stats
    let stats = getOrCreateStats();
    stats.totalUsers = stats.totalUsers.plus(BigInt.fromI32(1));
    stats.save();
  }
  return user;
}

/**
 * Handle OperationExecuted event
 */
export function handleOperationExecuted(event: OperationExecuted): void {
  let operation = new Operation(event.params.operationId.toHexString());
  
  // Get or create user
  let user = getOrCreateUser(event.params.user);
  
  operation.user = user.id;
  operation.success = event.params.success;
  operation.message = event.params.message;
  operation.timestamp = event.block.timestamp;
  operation.blockNumber = event.block.number;
  operation.transactionHash = event.transaction.hash;
  
  operation.save();
  
  // Update user stats
  user.totalOperations = user.totalOperations.plus(BigInt.fromI32(1));
  if (event.params.success) {
    user.successfulOperations = user.successfulOperations.plus(BigInt.fromI32(1));
  } else {
    user.failedOperations = user.failedOperations.plus(BigInt.fromI32(1));
  }
  if (user.firstOperationAt == null) {
    user.firstOperationAt = event.block.timestamp;
  }
  user.lastOperationAt = event.block.timestamp;
  user.save();
  
  // Update global stats
  let stats = getOrCreateStats();
  stats.totalOperations = stats.totalOperations.plus(BigInt.fromI32(1));
  if (event.params.success) {
    stats.successfulOperations = stats.successfulOperations.plus(BigInt.fromI32(1));
  }
  stats.lastUpdated = event.block.timestamp;
  stats.save();
}

/**
 * Handle PrimitiveUpdated event
 */
export function handlePrimitiveUpdated(event: PrimitiveUpdated): void {
  let primitive = PrimitiveStatus.load(event.params.primitiveId.toHexString());
  if (primitive == null) {
    primitive = new PrimitiveStatus(event.params.primitiveId.toHexString());
    primitive.name = getPrimitiveName(event.params.primitiveId);
    primitive.isActive = true;
  }
  
  primitive.contractAddress = event.params.newAddress;
  primitive.lastUpdated = event.block.timestamp;
  
  primitive.save();
}

/**
 * Handle PrimitiveStatusChanged event
 */
export function handlePrimitiveStatusChanged(event: PrimitiveStatusChanged): void {
  let primitive = PrimitiveStatus.load(event.params.primitiveId.toHexString());
  if (primitive == null) {
    primitive = new PrimitiveStatus(event.params.primitiveId.toHexString());
    primitive.name = getPrimitiveName(event.params.primitiveId);
    primitive.contractAddress = Bytes.fromHexString("0x0000000000000000000000000000000000000000");
  }
  
  primitive.isActive = event.params.active;
  primitive.lastUpdated = event.block.timestamp;
  
  primitive.save();
}

/**
 * Get primitive name from ID
 */
function getPrimitiveName(primitiveId: Bytes): string {
  // These are keccak256 hashes of the primitive names
  // PC3 = keccak256("PC3")
  // PBP = keccak256("PBP")
  // EASC = keccak256("EASC")
  // CDNA = keccak256("CDNA")
  
  let id = primitiveId.toHexString();
  
  // Using first 8 chars to identify
  if (id.startsWith("0x8d8f")) {
    return "PC3";
  } else if (id.startsWith("0x5f3e")) {
    return "PBP";
  } else if (id.startsWith("0x6e7a")) {
    return "EASC";
  } else if (id.startsWith("0x4c12")) {
    return "CDNA";
  }
  
  return "Unknown";
}
