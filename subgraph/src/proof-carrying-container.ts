import { BigInt, Bytes } from "@graphprotocol/graph-ts";
import {
  ContainerCreated,
  ContainerVerified,
  ContainerConsumed,
  PolicyAdded,
  PolicyRemoved,
} from "../generated/ProofCarryingContainer/ProofCarryingContainer";
import {
  Container,
  ContainerVerification,
  Policy,
  SystemStats,
  User,
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
 * Handle ContainerCreated event
 */
export function handleContainerCreated(event: ContainerCreated): void {
  let container = new Container(event.params.containerId.toHexString());
  
  container.stateCommitment = event.params.stateCommitment;
  container.nullifier = event.params.nullifier;
  container.policyHash = event.params.policyHash;
  container.chainId = BigInt.fromI32(event.params.chainId);
  container.createdAt = event.block.timestamp;
  container.blockNumber = event.block.number;
  container.transactionHash = event.transaction.hash;
  container.creator = event.transaction.from;
  container.isVerified = false;
  container.isConsumed = false;
  
  container.save();
  
  // Update user
  let user = getOrCreateUser(event.transaction.from);
  let containers = user.containersCreated;
  containers.push(container.id);
  user.containersCreated = containers;
  if (user.firstOperationAt == null) {
    user.firstOperationAt = event.block.timestamp;
  }
  user.lastOperationAt = event.block.timestamp;
  user.save();
  
  // Update stats
  let stats = getOrCreateStats();
  stats.totalContainers = stats.totalContainers.plus(BigInt.fromI32(1));
  stats.lastUpdated = event.block.timestamp;
  stats.save();
}

/**
 * Handle ContainerVerified event
 */
export function handleContainerVerified(event: ContainerVerified): void {
  let container = Container.load(event.params.containerId.toHexString());
  if (container == null) {
    return;
  }
  
  // Create verification record
  let verificationId = event.params.containerId.toHexString()
    .concat("-")
    .concat(event.params.verifier.toHexString())
    .concat("-")
    .concat(event.block.timestamp.toString());
    
  let verification = new ContainerVerification(verificationId);
  verification.container = container.id;
  verification.verifier = event.params.verifier;
  verification.success = event.params.success;
  verification.reason = event.params.reason;
  verification.timestamp = event.block.timestamp;
  verification.blockNumber = event.block.number;
  verification.save();
  
  // Update container if verified successfully
  if (event.params.success) {
    container.isVerified = true;
    container.save();
    
    // Update stats
    let stats = getOrCreateStats();
    stats.totalVerified = stats.totalVerified.plus(BigInt.fromI32(1));
    stats.lastUpdated = event.block.timestamp;
    stats.save();
  }
}

/**
 * Handle ContainerConsumed event
 */
export function handleContainerConsumed(event: ContainerConsumed): void {
  let container = Container.load(event.params.containerId.toHexString());
  if (container == null) {
    return;
  }
  
  container.isConsumed = true;
  container.consumer = event.params.consumer;
  container.consumedAt = event.block.timestamp;
  container.save();
  
  // Update stats
  let stats = getOrCreateStats();
  stats.totalConsumed = stats.totalConsumed.plus(BigInt.fromI32(1));
  stats.totalNullifiers = stats.totalNullifiers.plus(BigInt.fromI32(1));
  stats.lastUpdated = event.block.timestamp;
  stats.save();
}

/**
 * Handle PolicyAdded event
 */
export function handlePolicyAdded(event: PolicyAdded): void {
  let policy = new Policy(event.params.policyHash.toHexString());
  
  policy.isActive = true;
  policy.addedAt = event.block.timestamp;
  policy.blockNumber = event.block.number;
  policy.transactionHash = event.transaction.hash;
  
  policy.save();
  
  // Update stats
  let stats = getOrCreateStats();
  stats.totalPolicies = stats.totalPolicies.plus(BigInt.fromI32(1));
  stats.activePolicies = stats.activePolicies.plus(BigInt.fromI32(1));
  stats.lastUpdated = event.block.timestamp;
  stats.save();
}

/**
 * Handle PolicyRemoved event
 */
export function handlePolicyRemoved(event: PolicyRemoved): void {
  let policy = Policy.load(event.params.policyHash.toHexString());
  if (policy == null) {
    return;
  }
  
  policy.isActive = false;
  policy.removedAt = event.block.timestamp;
  policy.save();
  
  // Update stats
  let stats = getOrCreateStats();
  stats.activePolicies = stats.activePolicies.minus(BigInt.fromI32(1));
  stats.lastUpdated = event.block.timestamp;
  stats.save();
}
