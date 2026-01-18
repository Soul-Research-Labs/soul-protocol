import { BigInt, Bytes } from "@graphprotocol/graph-ts";
import {
  CommitmentCreated,
  StateTransitionRecorded,
} from "../generated/ExecutionAgnosticStateCommitments/ExecutionAgnosticStateCommitments";
import { StateCommitment, StateTransition, SystemStats } from "../generated/schema";

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
 * Handle CommitmentCreated event
 */
export function handleCommitmentCreated(event: CommitmentCreated): void {
  let commitment = new StateCommitment(event.params.commitmentId.toHexString());
  
  commitment.stateRoot = event.params.stateRoot;
  commitment.executionEnvHash = event.params.executionEnvHash;
  commitment.creator = event.params.creator;
  commitment.createdAt = event.block.timestamp;
  commitment.lastUpdated = event.block.timestamp;
  commitment.transitionCount = BigInt.fromI32(0);
  commitment.blockNumber = event.block.number;
  
  commitment.save();
  
  // Update stats
  let stats = getOrCreateStats();
  stats.totalCommitments = stats.totalCommitments.plus(BigInt.fromI32(1));
  stats.lastUpdated = event.block.timestamp;
  stats.save();
}

/**
 * Handle StateTransitionRecorded event
 */
export function handleStateTransitionRecorded(event: StateTransitionRecorded): void {
  let commitment = StateCommitment.load(event.params.commitmentId.toHexString());
  if (commitment == null) {
    return;
  }
  
  // Create transition record
  let transitionId = event.params.commitmentId.toHexString()
    .concat("-")
    .concat(event.params.transitionIndex.toString());
    
  let transition = new StateTransition(transitionId);
  
  transition.commitment = commitment.id;
  transition.previousRoot = event.params.previousRoot;
  transition.newRoot = event.params.newRoot;
  transition.index = event.params.transitionIndex;
  transition.timestamp = event.block.timestamp;
  transition.blockNumber = event.block.number;
  
  transition.save();
  
  // Update commitment
  commitment.stateRoot = event.params.newRoot;
  commitment.lastUpdated = event.block.timestamp;
  commitment.transitionCount = commitment.transitionCount.plus(BigInt.fromI32(1));
  commitment.save();
}
