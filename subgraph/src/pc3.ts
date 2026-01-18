import {
  ContainerCreated,
  ContainerConsumed,
} from "../generated/ProofCarryingContainer/ProofCarryingContainer";
import {
  Container,
  User,
  DailyStats,
  HourlyStats,
  ChainStats,
} from "../generated/schema";
import { BigInt, Bytes, ethereum } from "@graphprotocol/graph-ts";

// Helper functions
function getOrCreateUser(address: Bytes, timestamp: BigInt): User {
  let user = User.load(address.toHexString());
  if (!user) {
    user = new User(address.toHexString());
    user.address = address;
    user.firstSeen = timestamp;
    user.lastSeen = timestamp;
    user.containersCreated = BigInt.fromI32(0);
    user.containersConsumed = BigInt.fromI32(0);
    user.proofsSubmitted = BigInt.fromI32(0);
    user.nullifiersRegistered = BigInt.fromI32(0);
  }
  user.lastSeen = timestamp;
  return user;
}

function getOrCreateDailyStats(timestamp: BigInt): DailyStats {
  let dayId = timestamp.div(BigInt.fromI32(86400)).toString();
  let stats = DailyStats.load(dayId);
  if (!stats) {
    stats = new DailyStats(dayId);
    stats.date = timestamp.div(BigInt.fromI32(86400)).times(BigInt.fromI32(86400));
    stats.containersCreated = BigInt.fromI32(0);
    stats.containersConsumed = BigInt.fromI32(0);
    stats.proofsVerified = BigInt.fromI32(0);
    stats.policiesRegistered = BigInt.fromI32(0);
    stats.nullifiersConsumed = BigInt.fromI32(0);
    stats.stateCommitments = BigInt.fromI32(0);
    stats.totalGasUsed = BigInt.fromI32(0);
    stats.averageGasPerContainer = BigInt.fromI32(0);
    stats.uniqueCreators = BigInt.fromI32(0);
    stats.uniqueConsumers = BigInt.fromI32(0);
  }
  return stats;
}

function getOrCreateHourlyStats(timestamp: BigInt): HourlyStats {
  let hourId = timestamp.div(BigInt.fromI32(3600)).toString();
  let stats = HourlyStats.load(hourId);
  if (!stats) {
    stats = new HourlyStats(hourId);
    stats.hour = timestamp.div(BigInt.fromI32(3600)).times(BigInt.fromI32(3600));
    stats.containersCreated = BigInt.fromI32(0);
    stats.containersConsumed = BigInt.fromI32(0);
    stats.proofsVerified = BigInt.fromI32(0);
    stats.nullifiersConsumed = BigInt.fromI32(0);
    stats.totalGasUsed = BigInt.fromI32(0);
  }
  return stats;
}

function getOrCreateChainStats(chainId: i32): ChainStats {
  let id = chainId.toString();
  let stats = ChainStats.load(id);
  if (!stats) {
    stats = new ChainStats(id);
    stats.chainId = chainId;
    stats.name = getChainName(chainId);
    stats.totalContainers = BigInt.fromI32(0);
    stats.totalProofs = BigInt.fromI32(0);
    stats.totalNullifiers = BigInt.fromI32(0);
    stats.totalStateCommitments = BigInt.fromI32(0);
    stats.activeContainers = BigInt.fromI32(0);
    stats.lastUpdated = BigInt.fromI32(0);
  }
  return stats;
}

function getChainName(chainId: i32): string {
  if (chainId == 1) return "Ethereum";
  if (chainId == 11155111) return "Sepolia";
  if (chainId == 42161) return "Arbitrum";
  if (chainId == 10) return "Optimism";
  if (chainId == 8453) return "Base";
  if (chainId == 324) return "zkSync";
  if (chainId == 534352) return "Scroll";
  if (chainId == 59144) return "Linea";
  return "Unknown";
}

// Event handlers
export function handleContainerCreated(event: ContainerCreated): void {
  let containerId = event.params.containerId.toHexString();
  
  let container = new Container(containerId);
  container.creator = event.params.creator;
  container.proofHash = event.params.containerId; // Simplified
  container.publicInputsHash = event.params.containerId; // Simplified
  container.status = "ACTIVE";
  container.createdAt = event.block.timestamp;
  container.createdAtBlock = event.block.number;
  container.createdTxHash = event.transaction.hash;
  container.gasUsedCreate = event.transaction.gasLimit;
  
  container.save();
  
  // Update user stats
  let user = getOrCreateUser(event.params.creator, event.block.timestamp);
  user.containersCreated = user.containersCreated.plus(BigInt.fromI32(1));
  user.save();
  
  // Update daily stats
  let dailyStats = getOrCreateDailyStats(event.block.timestamp);
  dailyStats.containersCreated = dailyStats.containersCreated.plus(BigInt.fromI32(1));
  dailyStats.totalGasUsed = dailyStats.totalGasUsed.plus(event.transaction.gasLimit);
  dailyStats.save();
  
  // Update hourly stats
  let hourlyStats = getOrCreateHourlyStats(event.block.timestamp);
  hourlyStats.containersCreated = hourlyStats.containersCreated.plus(BigInt.fromI32(1));
  hourlyStats.totalGasUsed = hourlyStats.totalGasUsed.plus(event.transaction.gasLimit);
  hourlyStats.save();
  
  // Update chain stats (assuming we can get chainId)
  let chainStats = getOrCreateChainStats(1); // Default to mainnet
  chainStats.totalContainers = chainStats.totalContainers.plus(BigInt.fromI32(1));
  chainStats.activeContainers = chainStats.activeContainers.plus(BigInt.fromI32(1));
  chainStats.lastUpdated = event.block.timestamp;
  chainStats.save();
}

export function handleContainerConsumed(event: ContainerConsumed): void {
  let containerId = event.params.containerId.toHexString();
  
  let container = Container.load(containerId);
  if (container) {
    container.status = "CONSUMED";
    container.consumedAt = event.block.timestamp;
    container.consumedAtBlock = event.block.number;
    container.consumedTxHash = event.transaction.hash;
    container.consumer = event.params.consumer;
    container.gasUsedConsume = event.transaction.gasLimit;
    container.save();
    
    // Update user stats
    let user = getOrCreateUser(event.params.consumer, event.block.timestamp);
    user.containersConsumed = user.containersConsumed.plus(BigInt.fromI32(1));
    user.save();
    
    // Update daily stats
    let dailyStats = getOrCreateDailyStats(event.block.timestamp);
    dailyStats.containersConsumed = dailyStats.containersConsumed.plus(BigInt.fromI32(1));
    dailyStats.totalGasUsed = dailyStats.totalGasUsed.plus(event.transaction.gasLimit);
    dailyStats.save();
    
    // Update hourly stats
    let hourlyStats = getOrCreateHourlyStats(event.block.timestamp);
    hourlyStats.containersConsumed = hourlyStats.containersConsumed.plus(BigInt.fromI32(1));
    hourlyStats.save();
    
    // Update chain stats
    let chainStats = getOrCreateChainStats(1);
    chainStats.activeContainers = chainStats.activeContainers.minus(BigInt.fromI32(1));
    chainStats.lastUpdated = event.block.timestamp;
    chainStats.save();
  }
}
