const { 
  Finding, 
  FindingSeverity, 
  FindingType,
  getEthersProvider,
  ethers
} = require("forta-agent");

// PIL Contract Addresses (update after deployment)
const CONTRACTS = {
  PC3: process.env.PC3_ADDRESS || "0x0",
  PBP: process.env.PBP_ADDRESS || "0x0",
  EASC: process.env.EASC_ADDRESS || "0x0",
  CDNA: process.env.CDNA_ADDRESS || "0x0",
  ORCHESTRATOR: process.env.ORCHESTRATOR_ADDRESS || "0x0",
};

// Event signatures to monitor
const EVENTS = {
  Paused: "event Paused(address account)",
  Unpaused: "event Unpaused(address account)",
  OwnershipTransferred: "event OwnershipTransferred(address indexed previousOwner, address indexed newOwner)",
  ContainerCreated: "event ContainerCreated(bytes32 indexed containerId, address indexed creator)",
  ContainerConsumed: "event ContainerConsumed(bytes32 indexed containerId, address indexed consumer)",
  NullifierConsumed: "event NullifierConsumed(bytes32 indexed nullifier, bytes32 indexed domainId)",
  RoleGranted: "event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender)",
  RoleRevoked: "event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender)",
};

// Thresholds
const THRESHOLDS = {
  maxContainersPerBlock: 100,
  maxGasPerTx: 2000000,
  suspiciousValueThreshold: ethers.parseEther("100"),
};

// State tracking
let containerCountPerBlock = new Map();
let lastProcessedBlock = 0;

function provideHandleTransaction(getProvider) {
  return async function handleTransaction(txEvent) {
    const findings = [];
    const provider = getProvider();
    
    // Check for pause events (Critical)
    const pauseEvents = txEvent.filterLog(EVENTS.Paused);
    for (const event of pauseEvents) {
      findings.push(
        Finding.fromObject({
          name: "PIL Contract Paused",
          description: `PIL contract was paused by ${event.args.account}`,
          alertId: "PIL-PAUSE-1",
          severity: FindingSeverity.Critical,
          type: FindingType.Suspicious,
          metadata: {
            account: event.args.account,
            contract: event.address,
            txHash: txEvent.hash,
          },
        })
      );
    }
    
    // Check for ownership transfers (Critical)
    const ownershipEvents = txEvent.filterLog(EVENTS.OwnershipTransferred);
    for (const event of ownershipEvents) {
      findings.push(
        Finding.fromObject({
          name: "PIL Ownership Transferred",
          description: `Ownership transferred from ${event.args.previousOwner} to ${event.args.newOwner}`,
          alertId: "PIL-OWNERSHIP-1",
          severity: FindingSeverity.Critical,
          type: FindingType.Info,
          metadata: {
            previousOwner: event.args.previousOwner,
            newOwner: event.args.newOwner,
            contract: event.address,
            txHash: txEvent.hash,
          },
        })
      );
    }
    
    // Check for role changes (High)
    const roleGrantedEvents = txEvent.filterLog(EVENTS.RoleGranted);
    for (const event of roleGrantedEvents) {
      findings.push(
        Finding.fromObject({
          name: "PIL Role Granted",
          description: `Role ${event.args.role} granted to ${event.args.account}`,
          alertId: "PIL-ROLE-1",
          severity: FindingSeverity.High,
          type: FindingType.Info,
          metadata: {
            role: event.args.role,
            account: event.args.account,
            sender: event.args.sender,
            contract: event.address,
          },
        })
      );
    }
    
    // Check for high gas usage (Medium)
    if (txEvent.gasUsed > THRESHOLDS.maxGasPerTx) {
      findings.push(
        Finding.fromObject({
          name: "High Gas Usage Detected",
          description: `Transaction used ${txEvent.gasUsed} gas`,
          alertId: "PIL-GAS-1",
          severity: FindingSeverity.Medium,
          type: FindingType.Info,
          metadata: {
            gasUsed: txEvent.gasUsed.toString(),
            threshold: THRESHOLDS.maxGasPerTx.toString(),
            txHash: txEvent.hash,
          },
        })
      );
    }
    
    // Track container creation rate
    const containerEvents = txEvent.filterLog(EVENTS.ContainerCreated);
    if (containerEvents.length > 0) {
      const blockNumber = txEvent.blockNumber;
      const currentCount = containerCountPerBlock.get(blockNumber) || 0;
      containerCountPerBlock.set(blockNumber, currentCount + containerEvents.length);
      
      if (currentCount + containerEvents.length > THRESHOLDS.maxContainersPerBlock) {
        findings.push(
          Finding.fromObject({
            name: "High Container Creation Rate",
            description: `${currentCount + containerEvents.length} containers created in block ${blockNumber}`,
            alertId: "PIL-RATE-1",
            severity: FindingSeverity.Medium,
            type: FindingType.Suspicious,
            metadata: {
              blockNumber: blockNumber.toString(),
              containerCount: (currentCount + containerEvents.length).toString(),
              threshold: THRESHOLDS.maxContainersPerBlock.toString(),
            },
          })
        );
      }
    }
    
    // Clean up old block data
    if (txEvent.blockNumber > lastProcessedBlock) {
      lastProcessedBlock = txEvent.blockNumber;
      for (const [block] of containerCountPerBlock) {
        if (block < txEvent.blockNumber - 100) {
          containerCountPerBlock.delete(block);
        }
      }
    }
    
    return findings;
  };
}

function provideHandleBlock(getProvider) {
  return async function handleBlock(blockEvent) {
    const findings = [];
    
    // Block-level checks can go here
    // For example, checking contract balance, state, etc.
    
    return findings;
  };
}

module.exports = {
  handleTransaction: provideHandleTransaction(getEthersProvider),
  handleBlock: provideHandleBlock(getEthersProvider),
  provideHandleTransaction,
  provideHandleBlock,
};
