const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time } = require("@nomicfoundation/hardhat-network-helpers");

describe("PILTimelock", function () {
    let timelock;
    let owner, proposer1, proposer2, executor, canceller, user;
    
    const MIN_DELAY = 48 * 3600; // 48 hours
    const EMERGENCY_DELAY = 6 * 3600; // 6 hours
    const GRACE_PERIOD = 7 * 24 * 3600; // 7 days
    const REQUIRED_CONFIRMATIONS = 2;
    
    beforeEach(async function () {
        [owner, proposer1, proposer2, executor, canceller, user] = await ethers.getSigners();
        
        const PILTimelock = await ethers.getContractFactory("PILTimelock");
        timelock = await PILTimelock.deploy(
            MIN_DELAY,
            EMERGENCY_DELAY,
            REQUIRED_CONFIRMATIONS,
            [proposer1.address, proposer2.address], // proposers
            [executor.address], // executors
            owner.address // admin
        );
    });
    
    describe("Deployment", function () {
        it("Should set correct delays", async function () {
            expect(await timelock.minDelay()).to.equal(MIN_DELAY);
            expect(await timelock.emergencyDelay()).to.equal(EMERGENCY_DELAY);
        });
        
        it("Should set correct required confirmations", async function () {
            expect(await timelock.requiredConfirmations()).to.equal(REQUIRED_CONFIRMATIONS);
        });
        
        it("Should grant roles correctly", async function () {
            const PROPOSER_ROLE = await timelock.PROPOSER_ROLE();
            const EXECUTOR_ROLE = await timelock.EXECUTOR_ROLE();
            const CANCELLER_ROLE = await timelock.CANCELLER_ROLE();
            
            expect(await timelock.hasRole(PROPOSER_ROLE, proposer1.address)).to.be.true;
            expect(await timelock.hasRole(PROPOSER_ROLE, proposer2.address)).to.be.true;
            expect(await timelock.hasRole(EXECUTOR_ROLE, executor.address)).to.be.true;
            expect(await timelock.hasRole(CANCELLER_ROLE, owner.address)).to.be.true;
        });
        
        it("Should reject invalid delays", async function () {
            const PILTimelock = await ethers.getContractFactory("PILTimelock");
            
            // Too short
            await expect(
                PILTimelock.deploy(
                    60, // 1 minute - below MIN_DELAY_FLOOR
                    60,
                    1,
                    [],
                    [],
                    owner.address
                )
            ).to.be.revertedWithCustomError(PILTimelock, "InvalidDelay");
        });
    });
    
    describe("Propose Operations", function () {
        it("Should allow proposer to propose operation", async function () {
            const target = user.address;
            const value = 0;
            const data = "0x";
            const predecessor = ethers.ZeroHash;
            const salt = ethers.id("test-salt");
            
            const tx = await timelock.connect(proposer1).propose(
                target,
                value,
                data,
                predecessor,
                salt
            );
            
            const receipt = await tx.wait();
            const event = receipt.logs.find(
                log => log.fragment && log.fragment.name === "OperationProposed"
            );
            
            expect(event).to.not.be.undefined;
            expect(await timelock.pendingOperations()).to.equal(1);
        });
        
        it("Should reject proposal from non-proposer", async function () {
            await expect(
                timelock.connect(user).propose(
                    user.address,
                    0,
                    "0x",
                    ethers.ZeroHash,
                    ethers.id("salt")
                )
            ).to.be.reverted;
        });
        
        it("Should reject duplicate proposals", async function () {
            const salt = ethers.id("duplicate-test");
            
            await timelock.connect(proposer1).propose(
                user.address,
                0,
                "0x",
                ethers.ZeroHash,
                salt
            );
            
            await expect(
                timelock.connect(proposer1).propose(
                    user.address,
                    0,
                    "0x",
                    ethers.ZeroHash,
                    salt
                )
            ).to.be.revertedWithCustomError(timelock, "OperationAlreadyExists");
        });
    });
    
    describe("Confirm Operations", function () {
        let operationId;
        const salt = ethers.id("confirm-test");
        
        beforeEach(async function () {
            const tx = await timelock.connect(proposer1).propose(
                user.address,
                0,
                "0x",
                ethers.ZeroHash,
                salt
            );
            
            const receipt = await tx.wait();
            const event = receipt.logs.find(
                log => log.fragment && log.fragment.name === "OperationProposed"
            );
            operationId = event.args[0];
        });
        
        it("Should allow second proposer to confirm", async function () {
            await timelock.connect(proposer2).confirm(operationId);
            
            const op = await timelock.operations(operationId);
            expect(op.confirmations).to.equal(2);
        });
        
        it("Should reject double confirmation", async function () {
            await expect(
                timelock.connect(proposer1).confirm(operationId)
            ).to.be.revertedWithCustomError(timelock, "AlreadyConfirmed");
        });
        
        it("Should reject confirmation from non-proposer", async function () {
            await expect(
                timelock.connect(user).confirm(operationId)
            ).to.be.reverted;
        });
    });
    
    describe("Execute Operations", function () {
        let operationId;
        const salt = ethers.id("execute-test");
        
        beforeEach(async function () {
            const tx = await timelock.connect(proposer1).propose(
                user.address,
                0,
                "0x",
                ethers.ZeroHash,
                salt
            );
            
            const receipt = await tx.wait();
            const event = receipt.logs.find(
                log => log.fragment && log.fragment.name === "OperationProposed"
            );
            operationId = event.args[0];
            
            // Get second confirmation
            await timelock.connect(proposer2).confirm(operationId);
        });
        
        it("Should reject execution before delay", async function () {
            await expect(
                timelock.connect(executor).execute(
                    user.address,
                    0,
                    "0x",
                    ethers.ZeroHash,
                    salt
                )
            ).to.be.revertedWithCustomError(timelock, "OperationNotReady");
        });
        
        it("Should allow execution after delay", async function () {
            // Move time forward past delay
            await time.increase(MIN_DELAY + 1);
            
            await expect(
                timelock.connect(executor).execute(
                    user.address,
                    0,
                    "0x",
                    ethers.ZeroHash,
                    salt
                )
            ).to.emit(timelock, "OperationExecuted");
            
            expect(await timelock.pendingOperations()).to.equal(0);
            expect(await timelock.executedOperations()).to.equal(1);
        });
        
        it("Should reject execution after grace period", async function () {
            // Move time past grace period
            await time.increase(MIN_DELAY + GRACE_PERIOD + 1);
            
            await expect(
                timelock.connect(executor).execute(
                    user.address,
                    0,
                    "0x",
                    ethers.ZeroHash,
                    salt
                )
            ).to.be.revertedWithCustomError(timelock, "OperationExpired");
        });
        
        it("Should reject execution from non-executor", async function () {
            await time.increase(MIN_DELAY + 1);
            
            await expect(
                timelock.connect(user).execute(
                    user.address,
                    0,
                    "0x",
                    ethers.ZeroHash,
                    salt
                )
            ).to.be.reverted;
        });
        
        it("Should reject execution without enough confirmations", async function () {
            // Create new operation with only 1 confirmation
            const newSalt = ethers.id("single-confirm");
            await timelock.connect(proposer1).propose(
                user.address,
                0,
                "0x",
                ethers.ZeroHash,
                newSalt
            );
            
            await time.increase(MIN_DELAY + 1);
            
            await expect(
                timelock.connect(executor).execute(
                    user.address,
                    0,
                    "0x",
                    ethers.ZeroHash,
                    newSalt
                )
            ).to.be.revertedWithCustomError(timelock, "InsufficientConfirmations");
        });
    });
    
    describe("Cancel Operations", function () {
        let operationId;
        const salt = ethers.id("cancel-test");
        
        beforeEach(async function () {
            const tx = await timelock.connect(proposer1).propose(
                user.address,
                0,
                "0x",
                ethers.ZeroHash,
                salt
            );
            
            const receipt = await tx.wait();
            const event = receipt.logs.find(
                log => log.fragment && log.fragment.name === "OperationProposed"
            );
            operationId = event.args[0];
        });
        
        it("Should allow canceller to cancel", async function () {
            await expect(
                timelock.connect(owner).cancel(operationId)
            ).to.emit(timelock, "OperationCancelled");
            
            expect(await timelock.pendingOperations()).to.equal(0);
        });
        
        it("Should reject cancel from non-canceller", async function () {
            await expect(
                timelock.connect(user).cancel(operationId)
            ).to.be.reverted;
        });
        
        it("Should prevent execution of cancelled operation", async function () {
            await timelock.connect(proposer2).confirm(operationId);
            await timelock.connect(owner).cancel(operationId);
            
            await time.increase(MIN_DELAY + 1);
            
            await expect(
                timelock.connect(executor).execute(
                    user.address,
                    0,
                    "0x",
                    ethers.ZeroHash,
                    salt
                )
            ).to.be.revertedWithCustomError(timelock, "OperationNotPending");
        });
    });
    
    describe("Predecessor Operations", function () {
        it("Should enforce predecessor execution order", async function () {
            const salt1 = ethers.id("predecessor");
            const salt2 = ethers.id("dependent");
            
            // Create predecessor operation
            const tx1 = await timelock.connect(proposer1).propose(
                user.address,
                0,
                "0x",
                ethers.ZeroHash,
                salt1
            );
            const receipt1 = await tx1.wait();
            const predecessorId = receipt1.logs.find(
                log => log.fragment && log.fragment.name === "OperationProposed"
            ).args[0];
            
            // Create dependent operation
            await timelock.connect(proposer1).propose(
                user.address,
                0,
                "0x",
                predecessorId,
                salt2
            );
            
            // Confirm both
            await timelock.connect(proposer2).confirm(predecessorId);
            const dependentId = await timelock.computeOperationId(
                user.address,
                0,
                "0x",
                predecessorId,
                salt2
            );
            await timelock.connect(proposer2).confirm(dependentId);
            
            await time.increase(MIN_DELAY + 1);
            
            // Try to execute dependent before predecessor
            await expect(
                timelock.connect(executor).execute(
                    user.address,
                    0,
                    "0x",
                    predecessorId,
                    salt2
                )
            ).to.be.revertedWithCustomError(timelock, "PredecessorNotExecuted");
            
            // Execute predecessor first
            await timelock.connect(executor).execute(
                user.address,
                0,
                "0x",
                ethers.ZeroHash,
                salt1
            );
            
            // Now dependent should work
            await expect(
                timelock.connect(executor).execute(
                    user.address,
                    0,
                    "0x",
                    predecessorId,
                    salt2
                )
            ).to.emit(timelock, "OperationExecuted");
        });
    });
    
    describe("View Functions", function () {
        it("Should return correct operation status", async function () {
            const salt = ethers.id("status-test");
            
            const tx = await timelock.connect(proposer1).propose(
                user.address,
                0,
                "0x",
                ethers.ZeroHash,
                salt
            );
            const receipt = await tx.wait();
            const opId = receipt.logs.find(
                log => log.fragment && log.fragment.name === "OperationProposed"
            ).args[0];
            
            // Initially pending
            expect(await timelock.isOperationPending(opId)).to.be.true;
            
            // Not ready yet
            expect(await timelock.isOperationReady(opId)).to.be.false;
            
            // After delay and with confirmations
            await timelock.connect(proposer2).confirm(opId);
            await time.increase(MIN_DELAY + 1);
            
            expect(await timelock.isOperationReady(opId)).to.be.true;
        });
        
        it("Should compute correct operation ID", async function () {
            const target = user.address;
            const value = 0n;
            const data = "0x";
            const predecessor = ethers.ZeroHash;
            const salt = ethers.id("compute-test");
            
            const computedId = await timelock.computeOperationId(
                target,
                value,
                data,
                predecessor,
                salt
            );
            
            // Compute locally
            const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
                ["address", "uint256", "bytes", "bytes32", "bytes32"],
                [target, value, data, predecessor, salt]
            );
            const expectedId = ethers.keccak256(encoded);
            
            expect(computedId).to.equal(expectedId);
        });
    });
    
    describe("Admin Functions", function () {
        it("Should allow admin to update min delay", async function () {
            const newDelay = 72 * 3600; // 72 hours
            
            await expect(
                timelock.connect(owner).updateMinDelay(newDelay)
            ).to.emit(timelock, "DelayUpdated");
            
            expect(await timelock.minDelay()).to.equal(newDelay);
        });
        
        it("Should reject invalid delay update", async function () {
            await expect(
                timelock.connect(owner).updateMinDelay(60) // Too short
            ).to.be.revertedWithCustomError(timelock, "InvalidDelay");
        });
        
        it("Should reject delay update from non-admin", async function () {
            await expect(
                timelock.connect(user).updateMinDelay(72 * 3600)
            ).to.be.reverted;
        });
    });
});

describe("TimelockAdmin Integration", function () {
    let timelock, timelockAdmin;
    let pc3, pbp, easc, cdna;
    let owner, proposer, executor;
    
    const MIN_DELAY = 48 * 3600;
    const EMERGENCY_DELAY = 6 * 3600;
    
    beforeEach(async function () {
        [owner, proposer, executor] = await ethers.getSigners();
        
        // Deploy PIL contracts
        const PC3 = await ethers.getContractFactory("ProofCarryingContainer");
        pc3 = await PC3.deploy();
        
        const PBP = await ethers.getContractFactory("PolicyBoundProofs");
        pbp = await PBP.deploy();
        
        const EASC = await ethers.getContractFactory("ExecutionAgnosticStateCommitments");
        easc = await EASC.deploy();
        
        const CDNA = await ethers.getContractFactory("CrossDomainNullifierAlgebra");
        cdna = await CDNA.deploy();
        
        // Deploy timelock
        const PILTimelock = await ethers.getContractFactory("PILTimelock");
        timelock = await PILTimelock.deploy(
            MIN_DELAY,
            EMERGENCY_DELAY,
            1, // 1 confirmation for testing
            [proposer.address],
            [executor.address],
            owner.address
        );
        
        // Deploy timelock admin
        const TimelockAdmin = await ethers.getContractFactory("TimelockAdmin");
        timelockAdmin = await TimelockAdmin.deploy(
            await timelock.getAddress(),
            await pc3.getAddress(),
            await pbp.getAddress(),
            await easc.getAddress(),
            await cdna.getAddress()
        );
        
        // Grant timelock admin role to timelock contract for PIL contracts
        const DEFAULT_ADMIN_ROLE = ethers.ZeroHash;
        await pc3.grantRole(DEFAULT_ADMIN_ROLE, await timelock.getAddress());
        await pbp.grantRole(DEFAULT_ADMIN_ROLE, await timelock.getAddress());
        await easc.grantRole(DEFAULT_ADMIN_ROLE, await timelock.getAddress());
        await cdna.grantRole(DEFAULT_ADMIN_ROLE, await timelock.getAddress());
        
        // Grant proposer role to timelockAdmin
        const PROPOSER_ROLE = await timelock.PROPOSER_ROLE();
        await timelock.grantRole(PROPOSER_ROLE, await timelockAdmin.getAddress());
    });
    
    it("Should schedule pause operation via TimelockAdmin", async function () {
        const salt = ethers.id("pause-pc3");
        
        const tx = await timelockAdmin.connect(proposer).schedulePausePC3(salt);
        const receipt = await tx.wait();
        
        const event = receipt.logs.find(
            log => log.fragment && log.fragment.name === "AdminOperationScheduled"
        );
        
        expect(event).to.not.be.undefined;
        expect(event.args.operationType).to.equal("PAUSE_PC3");
    });
    
    it("Should execute pause after delay", async function () {
        const salt = ethers.id("execute-pause");
        
        // Schedule pause
        await timelockAdmin.connect(proposer).schedulePausePC3(salt);
        
        // Wait for delay
        await time.increase(MIN_DELAY + 1);
        
        // Execute via timelock directly
        const pauseData = pc3.interface.encodeFunctionData("pause");
        
        await timelock.connect(executor).execute(
            await pc3.getAddress(),
            0,
            pauseData,
            ethers.ZeroHash,
            salt
        );
        
        expect(await pc3.paused()).to.be.true;
    });
});
