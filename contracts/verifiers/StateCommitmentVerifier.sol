// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract StateCommitmentVerifier {
    // Scalar field size
    uint256 internal constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 internal constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 internal constant alphax  = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 internal constant alphay  = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 internal constant betax1  = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 internal constant betax2  = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 internal constant betay1  = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 internal constant betay2  = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 internal constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 internal constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 internal constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 internal constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 internal constant deltax1 = 17846497352578059539418310992017781819399623020131369401060961566915301085972;
    uint256 internal constant deltax2 = 8839722292097241532933991078044971752362977149377089884085415731133876445258;
    uint256 internal constant deltay1 = 17787987133013706671414277032662073876014421810683737311605677634667953763560;
    uint256 internal constant deltay2 = 3026899431378755029150885117145285241019471946070468139786994016460457402356;

    
    uint256 internal constant IC0x = 6383863142571362222015706476388584692123230284478488791185516887292804422940;
    uint256 internal constant IC0y = 10243060998333790665052174495744025432014142330415822083889690032427606402018;
    
    uint256 internal constant IC1x = 20472963009830843871142942049923658411434050244878271053394467774989750624577;
    uint256 internal constant IC1y = 15163321716361665646824760039815456940057830009189402911951144014143166581697;
    
    uint256 internal constant IC2x = 17154633389835627267973850331599499024470261193833161955347730551726315390131;
    uint256 internal constant IC2y = 8764067047101208074896508124675749150144935169781971158762087469302912639417;
    
    uint256 internal constant IC3x = 21552869345267824227449429703933630400800392357773375967237494969878127490154;
    uint256 internal constant IC3y = 20652696376125541479081220463083089927219994178937075609789198141842862335532;
    
 
    // Memory data
    uint16 internal constant pVk = 0;
    uint16 internal constant pPairing = 128;

    uint16 internal constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[3] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
