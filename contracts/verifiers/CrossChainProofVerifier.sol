// SPDX-License-Identifier: MIT
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

pragma solidity ^0.8.24;

/**
 * @title CrossChainProofVerifier
 * @author ZASEON Team
 * @notice Cross Chain Proof Verifier contract
 */
contract CrossChainProofVerifier {
    // Scalar field size
    uint256 internal constant _r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 internal constant _q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 internal constant _alphax  = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 internal constant _alphay  = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 internal constant _betax1  = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 internal constant _betax2  = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 internal constant _betay1  = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 internal constant _betay2  = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 internal constant _gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 internal constant _gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 internal constant _gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 internal constant _gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 internal constant _deltax1 = 1395726966279570445591055411099746442472448713317921159628779887529704411304;
    uint256 internal constant _deltax2 = 14841720514900611188873216886977630166190402133622456420058741170546692990835;
    uint256 internal constant _deltay1 = 5430400955469402610976226808464766355099923003002933200563793538669772365784;
    uint256 internal constant _deltay2 = 8951032808719420666675113007067553010144397287198649347021189832521279849228;

    
    uint256 internal constant _IC0x = 10463044926228245046715686908864073473877282956016026464564486657068942507187;
    uint256 internal constant _IC0y = 20603107948870321217640225233306863489797170886308405934643555260426341317430;
    
    uint256 internal constant _IC1x = 2195575006005776396730811011438390668778377161996805060975195273879517438933;
    uint256 internal constant _IC1y = 12570517334709449120317021116284753512825282967695427449524596456850882125015;
    
    uint256 internal constant _IC2x = 21429264127699284540592787679974420234275143288760960531438760529543347330307;
    uint256 internal constant _IC2y = 19575190742846016447660871546513055590261440639154937260485392419182376734870;
    
    uint256 internal constant _IC3x = 15260576609979165563691619903961543979653612475556788211166016065814928988341;
    uint256 internal constant _IC3y = 18668869917185256198497186819378519857869265701595180802183426430134661290413;
    
    uint256 internal constant _IC4x = 18418110676990999157210574463606221965534896420102110066378478600741489019300;
    uint256 internal constant _IC4y = 21683460406224589091872252940193008251367202775271950691201388829249432798553;
    
    uint256 internal constant _IC5x = 4659743327545502296739124404582678412042923260119320944902974108475658222105;
    uint256 internal constant _IC5y = 20630445248450227128333256875798221739434233176511983242246070860009030357046;
    
    uint256 internal constant _IC6x = 15974158158895645461215382214181725061484162243904387309975250471473677234284;
    uint256 internal constant _IC6y = 6496507738022225241120987080663301782058617121557300910799419528835965258807;
    
    uint256 internal constant _IC7x = 8444201158059824251869828933036276077691022583203134699537024612528117616267;
    uint256 internal constant _IC7y = 4153918216747734030684301963633953559151704134368681257103611692751653983352;
    
 
    // Memory data
    uint16 internal constant _pVk = 0;
    uint16 internal constant _pPairing = 128;

    uint16 internal constant _pLastMem = 896;

        /**
     * @notice Verifys proof
     * @param _pA The _p a
     * @param _pB The _p b
     * @param _pC The _p c
     * @param _pubSignals The _pub signals
     * @return The result value
     */
function verifyProof(uint256[2] calldata _pA, uint256[2][2] calldata _pB, uint256[2] calldata _pC, uint256[7] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, _r)) {
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
                let ptrPairing := add(pMem, _pPairing)
                let ptrVk := add(pMem, _pVk)

                mstore(ptrVk, _IC0x)
                mstore(add(ptrVk, 32), _IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(ptrVk, _IC1x, _IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(ptrVk, _IC2x, _IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(ptrVk, _IC3x, _IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(ptrVk, _IC4x, _IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(ptrVk, _IC5x, _IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(ptrVk, _IC6x, _IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(ptrVk, _IC7x, _IC7y, calldataload(add(pubSignals, 192)))
                

                // -A
                mstore(ptrPairing, calldataload(pA))
                mstore(add(ptrPairing, 32), mod(sub(_q, calldataload(add(pA, 32))), _q))

                // B
                mstore(add(ptrPairing, 64), calldataload(pB))
                mstore(add(ptrPairing, 96), calldataload(add(pB, 32)))
                mstore(add(ptrPairing, 128), calldataload(add(pB, 64)))
                mstore(add(ptrPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(ptrPairing, 192), _alphax)
                mstore(add(ptrPairing, 224), _alphay)

                // beta2
                mstore(add(ptrPairing, 256), _betax1)
                mstore(add(ptrPairing, 288), _betax2)
                mstore(add(ptrPairing, 320), _betay1)
                mstore(add(ptrPairing, 352), _betay2)

                // vk_x
                mstore(add(ptrPairing, 384), mload(add(pMem, _pVk)))
                mstore(add(ptrPairing, 416), mload(add(pMem, add(_pVk, 32))))


                // gamma2
                mstore(add(ptrPairing, 448), _gammax1)
                mstore(add(ptrPairing, 480), _gammax2)
                mstore(add(ptrPairing, 512), _gammay1)
                mstore(add(ptrPairing, 544), _gammay2)

                // C
                mstore(add(ptrPairing, 576), calldataload(pC))
                mstore(add(ptrPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(ptrPairing, 640), _deltax1)
                mstore(add(ptrPairing, 672), _deltax2)
                mstore(add(ptrPairing, 704), _deltay1)
                mstore(add(ptrPairing, 736), _deltay2)


                let success := staticcall(sub(gas(), 2000), 8, ptrPairing, 768, ptrPairing, 0x20)

                isOk := and(success, mload(ptrPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, _pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
