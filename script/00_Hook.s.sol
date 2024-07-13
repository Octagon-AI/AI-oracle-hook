// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {PoolManager} from "v4-core/src/PoolManager.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolModifyLiquidityTest} from "v4-core/src/test/PoolModifyLiquidityTest.sol";
import {PoolSwapTest} from "v4-core/src/test/PoolSwapTest.sol";
import {PoolDonateTest} from "v4-core/src/test/PoolDonateTest.sol";
import {HookMiner} from "../test/utils/HookMiner.sol";

import {AIOracleHook} from "../src/AIOracleHook.sol";

contract HookScript is Script {
    address constant CREATE2_DEPLOYER = address(0x4e59b44847b379578588920cA78FbF26c0B4956C);

    address poolManager = address(0xFf34e285F8ED393E366046153e3C16484A4dD674);
    address lpRouter = address(0xFB3e0C6F74eB1a21CC1Da29aeC80D2Dfe6C9a317);
    address swapRouter = address(0x9A8ca723F5dcCb7926D00B71deC55c2fEa1F50f7);

    function setUp() public {}

   
    function run() public {
        // hook contracts must have specific flags encoded in the address
        uint160 flags = uint160(
            Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_ADD_LIQUIDITY_FLAG | Hooks.AFTER_ADD_LIQUIDITY_FLAG
                | Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG | Hooks.AFTER_REMOVE_LIQUIDITY_FLAG
        );

        // Mine a salt that will produce a hook address with the correct flags
        (address hookAddress, bytes32 salt) = HookMiner.find(
            CREATE2_DEPLOYER, flags, type(AIOracleHook).creationCode, abi.encode(poolManager, lpRouter, swapRouter)
        );

        // Deploy the hook using CREATE2
        vm.broadcast();
        AIOracleHook aiOracle = new AIOracleHook{salt: salt}(poolManager, lpRouter, swapRouter);
        require(address(aiOracle) == hookAddress, "CounterScript: hook address mismatch");
    }
}
