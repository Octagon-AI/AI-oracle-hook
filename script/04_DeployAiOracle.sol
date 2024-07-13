// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolManager} from "v4-core/src/PoolManager.sol";
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {CurrencyLibrary, Currency} from "v4-core/src/types/Currency.sol";
import {PoolId, PoolIdLibrary} from "v4-core/src/types/PoolId.sol";

import {AIOracleHook} from "../src/AIOracleHook.sol";

contract CreatePoolScript is Script {
    using CurrencyLibrary for Currency;

    address poolManager = address(0xFf34e285F8ED393E366046153e3C16484A4dD674);
    address lpRouter = address(0xFB3e0C6F74eB1a21CC1Da29aeC80D2Dfe6C9a317);
    address swapRouter = address(0x9A8ca723F5dcCb7926D00B71deC55c2fEa1F50f7);

    address WETH = 0x14fDF78D02Ba2B136cac229caB4E78A624Fa09DC;
    address USDC = 0x693AA12886c4C2De10D0900F507603F041a9ddA9;

    function run() external {
        vm.broadcast();
        AIOracleHook hook = new AIOracleHook(poolManager, lpRouter, swapRouter);
    }
}
