// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {TickMath} from "v4-core/src/libraries/TickMath.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";
import {PoolId, PoolIdLibrary} from "v4-core/src/types/PoolId.sol";
import {CurrencyLibrary, Currency} from "v4-core/src/types/Currency.sol";
import {PoolSwapTest} from "v4-core/src/test/PoolSwapTest.sol";
import {Deployers} from "v4-core/test/utils/Deployers.sol";
import {StateLibrary} from "v4-core/src/libraries/StateLibrary.sol";

import {AIStrategy} from "../src/AIStrategy.sol";
import {AIOracleHook} from "../src/AIOracleHook.sol";

contract CounterTest is Test, Deployers {
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using StateLibrary for IPoolManager;

    address poolManagerAddr = address(0xFf34e285F8ED393E366046153e3C16484A4dD674);
    address lpRouterAddr = address(0xFB3e0C6F74eB1a21CC1Da29aeC80D2Dfe6C9a317);
    address swapRouterAddr = address(0x9A8ca723F5dcCb7926D00B71deC55c2fEa1F50f7);

    address WETH = 0x14fDF78D02Ba2B136cac229caB4E78A624Fa09DC;
    address USDC = 0x693AA12886c4C2De10D0900F507603F041a9ddA9;

    uint160 sqrtPriceInit = 4339505179874779672736325173248;

    AIStrategy strategy;
    AIOracleHook hook;
    PoolId poolId;

    function setUp() public {
        // creates the pool manager, utility routers, and test tokens
        Deployers.deployFreshManagerAndRouters();
        Deployers.deployMintAndApprove2Currencies();

        // Deploy the hook to an address with the correct flags
        address flags = address(
            uint160(
                Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_ADD_LIQUIDITY_FLAG | Hooks.AFTER_ADD_LIQUIDITY_FLAG
                    | Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG | Hooks.AFTER_REMOVE_LIQUIDITY_FLAG
            )
        );
        deployCodeTo("Counter.sol:Counter", abi.encode(poolManagerAddr, lpRouterAddr, swapRouterAddr), flags);

        hook = AIOracleHook(flags);

        // Create the pool
        key = PoolKey(Currency.wrap(WETH), Currency.wrap(USDC), 3000, 60, IHooks(hook));
        poolId = key.toId();
        manager.initialize(key, sqrtPriceInit, ZERO_BYTES);

        // Provide full-range liquidity to the pool
        modifyLiquidityRouter.modifyLiquidity(
            key,
            IPoolManager.ModifyLiquidityParams(TickMath.minUsableTick(60), TickMath.maxUsableTick(60), 10_000 ether, 0),
            ZERO_BYTES
        );
    }

    // function testCounterHooks() public {
    //     // positions were created in setup()
    //     assertEq(hook.beforeAddLiquidityCount(poolId), 1);
    //     assertEq(hook.beforeRemoveLiquidityCount(poolId), 0);

    //     assertEq(hook.beforeSwapCount(poolId), 0);
    //     assertEq(hook.afterSwapCount(poolId), 0);

    //     // Perform a test swap //
    //     bool zeroForOne = true;
    //     int256 amountSpecified = -1e18; // negative number indicates exact input swap!
    //     BalanceDelta swapDelta = swap(key, zeroForOne, amountSpecified, ZERO_BYTES);
    //     // ------------------- //

    //     assertEq(int256(swapDelta.amount0()), amountSpecified);

    //     assertEq(hook.beforeSwapCount(poolId), 1);
    //     assertEq(hook.afterSwapCount(poolId), 1);
    // }

    // function testLiquidityHooks() public {
    //     // positions were created in setup()
    //     assertEq(hook.beforeAddLiquidityCount(poolId), 1);
    //     assertEq(hook.beforeRemoveLiquidityCount(poolId), 0);

    //     // remove liquidity
    //     int256 liquidityDelta = -1e18;
    //     modifyLiquidityRouter.modifyLiquidity(
    //         key,
    //         IPoolManager.ModifyLiquidityParams(
    //             TickMath.minUsableTick(60), TickMath.maxUsableTick(60), liquidityDelta, 0
    //         ),
    //         ZERO_BYTES
    //     );

    //     assertEq(hook.beforeAddLiquidityCount(poolId), 1);
    //     assertEq(hook.beforeRemoveLiquidityCount(poolId), 1);
    // }
}
