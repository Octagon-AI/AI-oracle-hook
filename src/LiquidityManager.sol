// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "v4-periphery/libraries/LiquidityAmounts.sol";
import {PoolModifyLiquidityTest} from "v4-core/src/test/PoolModifyLiquidityTest.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {CurrencyLibrary, Currency} from "v4-core/src/types/Currency.sol";
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolSwapTest} from "v4-core/src/test/PoolSwapTest.sol";

import {BalanceDelta, BalanceDeltaLibrary} from "v4-core/src/types/BalanceDelta.sol";

import {TickMath} from "./libraries/TickMath.sol";

abstract contract LiquidityManager {
    struct PoolInfo {
        address token0;
        address token1;
        uint24 fee;
    }

    struct TickRange {
        int24 lower;
        int24 upper;
    }

    event RemoveLiquidityEvent();
    event AddLiquidityEvent();

    int24 constant TICK_SPACING = 60;
    uint160 constant sqrtRatioX96Price = 4339505179874779672736325173248; // 3000 USDC/ETH

    PoolInfo public s_activePool;
    mapping(bytes32 => TickRange) public s_activeTickRange;
    mapping(bytes32 => uint256) public s_activeLiquidity;

    PoolModifyLiquidityTest public lpRouter;
    PoolSwapTest public swapRouter;

    constructor(address _lpRouter, address _swapRouter) {
        lpRouter = PoolModifyLiquidityTest(_lpRouter);
        swapRouter = PoolSwapTest(_swapRouter);
    }

    function openNewPosition(
        address token0,
        address token1,
        uint256 amount0,
        uint256 amount1,
        uint24 swapFee,
        int24 lower,
        int24 upper
    ) internal {
        PoolKey memory pool = PoolKey({
            currency0: Currency.wrap(token0),
            currency1: Currency.wrap(token1),
            fee: swapFee,
            tickSpacing: TICK_SPACING,
            hooks: IHooks(address(this))
        });

        bytes memory hookData = new bytes(0);

        uint160 sqrtRatioX96Lower = TickMath.getSqrtRatioAtTick(lower);
        uint160 sqrtRatioX96Upper = TickMath.getSqrtRatioAtTick(upper);

        uint256 liquidity = LiquidityAmounts.getLiquidityForAmounts(
            sqrtRatioX96Price, sqrtRatioX96Lower, sqrtRatioX96Upper, amount0, amount1
        ); // TODO

        IERC20(token0).approve(address(lpRouter), amount0);
        IERC20(token1).approve(address(lpRouter), amount1);

        lpRouter.modifyLiquidity(pool, IPoolManager.ModifyLiquidityParams(lower, upper, int256(liquidity), 0), hookData);

        bytes32 poolId = keccak256(abi.encodePacked(pool.currency0, pool.currency1, pool.fee));
        s_activeLiquidity[poolId] += liquidity;
        s_activeTickRange[poolId] = TickRange(lower, upper);

        emit AddLiquidityEvent();
    }

    function removeLiquidity(address token0, address token1, uint24 swapFee)
        internal
        returns (uint256 amount0, uint256 amount1)
    {
        PoolKey memory pool = PoolKey({
            currency0: Currency.wrap(token0),
            currency1: Currency.wrap(token1),
            fee: swapFee,
            tickSpacing: TICK_SPACING,
            hooks: IHooks(address(this))
        });

        bytes memory hookData = new bytes(0);

        bytes32 poolId = keccak256(abi.encodePacked(pool.currency0, pool.currency1, pool.fee));
        uint256 liquidity = s_activeLiquidity[poolId];
        TickRange storage tickRange = s_activeTickRange[poolId];

        BalanceDelta delta = lpRouter.modifyLiquidity(
            pool, IPoolManager.ModifyLiquidityParams(tickRange.lower, tickRange.upper, -int256(liquidity), 0), hookData
        );

        int256 balance0 = BalanceDeltaLibrary.amount0(delta);
        int256 balance1 = BalanceDeltaLibrary.amount1(delta);

        emit RemoveLiquidityEvent();

        return (uint256(balance0), uint256(balance1));
    }

    function executeSwap(address token0, address token1, uint256 amount0, uint24 swapFee)
        internal
        returns (uint256, uint256)
    {
        PoolKey memory pool = PoolKey({
            currency0: Currency.wrap(token0),
            currency1: Currency.wrap(token1),
            fee: swapFee,
            tickSpacing: TICK_SPACING,
            hooks: IHooks(address(this))
        });

        IERC20(token0).approve(address(swapRouter), amount0);

        // ---------------------------- //
        // Swap 100e18 token0 into token1 //
        // ---------------------------- //
        bool zeroForOne = true;
        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: zeroForOne,
            amountSpecified: int256(amount0),
            sqrtPriceLimitX96: 0 // unlimited impact
        });

        // in v4, users have the option to receieve native ERC20s or wrapped ERC1155 tokens
        // here, we'll take the ERC20s
        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false});

        bytes memory hookData = new bytes(0);
        (BalanceDelta delta) = swapRouter.swap(pool, params, testSettings, hookData);

        int256 balance0 = BalanceDeltaLibrary.amount0(delta);
        int256 balance1 = BalanceDeltaLibrary.amount1(delta);

        return (uint256(balance0), uint256(balance1));
    }

    // * UTILITIES --------------------------------------------
}
