// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BaseHook} from "v4-periphery/BaseHook.sol";

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {Currency} from "v4-core/src/types/Currency.sol";
import {PoolId, PoolIdLibrary} from "v4-core/src/types/PoolId.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/src/types/BeforeSwapDelta.sol";

import {IAIStrategy} from "./interfaces/IAIStrategy.sol";

import {LiquidityManager} from "./LiquidityManager.sol";

contract AIOracleHook is BaseHook, LiquidityManager {
    using PoolIdLibrary for PoolKey;

    // NOTE: ---------------------------------------------------------
    // state variables should typically be unique to a pool
    // a single hook contract should be able to service multiple pools
    // ---------------------------------------------------------------

    event UpdatedLpRange();

    mapping(PoolId => uint256 count) public beforeSwapCount;
    mapping(PoolId => uint256 count) public afterSwapCount;

    mapping(PoolId => uint256 count) public beforeAddLiquidityCount;
    mapping(PoolId => uint256 count) public beforeRemoveLiquidityCount;

    address aiOracle;

    IAIStrategy.Predictions private s_activePredictions;

    bool private s_initialized = false;

    // TODO: before moodify position:
    // 1. check that the lp range hook is the only one who can provide liquidity

    // TODO: After modify position:
    // What to do here

    // TODO: before swap:
    // 1. Check if the range should be updated

    constructor(address _poolManager, address _lpRouter, address _swapRouter)
        BaseHook(IPoolManager(_poolManager))
        LiquidityManager(_lpRouter, _swapRouter)
    {}

    function setAIOracle(address _oracle) external {
        aiOracle = _oracle;
    }

    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: true,
            afterAddLiquidity: true,
            beforeRemoveLiquidity: true,
            afterRemoveLiquidity: true,
            beforeSwap: true,
            afterSwap: false,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: false,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    // -----------------------------------------------
    // NOTE: see IHooks.sol for function documentation

    function provideLiquidity(address token0, address token1, uint256 amount0, uint256 amount1) external {
        IERC20(token0).transferFrom(msg.sender, address(this), amount0);
        IERC20(token1).transferFrom(msg.sender, address(this), amount1);
    }

    // -----------------------------------------------

    function beforeSwap(address, PoolKey calldata key, IPoolManager.SwapParams calldata, bytes calldata)
        external
        override
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        beforeSwapCount[key.toId()]++;

        // ! Check if position range should be updated
        IAIStrategy.Predictions storage activePredictions = s_activePredictions;
        // TODO: IAIStrategy.Predictions memory newPredictions = IAIStrategy(aiOracle).getPredictions();
        IAIStrategy.Predictions memory newPredictions = IAIStrategy.Predictions(0, 600, -600);

        if (
            newPredictions.predictedTickUpper != activePredictions.predictedTickUpper
                || newPredictions.predictedTickLower != activePredictions.predictedTickLower
        ) {
            (uint256 amount0, uint256 amount1) = (
                IERC20(Currency.unwrap(key.currency0)).balanceOf(address(this)),
                IERC20(Currency.unwrap(key.currency1)).balanceOf(address(this))
            );

            if (s_initialized) {
                (amount0, amount1) =
                    removeLiquidity(Currency.unwrap(key.currency0), Currency.unwrap(key.currency1), key.fee);
            }

            openNewPosition(
                Currency.unwrap(key.currency0),
                Currency.unwrap(key.currency1),
                amount0,
                amount1,
                key.fee,
                newPredictions.predictedTickLower,
                newPredictions.predictedTickUpper
            );

            activePredictions.predictedTickUpper = newPredictions.predictedTickUpper;
            activePredictions.predictedTickLower = newPredictions.predictedTickLower;
            activePredictions.predictedFees = newPredictions.predictedFees;

            // TODO: s_initialized = true;

            emit UpdatedLpRange();
        }

        return (BaseHook.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }

    function beforeAddLiquidity(
        address sender,
        PoolKey calldata key,
        IPoolManager.ModifyLiquidityParams calldata,
        bytes calldata
    ) external override returns (bytes4) {
        beforeAddLiquidityCount[key.toId()]++;

        if (sender != address(this)) {
            revert("AIOracleHook: only the AIOracle can add liquidity");
        }

        return BaseHook.beforeAddLiquidity.selector;
    }

    function beforeRemoveLiquidity(
        address sender,
        PoolKey calldata key,
        IPoolManager.ModifyLiquidityParams calldata,
        bytes calldata
    ) external override returns (bytes4) {
        beforeRemoveLiquidityCount[key.toId()]++;

        if (sender != address(this)) {
            revert("AIOracleHook: only the AIOracle can add liquidity");
        }

        return BaseHook.beforeRemoveLiquidity.selector;
    }
}
