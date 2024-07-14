// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./interfaces/INonfungiblePositionManager.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

abstract contract LiquidityManager {
    INonfungiblePositionManager public positionManager;

    struct PoolInfo {
        address token0;
        address token1;
        uint24 fee;
    }

    struct TickRange {
        int24 lower;
        int24 upper;
    }

    PoolInfo public s_activePool;
    TickRange public s_activeTickRange;
    uint128 public s_activeLiquidity;

    constructor(address _positionManager) {
        positionManager = INonfungiblePositionManager(_positionManager);
    }

    function openNewPosition(INonfungiblePositionManager.MintParams memory params)
        internal
        returns (uint256 tokenId, uint128 liquidity, uint256 amount0, uint256 amount1)
    {
        (tokenId, liquidity, amount0, amount1) = _addLiquidityInner(params);

        s_activePool = PoolInfo({token0: params.token0, token1: params.token1, fee: params.fee});
        s_activeTickRange = TickRange({lower: params.tickLower, upper: params.tickUpper});
        s_activeLiquidity = liquidity;
    }

    function addLiquidityToPool(uint256 amount)
        internal
        returns (uint256 tokenId, uint128 liquidity, uint256 amount0, uint256 amount1)
    {
        // TODO: Swap half of token0 for token1

        (address token0, address token1, uint24 fee) = (s_activePool.token0, s_activePool.token1, s_activePool.fee);
        (int24 tickLower, int24 tickUpper) = (s_activeTickRange.lower, s_activeTickRange.upper);

        INonfungiblePositionManager.MintParams memory params = INonfungiblePositionManager.MintParams({
            token0: token0,
            token1: token1,
            fee: fee,
            tickLower: tickLower,
            tickUpper: tickUpper,
            amount0Desired: amount,
            amount1Desired: amount,
            amount0Min: 0,
            amount1Min: 0,
            recipient: address(this),
            deadline: block.timestamp + 10 // Only in this block
        });

        (tokenId, liquidity, amount0, amount1) = _addLiquidityInner(params);

        s_activeLiquidity += liquidity;
    }

    function _addLiquidityInner(INonfungiblePositionManager.MintParams memory params)
        private
        returns (uint256 tokenId, uint128 liquidity, uint256 amount0, uint256 amount1)
    {
        IERC20(params.token0).approve(address(positionManager), params.amount0Desired);
        IERC20(params.token1).approve(address(positionManager), params.amount1Desired);

        (tokenId, liquidity, amount0, amount1) = positionManager.mint(params);

        // ! Keep the remaining funds in the vault instead of returning them to the user
    }

    function removeLiquidity(
        uint256 tokenId,
        uint128 liquidity,
        uint256 amount0Min,
        uint256 amount1Min,
        uint256 deadline
    ) internal returns (uint256 amount0, uint256 amount1) {
        INonfungiblePositionManager.DecreaseLiquidityParams memory params = INonfungiblePositionManager
            .DecreaseLiquidityParams({
            tokenId: tokenId,
            liquidity: liquidity,
            amount0Min: amount0Min,
            amount1Min: amount1Min,
            deadline: deadline
        });

        (amount0, amount1) = positionManager.decreaseLiquidity(params);

        // Collect the fees and remaining liquidity
        INonfungiblePositionManager.CollectParams memory collectParams = INonfungiblePositionManager.CollectParams({
            tokenId: tokenId,
            recipient: msg.sender,
            amount0Max: type(uint128).max,
            amount1Max: type(uint128).max
        });

        positionManager.collect(collectParams);
    }
}
