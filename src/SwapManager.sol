// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

import "./interfaces/ISwapRouter.sol";

contract SwapManager {
    ISwapRouter public immutable swapRouter;

    // Set the pool fee to 0.3%.
    uint24 public constant poolFee = 3000;

    constructor(address _swapRouter) {
        swapRouter = ISwapRouter(_swapRouter);
    }

    /// @notice Swaps a fixed amount of input token for a maximum possible amount of output token
    /// @param amountIn The exact amount of input token to be swapped
    /// @param amountOutMin The minimum amount of output token that must be received for the swap
    /// @param tokenIn The address of the input token
    /// @param tokenOut The address of the output token
    /// @param to The address that receives the output token
    function swapExactInputSingle(uint256 amountIn, uint256 amountOutMin, address tokenIn, address tokenOut, address to)
        public
        returns (uint256 amountOut)
    {
        // Approve the router to spend tokenIn.
        IERC20(tokenIn).approve(address(swapRouter), amountIn);

        // Set up the parameters for the swap.
        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            fee: poolFee,
            recipient: to,
            amountIn: amountIn,
            amountOutMinimum: amountOutMin,
            sqrtPriceLimitX96: 0
        });

        // Execute the swap.
        amountOut = swapRouter.exactInputSingle(params);
    }
}
