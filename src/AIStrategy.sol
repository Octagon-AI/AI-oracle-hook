// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// import {WETH} from "solmate/src/tokens/WETH.sol";
// import {FixedPointMathLib} from "solmate/src/utils/FixedPointMathLib.sol";

import {ERC20} from "solmate/src/tokens/ERC20.sol";
import {ERC4626} from "solmate/src/mixins/ERC4626.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

import {LiquidityManager} from "./LiquidityManager.sol";
import {SwapManager} from "./SwapManager.sol";

import {IHalo2Verifier} from "./interfaces/IVerifier.sol";
import {INonfungiblePositionManager} from "./interfaces/INonfungiblePositionManager.sol";

import {TickMath} from "./libraries/TickMath.sol";

contract AIStrategy is ERC4626, LiquidityManager, SwapManager, ReentrancyGuard {
    using SafeERC20 for ERC20;
    using Math for uint256;

    IHalo2Verifier public verifier;

    error NotProverError();
    error InvalidProofError();
    error InvalidPositionSizeError();

    event NewPositionOpened(
        uint256 tokenId, uint128 liquidity, uint256 amount0, uint256 amount1, uint256 predictedFees
    );

    uint256 constant MIN_POSITION_SIZE = 1000;

    struct Scalers {
        uint256 scaler;
        uint256 minAddition;
    }

    Scalers public feeScalers;
    Scalers public highScalers;
    Scalers public lowScalers;

    address public prover;

    modifier onlyProver() {
        // if (msg.sender != prover) revert NotProverError();
        _;
    }

    constructor(
        address _asset,
        string memory strategyName,
        string memory symbol,
        address _positionManager,
        address _swapRouter,
        address _modelVerifier,
        uint256[3] memory scalers,
        uint256[3] memory minAdditions
    ) LiquidityManager(_positionManager) SwapManager(_swapRouter) ERC4626(ERC20(_asset), strategyName, symbol) {
        verifier = IHalo2Verifier(_modelVerifier);

        feeScalers = Scalers(scalers[0], minAdditions[0]);
        highScalers = Scalers(scalers[1], minAdditions[1]);
        lowScalers = Scalers(scalers[2], minAdditions[2]);
    }

    // Override totalAssets to include assets managed by the strategy
    function totalAssets() public view override returns (uint256) {
        // Include assets in the vault and those managed by the strategy
        return asset.balanceOf(address(this)) + _getAssetsInStrategy();
    }

    // Override deposit to include strategy management
    function deposit(uint256 assets, address receiver) public override nonReentrant returns (uint256) {
        uint256 shares = previewDeposit(assets);
        asset.transferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares);

        // Manage the deposited assets according to the strategy
        _investInStrategy(assets);

        return shares;
    }

    function updateLiquidity(
        uint256 tokenId,
        PoolInfo memory newPool,
        bytes calldata proof,
        uint256[] calldata instances
    ) external onlyProver {
        // ! Verify the proof
        bool valid = verifier.verifyProof(proof, instances);
        if (!valid) revert InvalidProofError();

        // ! Remove the liquidity from the pool if necessary
        _removeLiquidityAndSellToEth(tokenId);

        if (asset.balanceOf(address(this)) < MIN_POSITION_SIZE) revert InvalidPositionSizeError();

        // ! Swap the tokens to the newPool assets
        (uint256 amount0, uint256 amount1) = _swapToNewPoolAssets(newPool);

        // ! Get the tick range for the new pool
        (address token0, address token1, uint24 fee) = (newPool.token0, newPool.token1, newPool.fee);

        uint256 predictedFees = _scaleProofOutput(instances[0], feeScalers);
        uint256 predictedHigh = _scaleProofOutput(instances[2], highScalers);
        uint256 predictedLow = _scaleProofOutput(instances[1], lowScalers);

        int24 tickUpper = _getTickFromPrice(predictedHigh);
        int24 tickLower = _getTickFromPrice(predictedLow);

        // ! Construct the mintParams for the new LP position

        INonfungiblePositionManager.MintParams memory params = INonfungiblePositionManager.MintParams({
            token0: token0,
            token1: token1,
            fee: fee,
            tickLower: tickLower,
            tickUpper: tickUpper,
            amount0Desired: amount0,
            amount1Desired: amount1,
            amount0Min: 0,
            amount1Min: 0,
            recipient: address(this),
            deadline: block.timestamp + 10 // Only in this block
        });

        // ! Open a new position with the newPool assets
        (uint256 newTokenId, uint128 liquidity, uint256 newAmount0, uint256 newAmount1) = openNewPosition(params);

        emit NewPositionOpened(newTokenId, liquidity, newAmount0, newAmount1, predictedFees);
    }

    // * HELPERS ================================================================

    function _removeLiquidityAndSellToEth(uint256 tokenId) private {
        if (s_activeLiquidity > 0 && tokenId != 0) {
            (uint256 amount0, uint256 amount1) = removeLiquidity(tokenId, s_activeLiquidity, 0, 0, block.timestamp + 10);

            // ! Swap the tokens back to the original vault asset (ETH)
            (address token0, address token1,) = (s_activePool.token0, s_activePool.token1, s_activePool.fee);
            if (token0 != address(asset)) {
                swapExactInputSingle(amount0, 0, token0, address(asset), address(this));
            }

            if (token1 != address(asset)) {
                swapExactInputSingle(amount1, 0, token1, address(asset), address(this));
            }
        }
    }

    function _swapToNewPoolAssets(PoolInfo memory newPool) private returns (uint256 amount0, uint256 amount1) {
        // ! Swap the tokens back to the original vault asset (ETH)
        (address token0, address token1,) = (newPool.token0, newPool.token1, newPool.fee);

        uint256 amount = asset.balanceOf(address(this)) / 2;

        amount0 = amount;
        amount1 = amount;
        if (token0 != address(asset)) {
            amount0 = swapExactInputSingle(amount, 0, address(asset), token0, address(this));
        }

        if (token1 != address(asset)) {
            amount1 = swapExactInputSingle(amount, 0, address(asset), token1, address(this));
        }
    }

    // Gets the model output result scaled by 10**5
    function _scaleProofOutput(uint256 proofOutput, Scalers storage scalers)
        private
        view
        returns (uint256 scaledOutput)
    {
        // Proof output is scaled by 2**11 so we devide by that
        // scaler is scaled by 10**18 so we devide by 10**13 because we want to scale by 10**5
        // minAddition is also scaled by 10**18 so we devide by 10**13 because we want to scale by 10**5
        scaledOutput = (proofOutput * scalers.scaler) / (2 ** 11 * 10 ** 13) + scalers.minAddition / 10 ** 13;
    }

    ///
    /// @param price The price scaled by 10**5
    function _getTickFromPrice(uint256 price) private pure returns (int24 tick) {
        uint256 sqrtPrice = Math.sqrt(price);

        uint256 sqrtPriceX96 = (sqrtPrice * 10 ** 5 * 2 ** 96) / 10 ** 5;

        int24 tick_temp = TickMath.getTickAtSqrtRatio(uint160(sqrtPriceX96));

        // Calculate the remainder when number is divided by 60
        int24 remainder = tick_temp % 60;

        if (remainder > 0) {
            return tick_temp - remainder;
        } else if (remainder < 0) {
            return tick_temp - remainder - 60;
        } else {
            return tick_temp;
        }
    }

    // Override withdraw to include strategy management
    // function withdraw(uint256 assets, address receiver, address owner) public override nonReentrant returns (uint256) {
    // }

    // Get assets managed by the strategy (e.g., assets deposited in Aave)
    function _getAssetsInStrategy() internal pure returns (uint256) {
        // Implement logic to retrieve assets managed by the strategy
        // This is a placeholder and needs to be replaced with actual logic
        // Example: activePool.liquidity * ???;
        return 0;
    }

    // Invest assets in the strategy (e.g., deposit into Aave)
    function _investInStrategy(uint256 assets) internal {
        // TODO: Swap half and half of the assets to the new pool assets
        // TODO: addLiquidityToPool(assets);
    }
}
