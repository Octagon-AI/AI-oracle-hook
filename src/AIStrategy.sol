// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// import {WETH} from "solmate/src/tokens/WETH.sol";
// import {FixedPointMathLib} from "solmate/src/utils/FixedPointMathLib.sol";

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/math/Math.sol";

import {LiquidityManager} from "./LiquidityManager.sol";

import {IHalo2Verifier} from "./interfaces/IVerifier.sol";

import {TickMath} from "./libraries/TickMath.sol";

contract AIStrategy {
    using Math for uint256;

    IHalo2Verifier public verifier;

    error NotProverError();
    error InvalidProofError();

    uint256 constant MIN_POSITION_SIZE = 1000;

    struct Predictions {
        uint256 predictedFees;
        int24 predictedTickUpper;
        int24 predictedTickLower;
    }

    struct Scalers {
        uint256 scaler;
        uint256 minAddition;
    }

    Scalers public feeScalers;
    Scalers public highScalers;
    Scalers public lowScalers;

    address public prover;

    Predictions private s_predictions;

    modifier onlyProver() {
        // if (msg.sender != prover) revert NotProverError();
        _;
    }

    constructor(address _modelVerifier, uint256[3] memory scalers, uint256[3] memory minAdditions) {
        verifier = IHalo2Verifier(_modelVerifier);

        feeScalers = Scalers(scalers[0], minAdditions[0]);
        highScalers = Scalers(scalers[1], minAdditions[1]);
        lowScalers = Scalers(scalers[2], minAdditions[2]);
    }

    function updateRangePrediction(bytes calldata proof, uint256[] calldata instances) external onlyProver {
        // ! Verify the proof
        bool valid = verifier.verifyProof(proof, instances);
        if (!valid) revert InvalidProofError();

        uint256 predictedFees = _scaleProofOutput(instances[0], feeScalers);
        uint256 predictedHigh = _scaleProofOutput(instances[2], highScalers);
        uint256 predictedLow = _scaleProofOutput(instances[1], lowScalers);

        int24 tickUpper = _getTickFromPrice(predictedHigh);
        int24 tickLower = _getTickFromPrice(predictedLow);

        s_predictions = Predictions(predictedFees, tickUpper, tickLower);
    }

    // * GETTERS ================================================================

    function getPredictions() external view returns (Predictions memory) {
        return s_predictions;
    }

    // * HELPERS ================================================================

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
}
