// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

interface IAIStrategy {
    struct Predictions {
        uint256 predictedFees;
        int24 predictedTickUpper;
        int24 predictedTickLower;
    }

    function updateRangePrediction(bytes calldata proof, uint256[] calldata instances) external;

    function getPredictions() external view returns (Predictions memory);
}
