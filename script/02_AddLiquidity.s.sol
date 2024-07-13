// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {PoolModifyLiquidityTest} from "v4-core/src/test/PoolModifyLiquidityTest.sol";
import {CurrencyLibrary, Currency} from "v4-core/src/types/Currency.sol";
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {PoolId, PoolIdLibrary} from "v4-core/src/types/PoolId.sol";

contract AddLiquidityScript is Script {
    using CurrencyLibrary for Currency;

    //addresses with contracts deployed
    address poolManager = address(0xFf34e285F8ED393E366046153e3C16484A4dD674);
    address lpRouterAddr = address(0xFB3e0C6F74eB1a21CC1Da29aeC80D2Dfe6C9a317);
    address swapRouter = address(0x9A8ca723F5dcCb7926D00B71deC55c2fEa1F50f7);

    address WETH = 0x14fDF78D02Ba2B136cac229caB4E78A624Fa09DC;
    address USDC = 0x693AA12886c4C2De10D0900F507603F041a9ddA9;

    address HOOK_ADDRESS = 0x2C0Cc9960fEDDF68DC51CABD8f1B9Bd0622B0f80;

    PoolModifyLiquidityTest lpRouter = PoolModifyLiquidityTest(lpRouterAddr);

    function run() external {
        //
        address token0 = uint160(USDC) < uint160(WETH) ? USDC : WETH;
        address token1 = uint160(USDC) < uint160(WETH) ? WETH : USDC;
        uint24 swapFee = 3000;
        int24 tickSpacing = 60;

        PoolKey memory pool = PoolKey({
            currency0: Currency.wrap(token0),
            currency1: Currency.wrap(token1),
            fee: swapFee,
            tickSpacing: tickSpacing,
            hooks: IHooks(HOOK_ADDRESS)
        });

        // approve tokens to the LP Router
        vm.broadcast();
        IERC20(token0).approve(address(lpRouter), 1000e18);
        vm.broadcast();
        IERC20(token1).approve(address(lpRouter), 1000e18);

        // optionally specify hookData if the hook depends on arbitrary data for liquidity modification
        bytes memory hookData = new bytes(0);

        // logging the pool ID
        PoolId id = PoolIdLibrary.toId(pool);
        bytes32 idBytes = PoolId.unwrap(id);
        console.log("Pool ID Below");
        console.logBytes32(bytes32(idBytes));

        // Provide 10_000e18 worth of liquidity on the range of [-600, 600]
        vm.broadcast();
        lpRouter.modifyLiquidity(pool, IPoolManager.ModifyLiquidityParams(-600, 600, 10_000e18, 0), hookData);
    }
}
