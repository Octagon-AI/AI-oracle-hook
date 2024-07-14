// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
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

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {AIStrategy} from "../src/AIStrategy.sol";
import {AIOracleHook} from "../src/AIOracleHook.sol";
import {Halo2Verifier} from "../src/Verifier.sol";

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
    Halo2Verifier public verifier;

    PoolSwapTest swapRouterTest;

    function setUp() public {
        // creates the pool manager, utility routers, and test tokens
        Deployers.deployFreshManagerAndRouters();
        Deployers.deployMintAndApprove2Currencies();

        // Deploy the hook to an address with the correct flags
        address flags = address(
            uint160(
                Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG | Hooks.BEFORE_ADD_LIQUIDITY_FLAG
                    | Hooks.AFTER_ADD_LIQUIDITY_FLAG | Hooks.BEFORE_REMOVE_LIQUIDITY_FLAG
                    | Hooks.AFTER_REMOVE_LIQUIDITY_FLAG
            )
        );
        deployCodeTo("AIOracleHook.sol:AIOracleHook", abi.encode(poolManagerAddr, lpRouterAddr, swapRouterAddr), flags);

        hook = AIOracleHook(flags);

        // Create the pool
        key = PoolKey({
            currency0: Currency.wrap(WETH),
            currency1: Currency.wrap(USDC),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(flags)
        });

        poolId = key.toId();
        IPoolManager(poolManagerAddr).initialize(key, sqrtPriceInit, ZERO_BYTES);

        swapRouterTest = PoolSwapTest(swapRouterAddr);

        // * ===================================================================

        verifier = new Halo2Verifier();

        uint256[3] memory scalers =
            [uint256(7455504813211), uint256(2953758299944270168064), uint256(1838876263346026577920)];
        uint256[3] memory minAddition = [uint256(1729926753534472704), uint256(262951735771738), uint256(0)];

        strategy = new AIStrategy(address(verifier), scalers, minAddition);
    }

    function testAddLiquidity() public {
        // positions were created in setup()
        // assertEq(hook.beforeAddLiquidityCount(poolId), 0);
        // assertEq(hook.beforeRemoveLiquidityCount(poolId), 0);

        vm.startPrank(0xaCEdF8742eDC7d923e1e6462852cCE136ee9Fb56);
        IERC20(WETH).approve(address(hook), 1e18);
        IERC20(USDC).approve(address(hook), 1000e18);

        hook.provideLiquidity(WETH, USDC, 1e18, 1000e18);

        // assertEq(hook.beforeAddLiquidityCount(poolId), 1);
        // assertEq(hook.beforeRemoveLiquidityCount(poolId), 0);
    }

    function testMakeSwap() public {
        testAddLiquidity();

        // positions were created in setup()
        assertEq(hook.beforeAddLiquidityCount(poolId), 0);
        assertEq(hook.beforeRemoveLiquidityCount(poolId), 0);

        assertEq(hook.beforeSwapCount(poolId), 0);
        assertEq(hook.afterSwapCount(poolId), 0);

        // Using a hooked pool
        PoolKey memory pool = PoolKey({
            currency0: Currency.wrap(WETH),
            currency1: Currency.wrap(USDC),
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });

        bool zeroForOne = true;
        IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
            zeroForOne: zeroForOne,
            amountSpecified: 0.1e18,
            sqrtPriceLimitX96: zeroForOne ? MIN_PRICE_LIMIT : MAX_PRICE_LIMIT // unlimited impact
        });

        // in v4, users have the option to receieve native ERC20s or wrapped ERC1155 tokens
        // here, we'll take the ERC20s
        PoolSwapTest.TestSettings memory testSettings =
            PoolSwapTest.TestSettings({takeClaims: false, settleUsingBurn: false});

        bytes memory hookData = new bytes(0);
        BalanceDelta swapDelta = swapRouterTest.swap(pool, params, testSettings, hookData);
        // ------------------- //

        int256 res = int128(swapDelta.amount0());
        console.log(uint256(res));

        console.log("Swap Delta");

        // assertEq(hook.beforeSwapCount(poolId), 1);
        // assertEq(hook.afterSwapCount(poolId), 1);
    }

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
