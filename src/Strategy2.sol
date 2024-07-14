// contract MyERC4626VaultWithStrategy is ERC4626, ReentrancyGuard {
//     using SafeERC20 for IERC20;

//     IAaveLendingPool public immutable lendingPool;

//     constructor(IERC20 _asset, IAaveLendingPool _lendingPool) ERC20("My Vault Token", "MVT") ERC4626(_asset) {
//         lendingPool = _lendingPool;
//     }

//     // Override totalAssets to include assets managed by the strategy
//     function totalAssets() public view override returns (uint256) {
//         // Include assets in the vault and those managed by the strategy
//         return asset.balanceOf(address(this)) + _getAssetsInStrategy();
//     }

//     // Get assets managed by the strategy (e.g., assets deposited in Aave)
//     function _getAssetsInStrategy() internal view returns (uint256) {
//         // Implement logic to retrieve assets managed by the strategy
//         // This is a placeholder and needs to be replaced with actual logic
//         // Example: return aToken.balanceOf(address(this));
//         return 0;
//     }

//     // Override deposit to include strategy management
//     function deposit(uint256 assets, address receiver) public override nonReentrant returns (uint256) {
//         uint256 shares = previewDeposit(assets);
//         asset.safeTransferFrom(msg.sender, address(this), assets);
//         _mint(receiver, shares);

//         // Manage the deposited assets according to the strategy
//         _investInStrategy(assets);

//         return shares;
//     }

//     // Override withdraw to include strategy management
//     function withdraw(uint256 assets, address receiver, address owner) public override nonReentrant returns (uint256) {
//         uint256 shares = previewWithdraw(assets);
//         if (msg.sender != owner) {
//             _spendAllowance(owner, msg.sender, shares);
//         }
//         _burn(owner, shares);

//         // Ensure sufficient assets are available for withdrawal
//         _ensureLiquidity(assets);
//         asset.safeTransfer(receiver, assets);

//         return shares;
//     }

//     // Invest assets in the strategy (e.g., deposit into Aave)
//     function _investInStrategy(uint256 assets) internal {
//         asset.safeApprove(address(lendingPool), assets);
//         lendingPool.deposit(address(asset), assets, address(this), 0);
//     }

//     // Ensure sufficient liquidity for withdrawals by redeeming from the strategy
//     function _ensureLiquidity(uint256 assets) internal {
//         uint256 available = asset.balanceOf(address(this));
//         if (available < assets) {
//             uint256 required = assets - available;
//             lendingPool.withdraw(address(asset), required, address(this));
//         }
//     }

//     // Redeem assets from the strategy
//     function redeem(uint256 shares, address receiver, address owner) public override nonReentrant returns (uint256) {
//         uint256 assets = previewRedeem(shares);
//         if (msg.sender != owner) {
//             _spendAllowance(owner, msg.sender, shares);
//         }
//         _burn(owner, shares);

//         // Ensure sufficient assets are available for redemption
//         _ensureLiquidity(assets);
//         asset.safeTransfer(receiver, assets);

//         return assets;
//     }
// }
