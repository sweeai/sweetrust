/**
 * sweetrust/sui — the ChainCage adapter for Sui.
 *
 * The only part of sweetrust that imports `@mysten/sui` (an optional peer
 * dependency). Nothing under mandate, gate or verify may import this file;
 * the build fails if their output reaches `@mysten/sui`.
 */
export { SuiChainCage, type SuiChainCageOptions } from "./adapter.ts"
export {
  createRegistry, openCage, spendFromCage, revokeCage, reclaimRevoked, SUI_CLOCK,
  type KernelConfig, type OpenCageParams, type CageSpendParams, type CageRef,
} from "./builders.ts"
export { TESTNET_KERNEL, TESTNET_FULLNODE } from "./deployments.ts"
export type { CagePolicy, CageSpend, CageSpendResult, CageRefusal, ChainCage } from "../cage/index.ts"
