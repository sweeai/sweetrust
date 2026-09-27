/**
 * Transaction builders for the on-chain spend cage (`swee_kernel::spend_cage`)
 * and its kill switch (`swee_kernel::mandate` RevocationRegistry).
 *
 * Moved 2026-09-26 from the retired `a-retired-package` package (sweeai/monorepo
 * `a-retired-package` and `transactions/mandate.ts`,
 * main @ 5c18bde). History stays in that repo; a cross-repo move cannot carry it.
 *
 * Each builder returns `(tx) => void`, so callers compose several into one
 * transaction (for example revoke + reclaim, the kill switch plus the refund).
 */
import { coinWithBalance, type Transaction } from "@mysten/sui/transactions"

export const SUI_CLOCK = "0x6"

export interface KernelConfig {
  /** The swee_kernel package id (mandate, spend_cage, admin). */
  readonly kernelPackageId: string
  /** The kernel's shared ProtocolState (the pause guard on create/deposit). */
  readonly protocolStateId: string
}

export interface OpenCageParams {
  readonly coinType: string
  readonly delegate: string
  readonly funding: bigint
  readonly maxPerTx: bigint
  readonly maxTotal: bigint
  readonly expiresAtMs: bigint
  readonly allowedRecipients: readonly string[]
  /** Micro-percent (1_000_000 = 100%). 0 for no fee. */
  readonly feeMicroPercent: number
  readonly feeRecipient: string
  /** The RevocationRegistry the cage is bound to. The delegator must own it. */
  readonly registryId: string
}

export interface CageSpendParams {
  readonly coinType: string
  readonly cageId: string
  readonly registryId: string
  readonly recipient: string
  readonly amount: bigint
  readonly memo?: string
}

export interface CageRef {
  readonly coinType: string
  readonly cageId: string
  readonly registryId: string
}

function assertPositive(value: bigint, name: string, where: string): void {
  if (value <= 0n) throw new RangeError(`${where}: ${name} must be > 0, got ${value}`)
}

function assertFeeMicroPercent(fee: number, where: string): void {
  if (!Number.isInteger(fee) || fee < 0 || fee > 1_000_000) {
    throw new RangeError(`${where}: feeMicroPercent must be an integer in [0, 1_000_000], got ${fee}`)
  }
}

/** Creates the shared RevocationRegistry that a cage is bound to. */
export const createRegistry = (config: KernelConfig) => (tx: Transaction): void => {
  tx.moveCall({ target: `${config.kernelPackageId}::mandate::create_registry`, arguments: [] })
}

/** The delegator funds and shares a custody cage. The funding moves INTO the cage. */
export const openCage = (config: KernelConfig, p: OpenCageParams) => (tx: Transaction): void => {
  assertFeeMicroPercent(p.feeMicroPercent, "openCage")
  assertPositive(p.funding, "funding", "openCage")
  if (p.allowedRecipients.includes(p.delegate)) {
    // Allowlisting the agent's own address lets a compromised agent pay itself
    // up to the caps. Legitimate only for a delegator-controlled address.
    console.warn("[sweetrust/sui] the cage's agent is on its own allowlist; it could pay itself up to the caps")
  }
  tx.moveCall({
    target: `${config.kernelPackageId}::spend_cage::create_and_share`,
    typeArguments: [p.coinType],
    arguments: [
      tx.pure.address(p.delegate),
      coinWithBalance({ type: p.coinType, balance: p.funding }),
      tx.pure.u64(p.maxPerTx),
      tx.pure.u64(p.maxTotal),
      tx.pure.u64(p.expiresAtMs),
      tx.pure.vector("address", [...p.allowedRecipients]),
      tx.pure.u64(p.feeMicroPercent),
      tx.pure.address(p.feeRecipient),
      tx.object(p.registryId),
      tx.object(config.protocolStateId),
      tx.object(SUI_CLOCK),
    ],
  })
}

/** The agent's spend: validate, withdraw from custody and pay, atomically. */
export const spendFromCage = (config: KernelConfig, p: CageSpendParams) => (tx: Transaction): void => {
  assertPositive(p.amount, "amount", "spendFromCage")
  const memo = new TextEncoder().encode(p.memo ?? "")
  tx.moveCall({
    target: `${config.kernelPackageId}::spend_cage::withdraw_and_pay_keep`,
    typeArguments: [p.coinType],
    arguments: [
      tx.object(p.cageId),
      tx.object(p.registryId),
      tx.pure.address(p.recipient),
      tx.pure.u64(p.amount),
      tx.pure.vector("u8", Array.from(memo)),
      tx.object(SUI_CLOCK),
    ],
  })
}

/** The kill switch: revoke the cage in its registry (the cage id is the revocation key). */
export const revokeCage = (config: KernelConfig, c: CageRef) => (tx: Transaction): void => {
  tx.moveCall({
    target: `${config.kernelPackageId}::mandate::revoke`,
    typeArguments: [c.coinType],
    arguments: [tx.object(c.registryId), tx.pure.id(c.cageId)],
  })
}

/** After a revoke: the remainder returns to the delegator and the cage is consumed. */
export const reclaimRevoked = (config: KernelConfig, c: CageRef) => (tx: Transaction): void => {
  tx.moveCall({
    target: `${config.kernelPackageId}::spend_cage::reclaim_revoked`,
    typeArguments: [c.coinType],
    arguments: [tx.object(c.cageId), tx.object(c.registryId), tx.object(SUI_CLOCK)],
  })
}
