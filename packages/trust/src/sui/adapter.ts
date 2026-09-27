/**
 * SuiChainCage: the ChainCage adapter for Sui, over `swee_kernel::spend_cage`.
 *
 * Refusals come back as results, and a refusal is RECORDED ON-CHAIN. Spends set
 * an explicit gas budget, because the SDK otherwise dry-runs a transaction to
 * estimate gas, and a spend that would abort then fails in the dry run and is
 * never submitted: the refusal would exist only on the caller's machine.
 */
import type { SuiGrpcClient } from "@mysten/sui/grpc"
import type { Signer } from "@mysten/sui/cryptography"
import { Transaction } from "@mysten/sui/transactions"
import type { CagePolicy, CageRefusal, CageSpend, CageSpendResult, ChainCage } from "../cage/index.ts"
import {
  createRegistry, openCage, reclaimRevoked, revokeCage, spendFromCage,
  type CageRef, type KernelConfig,
} from "./builders.ts"
import { TESTNET_KERNEL } from "./deployments.ts"

/** Enough gas for one cage spend; set explicitly so an abort lands on-chain. */
const SPEND_GAS_BUDGET = 20_000_000n

/** `swee_kernel::spend_cage` abort codes (spend_cage.move, the 800 series). */
const SPEND_CAGE_ABORTS: Readonly<Record<number, CageRefusal>> = {
  800: "not-the-agent",
  802: "expired",
  803: "over-per-spend-cap",
  804: "over-total-cap",
  805: "revoked",
  811: "recipient-not-allowed",
  817: "insufficient-funds",
}

interface Executed {
  readonly digest: string
  readonly success: boolean
  readonly abortCode?: number
  readonly abortModule?: string
  readonly error?: string
  readonly created: ReadonlyArray<{ objectId: string; objectType: string }>
}

export interface SuiChainCageOptions {
  readonly client: SuiGrpcClient
  /** Signs open and revoke. Required for those two. */
  readonly owner?: Signer
  /** Signs spends. Required for spend. */
  readonly agent?: Signer
  readonly kernel?: KernelConfig
  readonly coinType?: string
  /** Reuse an existing RevocationRegistry the owner holds; one is created otherwise. */
  readonly registryId?: string
  readonly feeMicroPercent?: number
}

export class SuiChainCage implements ChainCage<CageRef> {
  readonly #client: SuiGrpcClient
  readonly #owner?: Signer
  readonly #agent?: Signer
  readonly #kernel: KernelConfig
  readonly #coinType: string
  readonly #feeMicroPercent: number
  #registryId?: string

  constructor(opts: SuiChainCageOptions) {
    this.#client = opts.client
    this.#owner = opts.owner
    this.#agent = opts.agent
    this.#kernel = opts.kernel ?? TESTNET_KERNEL
    this.#coinType = opts.coinType ?? "0x2::sui::SUI"
    this.#feeMicroPercent = opts.feeMicroPercent ?? 0
    this.#registryId = opts.registryId
  }

  async open(policy: CagePolicy): Promise<CageRef> {
    const owner = this.#need(this.#owner, "owner", "open")
    const ownerAddress = owner.toSuiAddress()
    if (!this.#registryId) {
      const reg = await this.#exec(owner, (tx) => createRegistry(this.#kernel)(tx))
      if (!reg.success) throw new Error(`sweetrust/sui: create_registry failed (${reg.digest}): ${reg.error}`)
      this.#registryId = createdOfType(reg, "::mandate::RevocationRegistry")
    }
    const registryId = this.#registryId
    const made = await this.#exec(owner, (tx) =>
      openCage(this.#kernel, {
        coinType: this.#coinType,
        delegate: policy.agent,
        funding: policy.funding,
        maxPerTx: policy.perSpendMax,
        maxTotal: policy.totalMax,
        expiresAtMs: policy.expiresAtMs,
        allowedRecipients: policy.allowedRecipients,
        feeMicroPercent: this.#feeMicroPercent,
        feeRecipient: ownerAddress,
        registryId,
      })(tx),
    )
    if (!made.success) throw new Error(`sweetrust/sui: create_and_share failed (${made.digest}): ${made.error}`)
    return { coinType: this.#coinType, cageId: createdOfType(made, "::spend_cage::SpendCage<"), registryId }
  }

  async spend(cage: CageRef, spend: CageSpend): Promise<CageSpendResult> {
    const agent = this.#need(this.#agent, "agent", "spend")
    const r = await this.#exec(
      agent,
      (tx) => spendFromCage(this.#kernel, { ...cage, recipient: spend.to, amount: spend.amount, memo: spend.memo })(tx),
      SPEND_GAS_BUDGET,
    )
    if (r.success) return { ok: true, txId: r.digest }
    const fromCage = r.abortModule === "spend_cage" && r.abortCode !== undefined
    return {
      ok: false,
      refusal: (fromCage && SPEND_CAGE_ABORTS[r.abortCode!]) || "other",
      txId: r.digest,
      detail: r.error ?? "failed",
    }
  }

  /** The kill switch, and the refund with it: revoke, then return the remainder, in one transaction. */
  async revoke(cage: CageRef): Promise<void> {
    const owner = this.#need(this.#owner, "owner", "revoke")
    const r = await this.#exec(owner, (tx) => {
      revokeCage(this.#kernel, cage)(tx)
      reclaimRevoked(this.#kernel, cage)(tx)
    })
    if (!r.success) throw new Error(`sweetrust/sui: revoke failed (${r.digest}): ${r.error}`)
  }

  async remaining(cage: CageRef): Promise<bigint> {
    const res = await this.#client.getObject({ objectId: cage.cageId, include: { json: true } })
    const f = (res.object.json ?? {}) as Record<string, unknown>
    const byCap = toBig(f["max_total"]) - toBig(f["total_spent"])
    const inVault = toBig(f["funds"])
    const left = byCap < inVault ? byCap : inVault
    return left > 0n ? left : 0n
  }

  #need(signer: Signer | undefined, role: string, op: string): Signer {
    if (!signer) throw new Error(`sweetrust/sui: ${op} needs the ${role} signer; pass \`${role}\` to SuiChainCage`)
    return signer
  }

  async #exec(signer: Signer, build: (tx: Transaction) => void, gasBudget?: bigint): Promise<Executed> {
    const sender = signer.toSuiAddress()
    const tx = new Transaction()
    tx.setSender(sender)
    build(tx)
    let bytes: Uint8Array
    if (gasBudget === undefined) {
      bytes = await tx.build({ client: this.#client })
    } else {
      // Resolve the commands only (this never fails on an abort), then supply every
      // gas field by hand. With nothing left to resolve, the SDK skips its simulation,
      // so a spend the cage refuses is submitted and the refusal is recorded on-chain.
      const full = Transaction.fromKind(await tx.build({ client: this.#client, onlyTransactionKind: true }))
      full.setSender(sender)
      full.setGasBudget(gasBudget)
      full.setGasPrice(BigInt((await this.#client.getReferenceGasPrice()).referenceGasPrice))
      const coins = (await this.#client.listCoins({ owner: sender, coinType: "0x2::sui::SUI" })).objects
      if (coins.length === 0) throw new Error(`sweetrust/sui: ${sender} has no SUI to pay gas`)
      full.setGasPayment(coins.slice(0, 1).map((c) => ({ objectId: c.objectId, version: c.version, digest: c.digest })))
      bytes = await full.build({ client: this.#client })
    }
    const { signature } = await signer.signTransaction(bytes)
    const res = await this.#client.executeTransaction({
      transaction: bytes,
      signatures: [signature],
      include: { effects: true, objectTypes: true },
    })
    const t = res.$kind === "Transaction" ? res.Transaction : res.FailedTransaction
    // The next transaction from the same signer must build on fresh object versions.
    await this.#client.waitForTransaction({ digest: t.digest }).catch(() => undefined)
    const created = t.effects.changedObjects
      .filter((c) => c.idOperation === "Created")
      .map((c) => ({ objectId: c.objectId, objectType: t.objectTypes[c.objectId] ?? "" }))
    if (t.status.success) return { digest: t.digest, success: true, created }
    const err = t.status.error
    if (err.$kind === "MoveAbort") {
      const code = Number(err.MoveAbort.abortCode)
      return {
        digest: t.digest,
        success: false,
        abortCode: Number.isSafeInteger(code) ? code : undefined,
        abortModule: err.MoveAbort.location?.module ?? undefined,
        error: `MoveAbort ${err.MoveAbort.abortCode} in ${err.MoveAbort.location?.module ?? "?"}${err.message ? `: ${err.message}` : ""}`,
        created,
      }
    }
    return { digest: t.digest, success: false, error: err.message || `${err.$kind} error`, created }
  }
}

function createdOfType(r: Executed, typeFragment: string): string {
  const hit = r.created.find((c) => c.objectType.includes(typeFragment))
  if (!hit) throw new Error(`sweetrust/sui: no ${typeFragment} created in ${r.digest}`)
  return hit.objectId
}

/** Move u64s arrive in JSON as strings; a Balance arrives as a string or as { value }. */
function toBig(v: unknown): bigint {
  if (typeof v === "string" || typeof v === "number" || typeof v === "bigint") return BigInt(v)
  if (v && typeof v === "object" && "value" in v) return toBig((v as { value: unknown }).value)
  throw new Error(`sweetrust/sui: unexpected on-chain field shape: ${JSON.stringify(v)}`)
}
