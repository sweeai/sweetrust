/**
 * ChainCage — the chain-agnostic shape of an on-chain spending cage.
 *
 * A cage holds an agent's budget on a chain and lets money leave only within
 * limits the chain itself enforces: a per-spend cap, a lifetime cap, an expiry
 * and a list of approved payees. It bounds a compromised agent key to those
 * limits. It does not make theft impossible: the key can still spend up to the
 * caps, to an approved payee.
 *
 * Types only, no runtime code and no chain names. Adapters implement it:
 * `sweetrust/sui` is the first and only one.
 */

/** The limits a cage is opened with. Amounts are in the coin's base units. */
export interface CagePolicy {
  /** The address allowed to spend from the cage (the agent). */
  readonly agent: string
  /** Money moved INTO the cage at open. The agent never holds it. */
  readonly funding: bigint
  /** Ceiling for a single spend. */
  readonly perSpendMax: bigint
  /** Ceiling over the cage's whole life. "Today's cap" is a cage that expires in a day. */
  readonly totalMax: bigint
  /** When the cage stops allowing spends (ms since epoch). */
  readonly expiresAtMs: bigint
  /** The only addresses the agent may pay. */
  readonly allowedRecipients: readonly string[]
}

export interface CageSpend {
  readonly to: string
  readonly amount: bigint
  readonly memo?: string
}

/**
 * Why a cage refused a spend. A refusal is a RESULT, never a throw: it is the
 * cage working. Transport and signing failures still throw.
 */
export type CageRefusal =
  | "over-total-cap"
  | "over-per-spend-cap"
  | "recipient-not-allowed"
  | "revoked"
  | "expired"
  | "insufficient-funds"
  | "not-the-agent"
  | "other"

export type CageSpendResult =
  | { readonly ok: true; readonly txId: string }
  /** `txId` is present when the refusal happened ON-CHAIN and is recorded there. */
  | { readonly ok: false; readonly refusal: CageRefusal; readonly txId?: string; readonly detail: string }

/**
 * `Cage` is the adapter's own handle for an opened cage (ids, coin type, and
 * so on). Opening and revoking act as the owner; spending acts as the agent.
 */
export interface ChainCage<Cage> {
  open(policy: CagePolicy): Promise<Cage>
  spend(cage: Cage, spend: CageSpend): Promise<CageSpendResult>
  revoke(cage: Cage): Promise<void>
  /** How much the agent may still spend, as the chain reports it. */
  remaining(cage: Cage): Promise<bigint>
}
