/**
 * A stand-in for a Sui fullnode, at the `client.core` seam the adapter talks to.
 *
 * It serves what the SDK's generic resolver asks for while building (object
 * references, gas price, gas coins) and what the adapter reads afterwards (the
 * allowance's BCS content, the clock), and it returns scripted execution
 * results. It refuses to simulate: the adapter must never simulate, because a
 * simulated refusal leaves no digest.
 */
import type { ClientWithCoreApi } from "@mysten/sui/client"
import { Transaction } from "@mysten/sui/transactions"
import { normalizeSuiAddress } from "@mysten/sui/utils"
import { encodeAllowance, encodeClock, type AllowanceState } from "../../src/allowance-move.ts"

export const DIGEST = (n: number): string =>
  // Real base58 32-byte digests (any valid one serializes); the suffix keeps them distinct in assertions.
  ["6BrnPQbLBLF864PuGvXJhjuqYHMiv12iKBpgtMwCQ4Kv", "BsoVKz4XUcau1HjHjPiM2bQyQ3Nchbm4W8jNBLchktHg",
    "2SYSrkFnaLtr2y4h4jujzMWZs9ietZKYc6EdSGWSpkGQ", "5f16mfCinZSEWAUff5T4vjn68pT76bUCB4LLfbN29BNE"][n % 4]

export const ALLOWANCE_ID = normalizeSuiAddress("0xa110")
export const CAP_ID = normalizeSuiAddress("0xca9")
const COIN_ID = normalizeSuiAddress("0xc017")

export type Scripted =
  | { kind: "executed"; digest: string; timestampMs: number; after?: AllowanceState | null; created?: boolean }
  | { kind: "abort"; digest: string; timestampMs: number; abortName: string; errorCode: number; message?: string }
  | { kind: "failed"; digest: string; timestampMs: number; error: Record<string, unknown> }
  | { kind: "throw"; message: string; after?: AllowanceState | null }

export interface MockChain {
  readonly client: ClientWithCoreApi
  /** The allowance as the fullnode serves it; null = deleted. */
  state: AllowanceState | null
  clockMs: bigint
  readonly script: Array<Scripted>
  readonly executed: Array<{ bytes: Uint8Array; sender: string }>
  readonly simulated: Array<unknown>
}

export function mockChain(initial: AllowanceState | null, clockMs: bigint): MockChain {
  const chain: MockChain = { client: undefined as unknown as ClientWithCoreApi, state: initial, clockMs, script: [], executed: [], simulated: [] }
  const txTime = new Map<string, number>()

  const objectFor = (id: string): Record<string, unknown> | Error => {
    const nid = normalizeSuiAddress(id)
    if (nid === normalizeSuiAddress("0x6")) {
      return { objectId: nid, version: "1", digest: DIGEST(0), owner: { $kind: "Shared", Shared: { initialSharedVersion: "1" } }, type: "0x2::clock::Clock", content: encodeClock(chain.clockMs) }
    }
    if (nid === ALLOWANCE_ID && chain.state !== null) {
      return { objectId: nid, version: "10", digest: DIGEST(1), owner: { $kind: "Shared", Shared: { initialSharedVersion: "5" } }, type: "0x2::allowance::Allowance<0x2::balance::Balance<0x2::sui::SUI>>", content: encodeAllowance(chain.state) }
    }
    if (nid === CAP_ID) {
      return { objectId: nid, version: "9", digest: DIGEST(2), owner: { $kind: "AddressOwner", AddressOwner: normalizeSuiAddress("0x1") }, type: "0x2::allowance::AllowanceCap<0x2::balance::Balance<0x2::sui::SUI>>", content: new Uint8Array() }
    }
    return new Error(`Object ${nid} not found`)
  }

  const core = {
    getObjects: async ({ objectIds }: { objectIds: Array<string> }) => ({ objects: objectIds.map(objectFor) }),
    getCurrentSystemState: async () => ({ systemState: { referenceGasPrice: "1000", epoch: "900" } }),
    getChainIdentifier: async () => ({ chainIdentifier: DIGEST(3) }),
    getBalance: async () => ({ balance: { coinType: "0x2::sui::SUI", balance: "100000000", coinBalance: "100000000", addressBalance: "0" } }),
    listCoins: async () => ({ objects: [{ objectId: COIN_ID, version: "7", digest: DIGEST(1), balance: "100000000", coinType: "0x2::sui::SUI" }], hasNextPage: false, cursor: null }),
    simulateTransaction: async (o: unknown) => {
      chain.simulated.push(o)
      throw new Error("mock-chain: the adapter simulated a transaction; it must execute it instead")
    },
    // Like the gRPC and GraphQL transports, this mock HAS its own resolver, and
    // using it is the bug: those simulate and throw on an abort, so a refused
    // spend would never get a digest. The adapter must build without it.
    resolveTransactionPlugin: () => async () => {
      throw new Error("mock-chain: the transport's resolver was used; it simulates and would swallow a refusal's digest")
    },
    getMoveFunction: async () => {
      throw new Error("mock-chain: the build asked for a function signature; inputs should state their mutability")
    },
    signAndExecuteTransaction: async ({ transaction }: { transaction: Uint8Array | Transaction }) => {
      if (!(transaction instanceof Uint8Array)) throw new Error("mock-chain: expected built bytes, got an unbuilt Transaction (it would be re-resolved by the transport)")
      const sender = Transaction.from(transaction).getData().sender ?? ""
      chain.executed.push({ bytes: transaction, sender })
      const next = chain.script.shift()
      if (next === undefined) throw new Error("mock-chain: no scripted result left")
      if (next.kind === "throw") {
        if (next.after !== undefined) chain.state = next.after
        throw new Error(next.message)
      }
      txTime.set(next.digest, next.timestampMs)
      const base = { digest: next.digest, signatures: [], epoch: "900", timestampMs: null, checkpoint: null, balanceChanges: undefined, events: undefined, transaction: undefined, bcs: undefined }
      if (next.kind === "executed") {
        if (next.after !== undefined) chain.state = next.after
        const effects = next.created
          ? { changedObjects: [
              { objectId: ALLOWANCE_ID, idOperation: "Created", outputOwner: { $kind: "Shared" } },
              { objectId: CAP_ID, idOperation: "Created", outputOwner: { $kind: "AddressOwner" } },
            ] }
          : { changedObjects: [] }
        const objectTypes = next.created
          ? { [ALLOWANCE_ID]: "0x2::allowance::Allowance<0x2::balance::Balance<0x2::sui::SUI>>", [CAP_ID]: "0x2::allowance::AllowanceCap<0x2::balance::Balance<0x2::sui::SUI>>" }
          : {}
        return { $kind: "Transaction", Transaction: { ...base, status: { success: true, error: null }, effects, objectTypes } }
      }
      const error = next.kind === "abort"
        ? {
            $kind: "MoveAbort",
            message: next.message ?? `MoveAbort in 1st command, '${next.abortName}'`,
            MoveAbort: {
              abortCode: "13836185853565075465",
              location: { package: "0x0000000000000000000000000000000000000000000000000000000000000002", module: "allowance", functionName: "consume" },
              cleverError: { constantName: next.abortName, errorCode: next.errorCode },
            },
          }
        : next.error
      return { $kind: "FailedTransaction", FailedTransaction: { ...base, status: { success: false, error }, effects: { changedObjects: [] }, objectTypes: {} } }
    },
    waitForTransaction: async ({ digest }: { digest: string }) => ({
      $kind: "Transaction",
      Transaction: { digest, timestampMs: txTime.get(digest) ?? null, status: { success: true, error: null } },
    }),
  }
  ;(chain as { client: ClientWithCoreApi }).client = { core } as unknown as ClientWithCoreApi
  return chain
}

/** A blank allowance state for tests to spread over. */
export function allowanceState(over: Partial<AllowanceState> & Pick<AllowanceState, "funder" | "spender">): AllowanceState {
  return {
    id: ALLOWANCE_ID,
    app: null,
    lifetimeCap: null,
    startMs: null,
    expiryMs: null,
    rate: null,
    name: "test",
    currentSpend: 0n,
    ...over,
  }
}

/** The Move call targets in built transaction bytes. */
export function targetsOf(bytes: Uint8Array): Array<string> {
  return Transaction.from(bytes).getData().commands.flatMap((c) =>
    c.MoveCall ? [`${normalizeSuiAddress(c.MoveCall.package)}::${c.MoveCall.module}::${c.MoveCall.function}`.replace(/^0x0+(\d)::/, "0x$1::")] : c.TransferObjects ? ["TransferObjects"] : [])
}
