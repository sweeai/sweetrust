import { describe, expect, test } from "vitest"
import { Transaction } from "@mysten/sui/transactions"
import {
  createRegistry, openCage, reclaimRevoked, revokeCage, spendFromCage, TESTNET_KERNEL,
} from "../../src/sui/index.ts"

const K = TESTNET_KERNEL
const A = "0x" + "a".repeat(64)
const B = "0x" + "b".repeat(64)
const C = "0x" + "c".repeat(64)
const cage = { coinType: "0x2::sui::SUI", cageId: C, registryId: B }

const calls = (build: (tx: Transaction) => void) => {
  const tx = new Transaction()
  build(tx)
  return tx.getData().commands.flatMap((c) =>
    c.$kind === "MoveCall"
      ? [{ fn: `${c.MoveCall.module}::${c.MoveCall.function}`, pkg: c.MoveCall.package, args: c.MoveCall.arguments.length }]
      : [],
  )
}

describe("sweetrust/sui builders target the deployed swee_kernel", () => {
  test("openCage calls spend_cage::create_and_share with its 11 arguments", () => {
    const c = calls(openCage(K, {
      coinType: "0x2::sui::SUI", delegate: A, funding: 10n, maxPerTx: 5n, maxTotal: 10n,
      expiresAtMs: 1n, allowedRecipients: [B], feeMicroPercent: 0, feeRecipient: A, registryId: B,
    }))
    expect(c).toEqual([{ fn: "spend_cage::create_and_share", pkg: K.kernelPackageId, args: 11 }])
  })

  test("spendFromCage calls the entry withdraw_and_pay_keep with its 6 arguments", () => {
    expect(calls(spendFromCage(K, { ...cage, recipient: A, amount: 1n }))).toEqual([
      { fn: "spend_cage::withdraw_and_pay_keep", pkg: K.kernelPackageId, args: 6 },
    ])
  })

  test("revoke then reclaim compose into one transaction: the kill switch and the refund together", () => {
    expect(calls((tx) => { revokeCage(K, cage)(tx); reclaimRevoked(K, cage)(tx) }).map((c) => c.fn)).toEqual([
      "mandate::revoke", "spend_cage::reclaim_revoked",
    ])
  })

  test("createRegistry calls mandate::create_registry", () => {
    expect(calls(createRegistry(K)).map((c) => c.fn)).toEqual(["mandate::create_registry"])
  })
})

describe("the builders refuse nonsense before it reaches the chain", () => {
  test("a zero or negative spend throws", () => {
    expect(() => calls(spendFromCage(K, { ...cage, recipient: A, amount: 0n }))).toThrow(RangeError)
  })
  test("a fee outside [0, 1_000_000] micro-percent throws", () => {
    expect(() => calls(openCage(K, {
      coinType: "0x2::sui::SUI", delegate: A, funding: 10n, maxPerTx: 5n, maxTotal: 10n,
      expiresAtMs: 1n, allowedRecipients: [B], feeMicroPercent: 1_000_001, feeRecipient: A, registryId: B,
    }))).toThrow(RangeError)
  })
})
