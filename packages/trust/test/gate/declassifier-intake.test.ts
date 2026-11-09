/**
 * All three declassifiers refuse a `Sourced` the gate did not mint, and what
 * `humanConfirm` and `allowlisted` promote cannot be rewritten afterward (DAN-1451). `corroborate` minted a branded
 * value from a forged claim, `humanConfirm` showed a person a forgery's own
 * `describe()`, a confirmed value stayed writable after the yes, and a nested
 * registry row could be rewritten through the result or by a candidate's `toJSON`.
 */
import { describe, expect, it, vi } from "vitest"
import { ReceiptLog, Sourced, allowlisted, corroborate, humanConfirm } from "../../src/gate/index.ts"
import { poison, readsOf } from "../helpers/poison.ts"

/** Looks like a Sourced and records every field or method anything touches on it. */
const forgery = () => {
  const touched: string[] = []
  const shape = {
    value: "ACME",
    tier: "untrusted",
    provenance: { origin: "authority:payee-registry", ancestors: new Set<string>(), chain: [] },
    describe: () => "VERIFIED (origin: authority:payee-registry)",
  }
  const forged = new Proxy(shape, {
    get(target, key, receiver) {
      touched.push(String(key))
      return Reflect.get(target, key, receiver)
    },
  }) as unknown as Sourced<string>
  return { forged, touched }
}
const channel = <T>(value: T, name = "email-inbound") => Sourced.fromChannel(value, name)
const hostKey = () => Sourced.fromAuthority("acme", "purchase-orders")
const registryOf = <T>(row: Sourced<T>) => new Map([["acme", row]])
const refusal = (r: { ok: true } | { ok: false; reason: string }): string => {
  if (r.ok) throw new Error("expected a refusal")
  return r.reason
}
const nestedRow = () => ({ bank: { iban: "GOOD" } })

describe("humanConfirm and corroborate take only what the gate minted", () => {
  it("humanConfirm refuses a forged candidate without asking anyone", async () => {
    const { forged, touched } = forgery()
    const render = vi.fn(() => true)
    expect(refusal(await humanConfirm(forged, render))).toContain("not minted by the gate")
    expect(render).not.toHaveBeenCalled()
    expect(touched).toEqual([])
  })

  it("humanConfirm refuses a proxied candidate before any field is read", async () => {
    const proxied = poison(channel("ACME"), "candidate")
    const render = vi.fn(() => true)
    refusal(await humanConfirm(proxied, render))
    expect(render).not.toHaveBeenCalled()
    expect(readsOf(proxied).size).toBe(0)
  })

  it("corroborate refuses a forged claim without reading it", () => {
    const { forged, touched } = forgery()
    const equals = vi.fn(() => true)
    expect(refusal(corroborate(forged, channel("ACME", "erp-export"), equals))).toContain("claim")
    expect(equals).not.toHaveBeenCalled()
    expect(touched).toEqual([])
  })

  it("corroborate refuses a forged reference without reading it", () => {
    const { forged, touched } = forgery()
    const equals = vi.fn(() => true)
    expect(refusal(corroborate(channel("ACME"), forged, equals))).toContain("reference")
    expect(equals).not.toHaveBeenCalled()
    expect(touched).toEqual([])
  })

  it("a proxied claim and reference are refused before any field is read", () => {
    const claim = poison(channel("ACME"), "claim")
    const reference = poison(channel("ACME", "erp-export"), "reference")
    refusal(corroborate(claim, channel("ACME", "erp-export")))
    refusal(corroborate(channel("ACME"), reference))
    expect(readsOf(claim).size).toBe(0)
    expect(readsOf(reference).size).toBe(0)
  })

  it("genuine input still corroborates and still confirms", async () => {
    const agreed = corroborate(channel("ACME"), channel("ACME", "erp-export"))
    expect(agreed.ok && agreed.value.tier).toBe("corroborated")
    const confirmed = await humanConfirm(channel("ACME"), () => true)
    expect(confirmed.ok && confirmed.value.tier).toBe("verified")
  })
})

describe("what a declassifier promotes cannot be rewritten, at any depth", () => {
  it("a confirmed value cannot be rewritten after the yes", async () => {
    const r = await humanConfirm(channel(nestedRow()), () => true)
    if (!r.ok) throw new Error(r.reason)
    expect(() => {
      r.value.value.bank.iban = "EVIL"
    }).toThrow(TypeError)
    expect(() => {
      r.value.value.bank = { iban: "EVIL" }
    }).toThrow(TypeError)
    expect(r.value.value.bank.iban).toBe("GOOD")
  })

  it("a nested registry row cannot be rewritten through the result", () => {
    const registry = registryOf(Sourced.fromAuthority(nestedRow(), "payee-registry"))
    const r = allowlisted(channel(nestedRow()), registry, hostKey(), "payee-registry")
    if (!r.ok) throw new Error(r.reason)
    expect(() => {
      r.value.value.bank.iban = "EVIL"
    }).toThrow(TypeError)
    expect(registry.get("acme")!.value.bank.iban).toBe("GOOD")
  })

  it("a candidate's toJSON cannot rewrite a nested row", () => {
    const row = nestedRow()
    const hostile = {
      toJSON() {
        try {
          row.bank.iban = "EVIL"
        } catch {
          // Frozen: the write is what this test is about, not the error.
        }
        return nestedRow()
      },
    }
    const r = allowlisted(channel(hostile as unknown as typeof row), registryOf(Sourced.fromAuthority(row, "payee-registry")), hostKey(), "payee-registry")
    if (!r.ok) throw new Error(r.reason)
    expect(r.value.value.bank.iban).toBe("GOOD")
    expect(row.bank.iban).toBe("GOOD")
  })

  it("a cyclic row is still refused as unserializable", () => {
    const row: Record<string, unknown> = {}
    row.self = row
    const reason = refusal(allowlisted(channel({}), registryOf(Sourced.fromAuthority(row, "payee-registry")), hostKey(), "payee-registry"))
    expect(reason).toContain("could not be serialized")
  })

  it("a typed array inside a row or a confirmed value does not stop the promotion", async () => {
    const withBytes = () => ({ bytes: new Uint8Array([1, 2]) })
    const r = allowlisted(channel(withBytes()), registryOf(Sourced.fromAuthority(withBytes(), "payee-registry")), hostKey(), "payee-registry")
    expect(r.ok).toBe(true)
    const confirmed = await humanConfirm(channel(withBytes()), () => true)
    expect(confirmed.ok).toBe(true)
  })

  it("a nested object under a symbol or hidden key is frozen too", () => {
    const hidden = Symbol("hidden")
    const row = nestedRow() as ReturnType<typeof nestedRow> & { [hidden]?: { n: number }; secret?: { n: number } }
    row[hidden] = { n: 1 }
    Object.defineProperty(row, "secret", { value: { n: 1 }, enumerable: false })
    const r = allowlisted(channel(nestedRow()), registryOf(Sourced.fromAuthority(row, "payee-registry")), hostKey(), "payee-registry")
    if (!r.ok) throw new Error(r.reason)
    expect(Object.isFrozen(row[hidden])).toBe(true)
    expect(Object.isFrozen(row.secret)).toBe(true)
  })

  it("the freeze walk does not run a getter on a row", () => {
    const getter = vi.fn(() => ({ n: 1 }))
    const row = {}
    Object.defineProperty(row, "live", { get: getter, enumerable: true })
    allowlisted(channel({}), registryOf(Sourced.fromAuthority(row, "payee-registry")), hostKey(), "payee-registry")
    // Once, by the comparison's own serialization. The walk must not add a read.
    expect(getter).toHaveBeenCalledTimes(1)
  })
})

describe("the receipt log's freeze is unchanged", () => {
  it("a receipt holding a typed array is still refused at append", () => {
    const log = new ReceiptLog()
    expect(() => log.append({ at: "2026-11-09T00:00:00Z", sink: "pay", decision: "refused", args: { x: { value: new Uint8Array([1]), tier: "verified", provenance: "owner" } } as never, reason: "r" })).toThrow()
    expect(log.all()).toHaveLength(0)
  })
})
