/**
 * A registry row and a candidate must be the gate's own (DAN-1448). `allowlisted`
 * checked its key's brand and tier and then ascended the registry entry with
 * neither check, so a row from parsed JSON or a row born in a channel came back
 * as a genuine `verified` value.
 */
import { describe, expect, it, vi } from "vitest"
import { Sourced, allowlisted, corroborate, humanConfirm } from "../../src/gate/index.ts"
import { poison, readsOf } from "../helpers/poison.ts"

const KEY = "acme"
const RECORD = "ACME-8817"
const hostKey = () => Sourced.fromAuthority(KEY, "purchase-orders")
const claim = () => Sourced.fromLLM(RECORD, "ExtractInvoice", [Sourced.fromChannel("an invoice", "email-inbound")])
const registryOf = (row: unknown) => new Map([[KEY, row as Sourced<string>]])
const refusal = (r: ReturnType<typeof allowlisted<string>>): string => {
  if (r.ok) throw new Error(`expected a refusal, got ${r.value.tier} ${String(r.value.value)}`)
  return r.reason
}

describe("allowlisted promotes only what the gate minted", () => {
  it("a registry row that only looks like a Sourced is refused", () => {
    const forged = { value: RECORD, tier: "verified", provenance: { origin: "authority:payee-registry", ancestors: new Set(), chain: [] }, describe: () => "VERIFIED" }
    const reason = refusal(allowlisted(claim(), registryOf(forged), hostKey(), "payee-registry"))
    expect(reason).toContain("payee-registry")
    expect(reason).not.toContain(RECORD)
  })

  it("a channel-tier registry row is refused and does not ascend", () => {
    for (const row of [Sourced.fromChannel(RECORD, "vendor-onboarding-form"), Sourced.fromLLM(RECORD, "ExtractVendor", [])]) {
      const reason = refusal(allowlisted(claim(), registryOf(row), hostKey(), "payee-registry"))
      expect(reason).toContain("untrusted")
      expect(reason).not.toContain(RECORD)
    }
  })

  it("a corroborated registry row is refused", () => {
    const agreed = corroborate(Sourced.fromChannel(RECORD, "email-inbound"), Sourced.fromChannel(RECORD, "erp-export"))
    if (!agreed.ok) throw new Error("expected the two channels to corroborate")
    const reason = refusal(allowlisted(claim(), registryOf(agreed.value), hostKey(), "payee-registry"))
    expect(reason).toContain("corroborated")
    expect(reason).not.toContain(RECORD)
  })

  it("a proxied registry row is refused before any field is read", () => {
    const proxied = poison(Sourced.fromAuthority(RECORD, "payee-registry"), "row")
    refusal(allowlisted(claim(), registryOf(proxied), hostKey(), "payee-registry"))
    expect(readsOf(proxied).size).toBe(0)
  })

  it("a promoted object row cannot be used to rewrite the registry", async () => {
    const confirmed = await humanConfirm(Sourced.fromChannel({ iban: "GOOD" }, "vendor-onboarding-form"), () => true)
    if (!confirmed.ok) throw new Error(confirmed.reason)
    const registry = new Map([[KEY, confirmed.value]])
    const r = allowlisted(Sourced.fromChannel({ iban: "GOOD" }, "email-inbound"), registry, hostKey(), "payee-registry")
    if (!r.ok) throw new Error(r.reason)
    expect(() => {
      r.value.value.iban = "EVIL"
    }).toThrow(TypeError)
    expect(registry.get(KEY)!.value.iban).toBe("GOOD")
  })

  it("a candidate's toJSON cannot rewrite the row it is compared against", async () => {
    const confirmed = await humanConfirm(Sourced.fromChannel({ iban: "GOOD" }, "vendor-onboarding-form"), () => true)
    if (!confirmed.ok) throw new Error(confirmed.reason)
    const row = confirmed.value
    const candidate = Sourced.fromChannel(
      {
        toJSON() {
          try {
            row.value.iban = "EVIL"
          } catch {
            // Frozen, which is the point.
          }
          return { iban: "GOOD" }
        },
      } as unknown as { iban: string },
      "email-inbound",
    )
    const r = allowlisted(candidate, new Map([[KEY, row]]), hostKey(), "payee-registry")
    if (!r.ok) throw new Error(r.reason)
    expect(r.value.value.iban).toBe("GOOD")
  })

  it("a row is frozen by the lookup, even when the candidate does not match", async () => {
    const confirmed = await humanConfirm(Sourced.fromChannel({ iban: "GOOD" }, "vendor-onboarding-form"), () => true)
    if (!confirmed.ok) throw new Error(confirmed.reason)
    expect(allowlisted(Sourced.fromChannel({ iban: "OTHER" }, "email-inbound"), new Map([[KEY, confirmed.value]]), hostKey(), "payee-registry").ok).toBe(false)
    expect(Object.isFrozen(confirmed.value.value)).toBe(true)
  })

  it("a candidate that only looks like a Sourced is refused without calling it", () => {
    const describeIt = vi.fn(() => "VERIFIED (origin: authority:erp)")
    let reads = 0
    const forged = {
      get value() {
        reads += 1
        return RECORD
      },
      describe: describeIt,
    }
    const registry = registryOf(Sourced.fromAuthority(RECORD, "payee-registry"))
    const get = vi.spyOn(registry, "get")
    const reason = refusal(allowlisted(forged as unknown as Sourced<string>, registry, hostKey(), "payee-registry"))
    expect(reason).toContain("payee-registry")
    expect(describeIt).not.toHaveBeenCalled()
    expect(reads).toBe(0)
    expect(get).not.toHaveBeenCalled()
  })

  it("a proxied candidate is refused before any field is read", () => {
    const proxied = poison(claim(), "candidate")
    refusal(allowlisted(proxied, registryOf(Sourced.fromAuthority(RECORD, "payee-registry")), hostKey(), "payee-registry"))
    expect(readsOf(proxied).size).toBe(0)
  })

  it("a verified row and a genuine candidate still promote the record", () => {
    const row = Sourced.fromAuthority(RECORD, "payee-registry")
    const r = allowlisted(claim(), registryOf(row), hostKey(), "payee-registry")
    if (!r.ok) throw new Error(r.reason)
    expect(r.value.tier).toBe("verified")
    expect(r.value.value).toBe(RECORD)
    expect(r.value.provenance.origin).toBe("authority:payee-registry")
    expect(r.value.provenance.chain[0]!.from).toBe("verified")
  })

  it("a row raised to verified through a declassifier is a verified row", async () => {
    const confirmed = await humanConfirm(Sourced.fromChannel(RECORD, "vendor-onboarding-form"), () => true)
    if (!confirmed.ok) throw new Error(confirmed.reason)
    expect(allowlisted(claim(), registryOf(confirmed.value), hostKey(), "payee-registry").ok).toBe(true)
  })
})
