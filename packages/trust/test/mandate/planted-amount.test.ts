/**
 * A malformed amount in the log fails closed (the DAN-1410 review, 2026-11-08).
 * A negative or non-numeric invoke on an unsigned store used to lower or poison the sum.
 */
import { appendFileSync, mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, expect, it } from "vitest"
import { createTrust, defineCapability, grantorId, makeJsonlAuditLive, MandateFailure } from "../../src/mandate/index.ts"

const Buy = defineCapability("x.buy")
const OWNER = grantorId("owner")

const setup = () => {
  const file = join(mkdtempSync(join(tmpdir(), "sweetrust-planted-")), "audit.jsonl")
  const trust = createTrust({ store: makeJsonlAuditLive(file) })
  const org = trust.issueOrgMandate({ grantor: OWNER, capabilities: [Buy] as const, rationale: "root" })
  const project = trust.issueProjectMandate({ grantor: OWNER, grantorScope: org, capabilities: [Buy] as const, rationale: "p" })
  const agent = trust.issueAgentMandate({
    grantor: OWNER, grantorScope: project, capabilities: [Buy] as const, rationale: "a",
    limits: { "x.buy": { amount: 100, unit: "USD" } },
  })
  trust.useCapability({ mandate: agent, capability: Buy, amount: 90 })
  const buy = (amount: number) => {
    try {
      trust.useCapability({ mandate: agent, capability: Buy, amount })
      return "allowed"
    } catch (e) {
      return MandateFailure.is(e) ? e._tag : "threw"
    }
  }
  const plant = (rawAmount: string) => {
    const last = readFileSync(file, "utf-8").trim().split("\n").pop()!
    appendFileSync(file, last.replace('"amount":90', `"amount":${rawAmount}`) + "\n")
  }
  return { buy, plant }
}

describe("a malformed amount in the log refuses the next spend", () => {
  it.each([["negative", "-999"], ["overflowing to Infinity", "1e999"], ["a string", '"5"'], ["null", "null"]])("%s", (_label, raw) => {
    const { buy, plant } = setup()
    plant(raw)
    expect(buy(50)).toBe("MandateLimitExceeded")
  })

  it("CONTROL: an honest log still allows what fits", () => {
    expect(setup().buy(10)).toBe("allowed")
  })
})
