/**
 * The host-produced `human-context` audit event names no vendor.
 *
 * Until the 2026-10-13 rail audit `MandateHumanContextEvent` carried
 * `linearCommentUrl` and `linearIssueId`, and `TriggerSource` was
 * `"linear" | "code"`. Nothing in this package produced the event or read those
 * fields; the adapter that did was extracted in 2026-07, and the names shipped
 * on in the public declarations. A stranger installing `sweetrust` has no
 * Linear. The event is what a HOST records when a human says something about a
 * mandate in whatever system the host uses, so the shape says that and nothing
 * more: `externalRef: { system, id, url? }` and `triggerSource: "external"`.
 *
 * Every test here was watched RED under `tsc --noEmit` before the type changed:
 * `externalRef` did not exist, `"external"` was not a `TriggerSource`, and the
 * `@ts-expect-error` below was reported unused because `"linear"` still was one.
 */
import { describe, expect, test } from "vitest"
import {
  makeInMemoryAuditLive,
  type ISO8601,
  type MandateAuditEvent,
  type MandateHumanContextEvent,
  type MandateId,
  type TriggerSource,
} from "../../src/mandate/index.ts"

const MANDATE = "m-01HZZZZZZZZZZZZZZZZZZZZZZZ" as MandateId
const NOW = "2026-10-13T00:00:00.000Z" as ISO8601

describe("MandateHumanContextEvent — a host-produced record with no vendor in its shape", () => {
  test("carries externalRef { system, id, url } and triggerSource \"external\", and the log stores it as handed", () => {
    const audit = makeInMemoryAuditLive()
    const event: MandateHumanContextEvent = {
      type: "human-context",
      mandateId: MANDATE,
      externalRef: { system: "issue-tracker", id: "OPS-412", url: "https://tracker.example/OPS-412#c-9" },
      author: "reviewer",
      body: "approved: within the quarter's budget",
      timestamp: NOW,
      triggerSource: "external",
    }
    audit.record(event)
    expect(audit.query(MANDATE)).toEqual([event])
    expect(audit.isRevoked(MANDATE)).toBe(false) // documentation only — it changes no state
  })

  test("url is optional, because not every system has one", () => {
    const event: MandateHumanContextEvent = {
      type: "human-context",
      mandateId: MANDATE,
      externalRef: { system: "email", id: "<20261013.1@mail.example>" },
      author: "ops@example",
      body: "hold this one until the invoice is matched",
      timestamp: NOW,
      triggerSource: "external",
    }
    expect(Object.keys(event.externalRef)).toEqual(["system", "id"])
    // No key on the record or its reference names a product.
    const keys = [...Object.keys(event), ...Object.keys(event.externalRef)]
    expect(keys.filter((k) => /linear/i.test(k))).toEqual([])
  })

  test("the retired vendor literal is not a TriggerSource; the union is \"external\" | \"code\"", () => {
    // @ts-expect-error — "linear" was the 0.3.0 literal. If this directive is ever
    // reported unused, the vendor name is back in the public union.
    const stale: TriggerSource = "linear"
    expect(stale).toBe("linear")
    const sources: ReadonlyArray<TriggerSource> = ["external", "code"]
    expect(sources).toHaveLength(2)
  })

  test("the event is a member of MandateAuditEvent, so a host's exhaustive switch sees it", () => {
    const event: MandateAuditEvent = {
      type: "human-context",
      mandateId: MANDATE,
      externalRef: { system: "chat", id: "C01/p1760313600" },
      author: "lead",
      body: "ok",
      timestamp: NOW,
      triggerSource: "external",
    }
    const kind = ((e: MandateAuditEvent): string => {
      switch (e.type) {
        case "grant": return "grant"
        case "invoke": return "invoke"
        case "revoke": return "revoke"
        case "human-context": return `context from ${e.externalRef.system}`
      }
    })(event)
    expect(kind).toBe("context from chat")
  })
})
