// Receipt["decision"] is semver-permanent (DAN-1159 item 4b). tsc is the runner.
// ============================================================================
// Once published, adding a member to this union breaks every consumer's
// exhaustive switch. So this file pins the union EXACTLY: the switch must name
// every member (the `never` default stops compiling if one is missing), and
// every case must be a member (a case that is not one fails as "not comparable").
// If this file goes red because someone added a decision, that is a breaking
// change announcing itself, not a flaky test.
//
// "declassify-refused" is reserved before the first publish for the refusal a
// declassifier should leave as evidence. Today a refused declassifier records
// nothing: only sink decisions reach the chain (SECURITY.md). Reserving the
// member is the irreversible half. Emitting it, through an optional log on the
// declassifiers, is additive and can follow without a major version.
// ============================================================================

import { describe, expect, it } from "vitest"
import type { Receipt } from "../../src/gate/index.ts"

const label = (decision: Receipt["decision"]): string => {
  switch (decision) {
    case "executed": return "the action ran"
    case "refused": return "a sink refused an under-tier argument"
    case "observed": return "observe mode: the violation was recorded, not enforced"
    case "warned": return "warn mode: the violation was recorded and surfaced"
    case "judgment-blocked": return "the judgment wall blocked an in-bounds action"
    case "judgment-flagged": return "the judgment wall allowed it, with its doubt on the receipt"
    case "errored": return "execute() threw after the checks passed"
    case "declassify-refused": return "a declassifier refused to raise a value"
    default: {
      const unreachable: never = decision
      return unreachable
    }
  }
}

describe("Receipt decision union (DAN-1159 item 4b)", () => {
  it("the switch above names every decision and only decisions (tsc asserts it; this proves the file ran)", () => {
    expect(label("executed")).toBe("the action ran")
  })
})
