/**
 * granted — the `GrantedPurpose` a judged sink needs at construction (0.6.0).
 * The suites that are not about the purpose take this one rather than each
 * inventing a grant; its hash names no real grant event, and nothing here
 * verifies one.
 */
import type { GrantedPurpose } from "../../src/purpose.ts"

export const GRANTED: GrantedPurpose = {
  purpose: { statement: "Pay the invoices the owner approved" },
  grantHash: "a".repeat(64),
}
