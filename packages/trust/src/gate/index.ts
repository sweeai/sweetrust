/**
 * sweetrust/gate — public API surface
 *
 * The enforcement kernel of SWEE AI's vertical trust rails: trust-tier
 * provenance (Sourced<T>), the three declassifiers, appetite-declaring
 * sinks with the observe→warn→enforce adoption ladder, the judgment seam,
 * and the hash-chained receipt log.
 *
 * Dependency-free (node builtins only).
 */

export {
  TIERS,
  meetsTier,
  minTier,
  Sourced,
  allowlisted,
  corroborate,
  humanConfirm,
  ReceiptLog,
  receiptBody,
  makeSink,
  mockJudgmentProvider,
  encodeAction,
  actionDigest,
  paymentDigest,
  verdictDigest,
  purposeHash,
  SpendAuthorization,
  type SpendAuthorizationResult,
  type SinkCallOptions,
  type Tier,
  type UpgradeEvent,
  type Provenance,
  type DeclassifyResult,
  type Receipt,
  type JudgmentVerdict,
  type JudgmentProvider,
  type EnforcementMode,
  type SinkResult,
  type Action,
  type Payment,
  type Verdict,
  type Approval,
  type HeldAction,
  type AuthorizedBy,
} from "./trust.ts"
export type { GrantedPurpose, Purpose } from "../purpose.ts"
