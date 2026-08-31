/**
 * @sweetrust/gate — public API surface
 *
 * The enforcement kernel of SWEE AI's vertical trust rails: trust-tier
 * provenance (Sourced<T>), the audited declassifier trio, appetite-declaring
 * sinks with the observe→warn→enforce adoption ladder, the judgment seam,
 * and the hash-chained receipt log.
 *
 * Per the trust-types specification v1.1, §4–§5.
 * Dependency-free (node builtins only) — see package.json _notes.
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
  type Tier,
  type UpgradeEvent,
  type Provenance,
  type DeclassifyResult,
  type Receipt,
  type JudgmentVerdict,
  type JudgmentProvider,
  type EnforcementMode,
  type SinkResult,
} from "./trust.ts"
