/**
 * sweetrust/mandate — public API surface
 *
 * Type-enforced agent capability declaration, with the constitutional
 * pre-check folded in (2026-07-19).
 */

export type {
  Capability,
  CapabilityLimit,
  CapabilityLimits,
  ExternalRef,
  GrantorId,
  ISO8601,
  MandateAuditEvent,
  MandateAuditService,
  MandateError,
  MandateGrantEvent,
  MandateHumanContextEvent,
  MandateId,
  MandateInvocationEvent,
  MandateResumeEvent,
  MandateRevokeEvent,
  MandateScope,
  MandateSettleEvent,
  MandateTier,
  ResumedScope,
  Signed,
  SignedMandateAuditEvent,
  TriggerSource,
  VerifyAuditChainResult,
} from "./types.ts"

export type { GrantedPurpose, Purpose } from "../purpose.ts"

export {
  makeInMemoryAuditLive,
  makeJsonlAuditLive,
  makeInMemorySignedAuditLive,
  makeJsonlSignedAuditLive,
  type SignedMandateAuditService,
} from "./audit.ts"

// Issue, use and revoke live on the client. The free functions in mandate.ts
// are the implementation and stay out of the public surface on purpose: each
// took the audit store as a trailing argument, and that argument was the
// 2026-10-31 audit-swap bypass (client.ts, top comment). Exporting them again
// would reopen it.
export { createTrust, type AuditView, type TrustClient, type TrustConfig } from "./client.ts"

export { capabilityKey, defineCapability, grantorId } from "./mandate.ts"

export {
  makeInMemorySignerLive,
  makeEd25519SignerLive,
  makeEd25519VerifierLive,
  verifyAuditChain,
  publicKeyHexFromPem,
  canonicalJSON,
  sha256Hex,
  signedPreimage,
  MANDATE_AUDIT_DOMAIN,
  type Ed25519SignerConfig,
  type Ed25519VerifierConfig,
  type MandateSignerService,
} from "./signer.ts"

// Folded from a formerly standalone package (2026-07-19): constitutional prompt-injection pre-check.
export { MandateFailure } from "./errors.ts"
export * from "./security.ts"
