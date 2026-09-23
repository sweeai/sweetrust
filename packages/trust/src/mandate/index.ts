/**
 * @sweetrust/mandate — public API surface
 *
 * v0.0 — type-enforced agent capability declaration with constitutional
 * pre-check inheritance from EM-2 / security-hardened-judge.allium.
 *
 * Per the mandate capability-declaration specification v0.0.
 */

export type {
  Capability,
  GrantorId,
  ISO8601,
  MandateAuditEvent,
  MandateAuditService,
  MandateError,
  MandateGrantEvent,
  MandateHumanContextEvent,
  MandateId,
  MandateInvocationEvent,
  MandateRevokeEvent,
  MandateScope,
  MandateTier,
  Signed,
  SignedMandateAuditEvent,
  TriggerSource,
  VerifyAuditChainResult,
} from "./types.ts"

export {
  makeInMemoryAuditLive,
  makeJsonlAuditLive,
  makeInMemorySignedAuditLive,
  makeJsonlSignedAuditLive,
  type SignedMandateAuditService,
} from "./audit.ts"

export {
  issueMandate,
  issueRootMandate,
  issueOrgMandate,
  issueProjectMandate,
  issueAgentMandate,
  revokeMandate,
  useCapability,
  capabilityKey,
  defineCapability,
} from "./mandate.ts"

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
