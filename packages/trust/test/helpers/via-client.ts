/**
 * via-client — the pre-0.5.0 call shape, routed through the shipped door.
 *
 * Until 0.5.0 the mandate entry points were free functions taking the audit
 * store as a trailing argument, and that argument was the hole (2026-10-31:
 * a caller-supplied store with one forged grant line was obeyed). The public
 * API is now `createTrust({ store })` with the same verbs as methods.
 *
 * The suites that pin the kernel's security properties were written against
 * the old shape, with the store named at every call. This helper keeps each
 * call site readable and sends EVERY call through `createTrust`, so the
 * assertions exercise the door consumers actually get. It can do that because
 * a scope is bound to its STORE, not to a client object: two clients over one
 * store agree (test/mandate/audit-bound-client.test.ts, case c), so a client
 * per call is exactly equivalent to one client held for the whole test.
 *
 * The generic signatures are copied from the client on purpose: the
 * `@ts-expect-error` compile-time proofs in test/mandate/mandate.test.ts must
 * keep failing to compile, and a loosened shim would silently turn them into
 * "unused directive" errors.
 */
import { createTrust, type TrustClient } from "../../src/mandate/client.ts"
import type { Capability, MandateAuditService, MandateScope, MandateTier } from "../../src/mandate/types.ts"

export { capabilityKey, defineCapability } from "../../src/mandate/mandate.ts"

export const issueOrgMandate = <Caps extends ReadonlyArray<Capability>>(
  args: Parameters<TrustClient["issueOrgMandate"]>[0] & { readonly capabilities: Caps },
  audit: MandateAuditService,
): MandateScope<Caps, "organization", null> => createTrust({ store: audit }).issueOrgMandate(args)

export const issueProjectMandate = <
  OrgCaps extends ReadonlyArray<Capability>,
  ProjectCaps extends ReadonlyArray<OrgCaps[number]>,
>(
  args: {
    readonly grantor: Parameters<TrustClient["issueOrgMandate"]>[0]["grantor"]
    readonly grantorScope: MandateScope<OrgCaps, "organization", null>
    readonly capabilities: ProjectCaps
    readonly rationale: string
    readonly triggerSource?: Parameters<TrustClient["issueOrgMandate"]>[0]["triggerSource"]
  },
  audit: MandateAuditService,
): MandateScope<ProjectCaps, "project", MandateScope<OrgCaps, "organization", null>> =>
  createTrust({ store: audit }).issueProjectMandate(args)

export const issueAgentMandate = <
  OrgCaps extends ReadonlyArray<Capability>,
  ProjectCaps extends ReadonlyArray<OrgCaps[number]>,
  AgentCaps extends ReadonlyArray<ProjectCaps[number]>,
>(
  args: {
    readonly grantor: Parameters<TrustClient["issueOrgMandate"]>[0]["grantor"]
    readonly grantorScope: MandateScope<ProjectCaps, "project", MandateScope<OrgCaps, "organization", null>>
    readonly capabilities: AgentCaps
    readonly rationale: string
    readonly triggerSource?: Parameters<TrustClient["issueOrgMandate"]>[0]["triggerSource"]
  },
  audit: MandateAuditService,
): MandateScope<AgentCaps, "agent", MandateScope<ProjectCaps, "project", MandateScope<OrgCaps, "organization", null>>> =>
  createTrust({ store: audit }).issueAgentMandate(args)

export const useCapability = <
  Caps extends ReadonlyArray<Capability>,
  Cap extends Caps[number],
  Tier extends MandateTier = "organization",
  ParentScope extends MandateScope<any, any, any> | null = null,
>(
  args: {
    readonly mandate: MandateScope<Caps, Tier, ParentScope>
    readonly capability: Cap
    readonly triggerSource?: Parameters<TrustClient["issueOrgMandate"]>[0]["triggerSource"]
  },
  audit: MandateAuditService,
): void => createTrust({ store: audit }).useCapability(args)

export const revokeMandate = (
  args: Parameters<TrustClient["revokeMandate"]>[0],
  audit: MandateAuditService,
): void => createTrust({ store: audit }).revokeMandate(args)
