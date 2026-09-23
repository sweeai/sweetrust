/**
 * @sweetrust/mandate — bootstrap demo
 *
 * Demonstrates the v0.0 type-enforced capability declaration:
 *   1. Define three capabilities (FileRead, FileWrite, ShellExec)
 *   2. Arthur (root grantor) issues a root mandate with all three to himself
 *   3. Arthur issues a child mandate to "AgentA" with [FileRead, FileWrite]
 *      (subset — ShellExec NOT included)
 *   4. AgentA uses FileRead under its mandate (works at compile + runtime)
 *   5. AgentA attempts to use ShellExec — COMPILE ERROR (type system gates;
 *      see the // @ts-expect-error annotation in the test file for evidence)
 *   6. Arthur revokes AgentA's mandate
 *   7. AgentA attempts FileRead — runtime MandateRevoked error
 *
 * Run:  node packages/trust/src/mandate/demo.ts
 *
 * Output: prints each step's result and the audit log dump at the end.
 */
import { makeInMemoryAuditLive } from "./audit.ts"
import {
  defineCapability,
  issueMandate,
  issueRootMandate,
  revokeMandate,
  useCapability,
} from "./mandate.ts"
import type { GrantorId, MandateError } from "./types.ts"

// Example capabilities. In production these would be defined by domain
// modules (e.g., a filesystem module exports FileRead + FileWrite; a shell
// module exports ShellExec). For the demo we declare them here.
const FileRead = defineCapability("demo/FileRead")
const FileWrite = defineCapability("demo/FileWrite")
const ShellExec = defineCapability("demo/ShellExec")

const ARTHUR: GrantorId = "ARTHUR" as GrantorId
const AGENT_A: GrantorId = "AGENT_A" as GrantorId

const main = (): void => {
  const audit = makeInMemoryAuditLive()

  console.log("=== @sweetrust/mandate v0.0 demo ===\n")

  // Step 1+2: Arthur issues himself a root mandate with all three caps.
  console.log("[1] Arthur issues root mandate with [FileRead, FileWrite, ShellExec]")
  const arthurScope = issueRootMandate(
    {
      grantor: ARTHUR,
      capabilities: [FileRead, FileWrite, ShellExec] as const,
      rationale: "root grantor — owns all capabilities at session bootstrap",
    },
    audit,
  )
  console.log(`    → mandate id: ${arthurScope.id}`)
  console.log(`    → caps: ${arthurScope.capabilities.length}`)
  console.log("")

  // Step 3: Arthur issues AgentA a subset — [FileRead, FileWrite] only.
  console.log("[2] Arthur issues AgentA mandate with [FileRead, FileWrite] subset")
  const agentScope = issueMandate(
    {
      grantor: ARTHUR,
      grantorScope: arthurScope,
      capabilities: [FileRead, FileWrite] as const,
      rationale: "agent scoped to file operations only — no shell execution",
    },
    audit,
  )
  console.log(`    → mandate id: ${agentScope.id}`)
  console.log(`    → parent: ${agentScope.parentMandateId}`)
  console.log(`    → caps: ${agentScope.capabilities.length}`)
  console.log("")

  // Step 4: AgentA uses FileRead — works.
  console.log("[3] AgentA uses FileRead → success (capability in scope)")
  useCapability({ mandate: agentScope, capability: FileRead }, audit)
  console.log("    → invocation recorded in audit log")
  console.log("")

  // Step 5: AgentA attempts ShellExec — COMPILE ERROR if the `as any` were removed.
  // The test file (test/mandate.test.ts) has the // @ts-expect-error proof.
  console.log("[4] AgentA attempts ShellExec → would COMPILE-ERROR (see test file for proof)")
  // Runtime check: even if types are erased via any-cast, the runtime
  // MandateScope check refuses.
  try {
    useCapability({ mandate: agentScope as any, capability: ShellExec }, audit)
  } catch (err) {
    console.log(`    → runtime fallback fired: ${(err as MandateError)._tag}`)
  }
  console.log("")

  // Step 6: Arthur revokes AgentA's mandate.
  console.log("[5] Arthur revokes AgentA's mandate")
  revokeMandate(
    {
      mandateId: agentScope.id,
      revokerScope: arthurScope,
      rationale: "demo cleanup; agent task complete",
    },
    audit,
  )
  console.log("    → revocation recorded")
  console.log("")

  // Step 7: AgentA attempts FileRead post-revocation — runtime fail.
  console.log("[6] AgentA attempts FileRead post-revocation → MandateRevoked error")
  try {
    useCapability({ mandate: agentScope, capability: FileRead }, audit)
  } catch (err) {
    console.log(`    → ${(err as MandateError)._tag}`)
  }
  console.log("")

  // Audit log dump
  console.log("[audit] Arthur's mandate audit trail:")
  for (const e of audit.query(arthurScope.id)) {
    console.log(`    ${e.type} @ ${e.timestamp}`)
  }

  console.log("\n[audit] AgentA's mandate audit trail:")
  for (const e of audit.query(agentScope.id)) {
    console.log(`    ${e.type} @ ${e.timestamp}`)
  }

  console.log("\n=== demo complete ===")
}

try {
  main()
} catch (err) {
  console.error("[demo] FAILED:", err)
  process.exit(1)
}
