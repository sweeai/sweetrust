/**
 * @sweetrust/mandate — bootstrap demo
 *
 * Demonstrates the type-enforced capability ladder, org → project → agent:
 *   1. Define three capabilities (FileRead, FileWrite, ShellExec)
 *   2. Arthur issues an organization-tier mandate holding all three
 *   3. Arthur issues the FILES_TEAM project a mandate with [FileRead, FileWrite]
 *      (subset — ShellExec NOT included)
 *   4. The project lead issues AgentA an agent-tier mandate with the same two
 *   5. AgentA uses FileRead under its mandate (works at compile + runtime)
 *   6. AgentA attempts to use ShellExec — COMPILE ERROR (type system gates;
 *      see the // @ts-expect-error annotation in the test file for evidence)
 *   7. Arthur, holding the org scope, revokes AgentA's mandate from the root
 *   8. AgentA attempts FileRead — runtime MandateRevoked error
 *
 * Until the 2026-10-13 rail audit this ran on the v0.0 `issueRootMandate` /
 * `issueMandate` pair, which stamped "organization" on everything it minted.
 * Those are gone; the tiered issuers are the API.
 *
 * Run:  node packages/trust/src/mandate/demo.ts
 *
 * Output: prints each step's result and the audit log dump at the end.
 */
import { makeInMemoryAuditLive } from "./audit.ts"
import {
  defineCapability,
  issueAgentMandate,
  issueOrgMandate,
  issueProjectMandate,
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
const FILES_TEAM: GrantorId = "FILES_TEAM" as GrantorId
const AGENT_A: GrantorId = "AGENT_A" as GrantorId

const main = (): void => {
  const audit = makeInMemoryAuditLive()

  console.log("=== @sweetrust/mandate demo ===\n")

  // Step 1+2: Arthur issues the organization root with all three caps.
  console.log("[1] Arthur issues the org mandate with [FileRead, FileWrite, ShellExec]")
  const arthurScope = issueOrgMandate(
    {
      grantor: ARTHUR,
      capabilities: [FileRead, FileWrite, ShellExec] as const,
      rationale: "organization root — owns all capabilities at session bootstrap",
    },
    audit,
  )
  console.log(`    → mandate id: ${arthurScope.id}`)
  console.log(`    → caps: ${arthurScope.capabilities.length}`)
  console.log("")

  // Step 3: Arthur issues the files project a subset — [FileRead, FileWrite] only.
  console.log("[2] Arthur issues FILES_TEAM a project mandate with [FileRead, FileWrite]")
  const projectScope = issueProjectMandate(
    {
      grantor: ARTHUR,
      grantorScope: arthurScope,
      capabilities: [FileRead, FileWrite] as const,
      rationale: "project scoped to file operations only — no shell execution",
    },
    audit,
  )
  console.log(`    → mandate id: ${projectScope.id}`)
  console.log(`    → parent: ${projectScope.parentMandateId}`)
  console.log(`    → caps: ${projectScope.capabilities.length}`)
  console.log("")

  // Step 4: the project lead issues AgentA an agent-tier leaf.
  console.log("[3] FILES_TEAM issues AgentA an agent mandate with [FileRead, FileWrite]")
  const agentScope = issueAgentMandate(
    {
      grantor: FILES_TEAM,
      grantorScope: projectScope,
      capabilities: [FileRead, FileWrite] as const,
      rationale: "agent scoped to the project's file operations",
    },
    audit,
  )
  console.log(`    → mandate id: ${agentScope.id}`)
  console.log(`    → parent: ${agentScope.parentMandateId}`)
  console.log(`    → caps: ${agentScope.capabilities.length}`)
  console.log("")

  // Step 5: AgentA uses FileRead — works.
  console.log("[4] AgentA uses FileRead → success (capability in scope)")
  useCapability({ mandate: agentScope, capability: FileRead }, audit)
  console.log("    → invocation recorded in audit log")
  console.log("")

  // Step 6: AgentA attempts ShellExec — COMPILE ERROR if the `as any` were removed.
  // The test file (test/mandate/mandate.test.ts) has the // @ts-expect-error proof.
  console.log("[5] AgentA attempts ShellExec → would COMPILE-ERROR (see test file for proof)")
  // Runtime check: even if types are erased via any-cast, the runtime
  // MandateScope check refuses.
  try {
    useCapability({ mandate: agentScope as any, capability: ShellExec }, audit)
  } catch (err) {
    console.log(`    → runtime fallback fired: ${(err as MandateError)._tag}`)
  }
  console.log("")

  // Step 7: Arthur revokes AgentA's mandate. The org scope is an ancestor of
  // the agent's, so possession of it is authority over the whole subtree.
  console.log("[6] Arthur revokes AgentA's mandate from the org root")
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

  // Step 8: AgentA attempts FileRead post-revocation — runtime fail.
  console.log("[7] AgentA attempts FileRead post-revocation → MandateRevoked error")
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

  console.log("\n[audit] FILES_TEAM's mandate audit trail:")
  for (const e of audit.query(projectScope.id)) {
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
