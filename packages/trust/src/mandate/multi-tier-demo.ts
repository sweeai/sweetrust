/**
 * @sweetrust/mandate v1.0 — multi-tier hierarchy + signed audit demo
 *
 * Working code for the whole authority story: a three-tier hierarchy where every
 * grant, use and revocation lands on one Ed25519-signed hash chain.
 *
 * Flow:
 *   1. Arthur issues a v1.0 organization-tier mandate with three capabilities
 *      [Read, Write, Deploy] — code-triggered, signed, recorded.
 *   2. Arthur issues a project-tier mandate "Cookie" with subset [Read, Write]
 *      — type-system enforces subset; signed; chain-linked to org grant.
 *   3. Arthur issues an agent-tier mandate "ChefBot" with subset [Read]
 *      — type-system enforces subset of project; signed; chain-linked.
 *   4. Arthur revokes ChefBot's mandate — signed revoke recorded.
 *   5. verifyAuditChain walks the full log and confirms validity.
 *   6. We then DEMONSTRATE TAMPERING: rewrite a record's rationale
 *      post-signing; re-verify; verifier reports the exact corrupted index.
 *
 * The point: every grant, every invocation, every revocation is
 * cryptographically attributed. The audit log is forensically tamper-
 * evident. The compile-time gate proves out-of-tier grants are refused
 * at the call site, not at runtime.
 *
 * Run: node packages/trust/src/mandate/multi-tier-demo.ts
 */
import { generateKeyPairSync } from "node:crypto"
import { makeInMemorySignedAuditLive } from "./audit.ts"
import {
  defineCapability,
  issueAgentMandate,
  issueOrgMandate,
  issueProjectMandate,
  revokeMandate,
} from "./mandate.ts"
import { makeEd25519SignerLive, verifyAuditChain } from "./signer.ts"
import type { GrantorId, SignedMandateAuditEvent } from "./types.ts"

const CapRead = defineCapability("v1-demo/CapRead")
const CapWrite = defineCapability("v1-demo/CapWrite")
const CapDeploy = defineCapability("v1-demo/CapDeploy")

const ARTHUR: GrantorId = "ARTHUR" as GrantorId
const COOKIE_LEAD: GrantorId = "COOKIE_PROJECT_LEAD" as GrantorId
const CHEFBOT: GrantorId = "CHEFBOT" as GrantorId

const formatSigned = (e: SignedMandateAuditEvent): string => {
  const sigPrefix = e.signature.slice(0, 16)
  const prevPrefix = e.previousHash ? e.previousHash.slice(0, 8) : "(genesis)"
  const triggerSrc = `[${e.payload.triggerSource}]`.padEnd(8)
  let body: string
  switch (e.payload.type) {
    case "grant":
      body = `GRANT     ${e.payload.mandateId}  by ${e.payload.grantor}  caps=${e.payload.capabilities.join(",")}`
      break
    case "invoke":
      body = `INVOKE    ${e.payload.mandateId}  cap=${e.payload.capability}`
      break
    case "revoke":
      body = `REVOKE    ${e.payload.mandateId}  by ${e.payload.revokedBy}  reason="${e.payload.rationale.slice(0, 40)}"`
      break
    case "human-context":
      body = `COMMENT   ${e.payload.mandateId}  ${e.payload.author}: "${e.payload.body.slice(0, 40)}..."`
      break
  }
  return `${triggerSrc} sig=${sigPrefix}.. prev=${prevPrefix}.. ${body}`
}

const main = (): void => {
  // Generate a fresh Ed25519 key pair for the demo. In production these
  // come from operator-managed key material per spec I10 / INV-SEC-1.
  const { publicKey, privateKey } = generateKeyPairSync("ed25519")
  const signerConfig = {
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }) as string,
    publicKeyPem: publicKey.export({ format: "pem", type: "spki" }) as string,
  }
  const signer = makeEd25519SignerLive(signerConfig)
  const { mandateAudit, signedAudit } = makeInMemorySignedAuditLive(signer)

  console.log("=== @sweetrust/mandate v1.0 — multi-tier + signed audit demo ===\n")

  // === Step 1: Arthur's organization-tier mandate ===
  const orgScope = issueOrgMandate(
    {
      grantor: ARTHUR,
      capabilities: [CapRead, CapWrite, CapDeploy] as const,
      rationale: "Workspace charter: org may use file read/write + deploy capabilities",
    },
    mandateAudit,
  )
  console.log(`[1] Arthur issues ORG-TIER mandate (charter)`)
  console.log(`    → ${orgScope.id}`)
  console.log(`    → tier: ${orgScope.tier}, caps: ${orgScope.capabilities.length}, parentScope: ${orgScope.parentScope}`)

  // === Step 2: Project-tier mandate "Cookie" — subset of org ===
  const projectScope = issueProjectMandate(
    {
      grantor: COOKIE_LEAD,
      grantorScope: orgScope,
      capabilities: [CapRead, CapWrite] as const,
      rationale: "Project Cookie: read+write file ops only — no deploy",
    },
    mandateAudit,
  )
  console.log(`\n[2] Project Lead issues PROJECT-TIER mandate "Cookie" (subset of org)`)
  console.log(`    → ${projectScope.id}`)
  console.log(`    → tier: ${projectScope.tier}, caps: ${projectScope.capabilities.length}, parent: ${projectScope.parentMandateId}`)

  // === Step 3: Agent-tier mandate "ChefBot" — subset of project ===
  const agentScope = issueAgentMandate(
    {
      grantor: CHEFBOT,
      grantorScope: projectScope,
      capabilities: [CapRead] as const,
      rationale: "Agent ChefBot: read-only — recipe data access for this task",
    },
    mandateAudit,
  )
  console.log(`\n[3] ChefBot issues AGENT-TIER mandate (subset of project)`)
  console.log(`    → ${agentScope.id}`)
  console.log(`    → tier: ${agentScope.tier}, caps: ${agentScope.capabilities.length}, parent: ${agentScope.parentMandateId}`)
  console.log(`    → agent-tier mandates are LEAVES — type system refuses upward delegation`)

  // === Step 4: Revoke ChefBot's mandate (Arthur, ancestor in chain) ===
  revokeMandate(
    {
      mandateId: agentScope.id,
      revokerScope: orgScope,
      rationale: "Demo cleanup: agent task complete",
    },
    mandateAudit,
  )
  console.log(`\n[4] Arthur revokes ChefBot's mandate (ancestor in delegation chain)`)
  console.log(`    → revocation recorded in signed audit log`)

  // === Step 5: Walk the full signed audit log + verify ===
  const fullLog = signedAudit.listAllSigned()
  console.log(`\n[5] Full signed audit chain (${fullLog.length} events):`)
  for (const record of fullLog) {
    console.log(`    ${formatSigned(record)}`)
  }

  const result1 = verifyAuditChain(fullLog, signer, {
    trustedSignerPublicKeyHex: signer.publicKeyHex,
  })
  console.log(`\n[6] verifyAuditChain on intact log:`)
  console.log(`    → valid: ${result1.valid}`)
  console.log(`    → reason: ${result1.reason}`)

  // === Step 6: Demonstrate tamper detection ===
  console.log(`\n[7] Demonstrating TAMPER DETECTION — rewriting record 1's rationale...`)
  const tamperedLog: SignedMandateAuditEvent[] = fullLog.map((r, i) => {
    if (i === 1 && r.payload.type === "grant") {
      return {
        ...r,
        payload: {
          ...r.payload,
          rationale: "Project Cookie: read+write+deploy — TAMPERED to grant deploy capability",
        },
      }
    }
    return r
  })
  const result2 = verifyAuditChain(tamperedLog, signer, {
    trustedSignerPublicKeyHex: signer.publicKeyHex,
  })
  console.log(`    → valid: ${result2.valid}`)
  console.log(`    → firstInvalidIndex: ${result2.firstInvalidIndex}`)
  console.log(`    → reason: ${result2.reason}`)
  console.log(`\nThe signature was over the ORIGINAL canonical JSON. Any field tamper`)
  console.log(`invalidates verification. The audit log is forensically tamper-evident.`)

  // === Step 7: Demonstrate hash-chain detection (record removal) ===
  console.log(`\n[8] Demonstrating CHAIN DETECTION — removing middle record...`)
  if (fullLog.length >= 3) {
    const removedMiddle: SignedMandateAuditEvent[] = [fullLog[0]!, ...fullLog.slice(2)]
    const result3 = verifyAuditChain(removedMiddle, signer, {
      trustedSignerPublicKeyHex: signer.publicKeyHex,
    })
    console.log(`    → valid: ${result3.valid}`)
    console.log(`    → firstInvalidIndex: ${result3.firstInvalidIndex}`)
    console.log(`    → reason: ${result3.reason}`)
    console.log(`\nThe surviving record's previousHash references the removed record's`)
    console.log(`hash, which doesn't match the new previous record. Chain breaks.`)
  }

  console.log(`\n=== demo complete ===`)
  console.log(`  Type system enforces multi-tier subset gates at compile time.`)
  console.log(`  Ed25519 signatures + SHA-256 hash chain make the audit log forensically`)
  console.log(`  tamper-evident.`)
}

try {
  main()
} catch (err) {
  console.error("[multi-tier-demo] FAILED:", err)
  process.exit(1)
}
