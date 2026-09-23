/**
 * F4: the durable audit store must be SIGNED and must BE the audit log (DAN-1159 item 1).
 *
 * Before this, a host had to choose. `makeJsonlAuditLive` is a durable
 * `MandateAuditService` and signs nothing, so anyone who can append to its file
 * can write a revoke, delete one, or blank the log with one bad byte (F5).
 * `makeJsonlSignedAuditLive` signs and chains every record, but it returned only
 * `recordSigned` / `querySigned` / `listAllSigned`. It had no `record`, `query`
 * or `isRevoked`, so it could not be handed to `issueOrgMandate`,
 * `useCapability` or `revokeMandate` at all. Signed or durable, never both.
 *
 * Two principals, per the test-suite audit (§2): the OPERATOR runs the store
 * and holds its signing key. The INTRUDER can append to the store's file, and
 * holds a key of its own but not the operator's.
 */
import { generateKeyPairSync } from "node:crypto"
import { appendFileSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { describe, expect, test } from "vitest"
import { makeJsonlSignedAuditLive } from "../../src/mandate/audit.ts"
import {
  defineCapability,
  issueOrgMandate,
  revokeMandate,
  useCapability,
} from "../../src/mandate/mandate.ts"
import {
  canonicalJSON,
  makeEd25519SignerLive,
  makeEd25519VerifierLive,
  MANDATE_AUDIT_DOMAIN,
  sha256Hex,
  verifyAuditChain,
  type MandateSignerService,
} from "../../src/mandate/signer.ts"
import type {
  GrantorId,
  MandateAuditEvent,
  MandateId,
  SignedMandateAuditEvent,
} from "../../src/mandate/types.ts"

const Deploy = defineCapability("durable-test/Deploy")
const OPERATOR = "OPERATOR" as GrantorId

const keypair = () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519")
  const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }) as string
  const signer = makeEd25519SignerLive({
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }) as string,
    publicKeyPem,
  })
  return { signer, publicKeyPem }
}

const freshPath = () => join(mkdtempSync(join(tmpdir(), "sweetrust-durable-")), "audit.jsonl")

/** The store under test, opened the way a host opens it. */
const openStore = (path: string, signer: MandateSignerService) => makeJsonlSignedAuditLive(path, signer)

/** Capture a throw so its shape can be asserted. */
const thrown = (fn: () => unknown): any => {
  try {
    fn()
  } catch (e) {
    return e
  }
  throw new Error("expected a throw, and nothing was thrown")
}

const lines = (path: string) => readFileSync(path, "utf-8").split("\n").filter((l) => l.length > 0)

/** The previousHash a record appended NOW would need, computed from the file. */
const headHash = (path: string) => sha256Hex(canonicalJSON(JSON.parse(lines(path).at(-1)!)))

/** The operator's org, issued and then revoked, in a store at `path`. */
const issuedThenRevoked = (path: string, signer: MandateSignerService) => {
  const store = openStore(path, signer)
  const org = issueOrgMandate(
    { grantor: OPERATOR, capabilities: [Deploy] as const, rationale: "org root" },
    store.mandateAudit,
  )
  revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "stop everything" }, store.mandateAudit)
  return { store, org }
}

const revokeEvent = (mandateId: MandateId): MandateAuditEvent => ({
  type: "revoke",
  mandateId,
  revokedBy: OPERATOR,
  rationale: "forged",
  timestamp: new Date().toISOString() as any,
  triggerSource: "code",
})

describe("F4 — the signed JSONL store is a MandateAuditService", () => {
  test("issue, use and revoke run against it end to end", () => {
    const { signer } = keypair()
    const store = openStore(freshPath(), signer)
    const org = issueOrgMandate(
      { grantor: OPERATOR, capabilities: [Deploy] as const, rationale: "org root" },
      store.mandateAudit,
    )
    useCapability({ mandate: org, capability: Deploy }, store.mandateAudit)
    revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "stop" }, store.mandateAudit)
    expect(thrown(() => useCapability({ mandate: org, capability: Deploy }, store.mandateAudit))).toMatchObject({
      _tag: "MandateRevoked",
      mandateId: org.id,
    })
  })

  test("a revocation survives a restart: a fresh store over the same file still refuses", () => {
    const { signer } = keypair()
    const path = freshPath()
    const { org } = issuedThenRevoked(path, signer)
    const restarted = openStore(path, signer)
    expect(restarted.mandateAudit.isRevoked(org.id)).toBe(true)
    expect(thrown(() => useCapability({ mandate: org, capability: Deploy }, restarted.mandateAudit))).toMatchObject({
      _tag: "MandateRevoked",
    })
  })

  test("an auditor holding only the operator's PUBLIC key reads the same verdict", () => {
    const { signer, publicKeyPem } = keypair()
    const path = freshPath()
    const { org } = issuedThenRevoked(path, signer)
    const auditor = openStore(path, makeEd25519VerifierLive({ publicKeyPem }))
    expect(auditor.mandateAudit.isRevoked(org.id)).toBe(true)
  })

  test("every line it writes verifies under the operator's pinned key", () => {
    const { signer } = keypair()
    const path = freshPath()
    const store = openStore(path, signer)
    const org = issueOrgMandate(
      { grantor: OPERATOR, capabilities: [Deploy] as const, rationale: "org root" },
      store.mandateAudit,
    )
    useCapability({ mandate: org, capability: Deploy }, store.mandateAudit)
    revokeMandate({ mandateId: org.id, revokerScope: org, rationale: "stop" }, store.mandateAudit)

    const onDisk = lines(path).map((l) => JSON.parse(l) as SignedMandateAuditEvent)
    expect(onDisk.map((r) => r.payload.type)).toEqual(["grant", "invoke", "revoke"])
    expect(verifyAuditChain(onDisk, signer, { trustedSignerPublicKeyHex: signer.publicKeyHex })).toMatchObject({
      valid: true,
    })
  })
})

describe("F4 — an intruder with append access and no operator key cannot steer authority", () => {
  test("a revoke the intruder signed with its OWN key is refused, not obeyed", () => {
    const operator = keypair().signer
    const intruder = keypair().signer
    const path = freshPath()
    const store = openStore(path, operator)
    const org = issueOrgMandate(
      { grantor: OPERATOR, capabilities: [Deploy] as const, rationale: "org root" },
      store.mandateAudit,
    )
    // A perfectly formed, correctly chained record. Only the key is wrong.
    const forged = intruder.sign({ payload: revokeEvent(org.id), previousHash: headHash(path), domain: MANDATE_AUDIT_DOMAIN })
    appendFileSync(path, JSON.stringify(forged) + "\n")

    // Not `true` (that obeys the intruder), not `false` (that hides the
    // tampering): a typed refusal naming the line.
    expect(thrown(() => store.mandateAudit.isRevoked(org.id))).toMatchObject({
      _tag: "AuditLogCorrupt",
      line: 2,
      reason: "untrusted-signer",
    })
    expect(thrown(() => useCapability({ mandate: org, capability: Deploy }, store.mandateAudit))).toMatchObject({
      _tag: "AuditLogCorrupt",
    })
  })

  test("a hand-written revoke line claiming the operator's key is refused", () => {
    const operator = keypair().signer
    const path = freshPath()
    const store = openStore(path, operator)
    const org = issueOrgMandate(
      { grantor: OPERATOR, capabilities: [Deploy] as const, rationale: "org root" },
      store.mandateAudit,
    )
    const handWritten = {
      payload: revokeEvent(org.id),
      signature: "00".repeat(64),
      signerPublicKeyHex: operator.publicKeyHex,
      signedAt: new Date().toISOString(),
      previousHash: headHash(path),
      domain: MANDATE_AUDIT_DOMAIN,
    }
    appendFileSync(path, JSON.stringify(handWritten) + "\n")
    expect(thrown(() => store.mandateAudit.isRevoked(org.id))).toMatchObject({ _tag: "AuditLogCorrupt", line: 2 })
  })

  test("deleting an INTERIOR revoke line breaks the chain and is refused", () => {
    const { signer } = keypair()
    const path = freshPath()
    const { store, org } = issuedThenRevoked(path, signer)
    // A later record, so the revoke is no longer the tail.
    issueOrgMandate({ grantor: OPERATOR, capabilities: [Deploy] as const, rationale: "second org" }, store.mandateAudit)
    const [grant, , later] = lines(path)
    writeFileSync(path, `${grant}\n${later}\n`)

    expect(thrown(() => store.mandateAudit.isRevoked(org.id))).toMatchObject({
      _tag: "AuditLogCorrupt",
      line: 2,
      reason: "hash-chain-broken",
    })
  })

  test("HONEST LIMIT (needs an anchor): deleting the LAST line leaves a valid shorter chain", () => {
    // SECURITY.md § Honest limits. Nothing inside the file tells a truncated log
    // from one that simply ended. Only an on-chain anchor over the head catches
    // it. This test pins the limit so that closing it is a visible change.
    const { signer } = keypair()
    const path = freshPath()
    const { store, org } = issuedThenRevoked(path, signer)
    const [grant] = lines(path)
    writeFileSync(path, `${grant}\n`)
    expect(store.mandateAudit.isRevoked(org.id)).toBe(false)
  })
})

describe("F4 — corruption fails closed, and the store never forks its chain", () => {
  test("one unparseable line makes every read THROW, never flip isRevoked to false", () => {
    const { signer } = keypair()
    const path = freshPath()
    const { store, org } = issuedThenRevoked(path, signer)
    appendFileSync(path, "{not json\n")

    const corrupt = { _tag: "AuditLogCorrupt", storePath: path, line: 3, reason: "unparseable" }
    expect(thrown(() => store.mandateAudit.isRevoked(org.id))).toMatchObject(corrupt)
    expect(thrown(() => store.mandateAudit.query(org.id))).toMatchObject(corrupt)
    expect(thrown(() => store.signedAudit.listAllSigned())).toMatchObject(corrupt)
  })

  test("it refuses to append past corruption: no second genesis", () => {
    // It used to read the corrupt file as EMPTY, sign the next record with
    // previousHash null and append it: a second genesis in the middle of the file.
    const { signer } = keypair()
    const path = freshPath()
    const { store, org } = issuedThenRevoked(path, signer)
    appendFileSync(path, "{not json\n")
    const before = readFileSync(path, "utf-8")

    expect(thrown(() => store.signedAudit.recordSigned(revokeEvent(org.id)))).toMatchObject({ _tag: "AuditLogCorrupt" })
    expect(thrown(() => store.mandateAudit.record(revokeEvent(org.id)))).toMatchObject({ _tag: "AuditLogCorrupt" })
    expect(readFileSync(path, "utf-8")).toBe(before)
  })

  test("a missing file is an empty log, and its first record is genesis", () => {
    const { signer } = keypair()
    const path = freshPath()
    const store = openStore(path, signer)
    expect(store.mandateAudit.isRevoked("MAN_NONE" as MandateId)).toBe(false)
    const first = store.signedAudit.recordSigned(revokeEvent("MAN_NONE" as MandateId))
    expect(first.previousHash).toBeNull()
  })

  test("an EMPTY file is an empty log, not an empty-chain verdict", () => {
    // verifyAuditChain([]) is `empty-chain` since DAN-1159 item 3. A store that
    // handed it a fresh, empty file would refuse to start.
    const { signer } = keypair()
    const path = freshPath()
    writeFileSync(path, "")
    const store = openStore(path, signer)
    expect(store.mandateAudit.isRevoked("MAN_NONE" as MandateId)).toBe(false)
    expect(store.mandateAudit.query("MAN_NONE" as MandateId)).toEqual([])
  })
})
