/**
 * @sweetrust/mandate — MandateAudit (in-memory + JSONL implementations)
 *
 * Per the mandate capability-declaration specification I10 — append-only
 * with cryptographic-signing scaffolding documented for v0.1.
 *
 * Two implementations for the unsigned audit:
 *   - InMemoryAudit — for tests and ephemeral demos
 *   - JsonlAudit — for production (append-only file storage)
 *
 * The signed variants add Ed25519 signing + SHA-256 hash-chaining on top of
 * the same service surface — swap implementations without code changes.
 */
import { appendFileSync, mkdirSync, readFileSync } from "node:fs"
import { dirname } from "node:path"
import {
  canonicalJSON,
  MANDATE_AUDIT_DOMAIN,
  sha256Hex,
  verifyAuditChain,
  type MandateSignerService,
} from "./signer.ts"
import type {
  MandateAuditEvent,
  MandateAuditService,
  MandateError,
  MandateId,
  SignedMandateAuditEvent,
} from "./types.ts"

type AuditLogCorrupt = Extract<MandateError, { readonly _tag: "AuditLogCorrupt" }>

const corrupt = (
  storePath: string,
  line: number,
  reason: AuditLogCorrupt["reason"],
  detail?: string,
): never => {
  const error: AuditLogCorrupt = {
    _tag: "AuditLogCorrupt",
    storePath,
    line,
    reason,
    ...(detail === undefined ? {} : { detail }),
  }
  throw error
}

/**
 * Read a JSONL audit file, fail-CLOSED (DAN-1159). A missing file is an empty
 * log. Every line must parse to an object, or the read throws `AuditLogCorrupt`
 * naming it. The line is never skipped: dropping a revoke while keeping its
 * grant resurrects a revoked mandate. And the file is never read as empty,
 * which is what flipped `isRevoked` from true to false on one bad byte (F5).
 * Any other I/O error propagates as itself: unreadable is not corrupt.
 */
const readJsonl = (storePath: string): ReadonlyArray<unknown> => {
  let text: string
  try {
    text = readFileSync(storePath, "utf-8")
  } catch (err) {
    if ((err as { readonly code?: unknown }).code === "ENOENT") return []
    throw err
  }
  const lines = text.split("\n")
  // Every record ends in "\n", so an intact file splits to one trailing "".
  if (lines[lines.length - 1] === "") lines.pop()
  return lines.map((line, i) => {
    let parsed: unknown
    try {
      parsed = JSON.parse(line)
    } catch (err) {
      return corrupt(storePath, i + 1, "unparseable", err instanceof Error ? err.message : String(err))
    }
    if (typeof parsed !== "object" || parsed === null) {
      return corrupt(storePath, i + 1, "unparseable", `line ${i + 1} is not a record`)
    }
    return parsed
  })
}

/**
 * In-memory audit log. Tests use this; production uses JsonlAudit.
 */
export const makeInMemoryAuditLive = (): MandateAuditService => {
  let events: ReadonlyArray<MandateAuditEvent> = []
  return {
    record: (event) => {
      events = [...events, event]
    },
    query: (mandateId: MandateId) => events.filter((e) => e.mandateId === mandateId),
    isRevoked: (mandateId: MandateId) =>
      events.some((e) => e.type === "revoke" && e.mandateId === mandateId),
  }
}

/**
 * SignedMandateAudit — v1.0 audit service that signs every recorded event
 * with the configured signer and chains records via SHA-256 `previousHash`
 * linkage. Per spec mandate-v0-2 I6 + I9.
 *
 * Two storage backings (mirroring the unsigned audit):
 *   - makeInMemorySignedAuditLive — plain array closure
 *   - makeJsonlSignedAuditLive(storePath) — append-only JSONL
 *
 * Consumers needing v0.0 semantics (unsigned audit) continue using the
 * existing `makeInMemoryAuditLive` / `makeJsonlAuditLive`. The signed
 * variants require a `MandateSignerService`.
 */
export interface SignedMandateAuditService {
  readonly recordSigned: (event: MandateAuditEvent) => SignedMandateAuditEvent
  readonly querySigned: (mandateId: MandateId) => ReadonlyArray<SignedMandateAuditEvent>
  readonly listAllSigned: () => ReadonlyArray<SignedMandateAuditEvent>
}

/**
 * makeInMemorySignedAuditLive — produces both a `MandateAuditService` and a
 * `SignedMandateAuditService` from a single backing store. The unsigned
 * `mandateAudit.record(event)` interface automatically signs and chains the
 * event; the `signedAudit` surface exposes the signed records directly.
 * Tests + demos that don't need signing continue to use
 * `makeInMemoryAuditLive`.
 *
 * Because execution is synchronous, the read-sign-append sequence is
 * inherently serialized — no semaphore needed (the original Effect version
 * used one only to guard against concurrent fibers observing the same chain
 * head).
 */
export const makeInMemorySignedAuditLive = (
  signer: MandateSignerService,
): { mandateAudit: MandateAuditService; signedAudit: SignedMandateAuditService } => {
  let events: ReadonlyArray<SignedMandateAuditEvent> = []

  const signAndRecord = (event: MandateAuditEvent): SignedMandateAuditEvent => {
    const previousHash =
      events.length > 0 ? sha256Hex(canonicalJSON(events[events.length - 1]!)) : null
    const signed = signer.sign({ payload: event, previousHash, domain: MANDATE_AUDIT_DOMAIN })
    events = [...events, signed]
    return signed
  }

  const mandateAudit: MandateAuditService = {
    record: (event) => {
      signAndRecord(event)
    },
    query: (mandateId) =>
      events.filter((e) => e.payload.mandateId === mandateId).map((e) => e.payload),
    isRevoked: (mandateId) =>
      events.some((e) => e.payload.type === "revoke" && e.payload.mandateId === mandateId),
  }

  const signedAudit: SignedMandateAuditService = {
    recordSigned: (event) => signAndRecord(event),
    querySigned: (mandateId) => events.filter((e) => e.payload.mandateId === mandateId),
    listAllSigned: () => events,
  }

  return { mandateAudit, signedAudit }
}

/**
 * makeJsonlSignedAuditLive — the durable, signed audit log. Like
 * `makeInMemorySignedAuditLive`, it returns BOTH surfaces over one file:
 * `mandateAudit` is the `MandateAuditService` that issue, use and revoke take,
 * and it signs and chains every event it records.
 *
 * Before DAN-1159 this returned only the signed surface, so it could not be
 * wired in as the audit log at all. A host had to pick the unsigned JSONL store
 * (durable, but anyone who can append to the file can write, delete or blank a
 * revoke) or this one (signed, but no `isRevoked`). Signed or durable, never
 * both (F4).
 *
 * Every read re-parses AND re-verifies the whole file against the store's
 * pinned key, `signer.publicKeyHex`: the operator's key, or for a verifier-only
 * signer, the operator's public key. Any failure throws `AuditLogCorrupt`,
 * from `isRevoked` too, so a forged, deleted or unparseable line is refused,
 * never obeyed and never hidden. Every append reads first, so the store refuses
 * to append past corruption. It used to read a corrupt file as empty and sign
 * the next record with previousHash null, a second genesis mid-file.
 *
 * Limits, stated rather than hidden: deleting the LAST lines leaves a valid
 * shorter chain, which only an on-chain anchor detects (SECURITY.md). And
 * appends are not locked across processes, so one store file needs one writer.
 * Verifying on every read costs one Ed25519 verification per record per call.
 * The previous version already re-parsed the whole file per call, so the
 * complexity class is unchanged, but the constant is much larger.
 */
export const makeJsonlSignedAuditLive = (
  storePath: string,
  signer: MandateSignerService,
): { mandateAudit: MandateAuditService; signedAudit: SignedMandateAuditService } => {
  mkdirSync(dirname(storePath), { recursive: true })
  const pin = { trustedSignerPublicKeyHex: signer.publicKeyHex }

  const readEvents = (): ReadonlyArray<SignedMandateAuditEvent> => {
    const records = readJsonl(storePath) as ReadonlyArray<SignedMandateAuditEvent>
    // A fresh store is an empty log, not an `empty-chain` verdict.
    if (records.length === 0) return records
    const verdict = verifyAuditChain(records, signer, pin)
    if (!verdict.valid) {
      // `empty-chain` is unreachable here, and every other failure names an index.
      corrupt(
        storePath,
        (verdict.firstInvalidIndex ?? 0) + 1,
        verdict.reason as AuditLogCorrupt["reason"],
        verdict.detail,
      )
    }
    return records
  }

  const signAndRecord = (event: MandateAuditEvent): SignedMandateAuditEvent => {
    // Reading verifies, so corruption stops the append before anything is signed.
    const existing = readEvents()
    const previousHash =
      existing.length > 0 ? sha256Hex(canonicalJSON(existing[existing.length - 1]!)) : null
    const signed = signer.sign({ payload: event, previousHash, domain: MANDATE_AUDIT_DOMAIN })
    appendFileSync(storePath, JSON.stringify(signed) + "\n", "utf-8")
    return signed
  }

  const mandateAudit: MandateAuditService = {
    record: (event) => {
      signAndRecord(event)
    },
    query: (mandateId) =>
      readEvents().filter((e) => e.payload.mandateId === mandateId).map((e) => e.payload),
    isRevoked: (mandateId) =>
      readEvents().some((e) => e.payload.type === "revoke" && e.payload.mandateId === mandateId),
  }

  const signedAudit: SignedMandateAuditService = {
    recordSigned: (event) => signAndRecord(event),
    querySigned: (mandateId) => readEvents().filter((e) => e.payload.mandateId === mandateId),
    listAllSigned: () => readEvents(),
  }

  return { mandateAudit, signedAudit }
}

/**
 * Append-only JSONL audit log. NOT cryptographically signed: anyone who can
 * append to the file can write or delete a revoke. Prefer
 * `makeJsonlSignedAuditLive`, which is the same `MandateAuditService` and
 * verifies every read.
 *
 * Reads fail CLOSED through `readJsonl` (DAN-1159, F5). This store used to read
 * the whole file inside one try/catch and return [] on any failure, so one bad
 * byte blanked the log: a direct `isRevoked` flipped from true to false, and
 * `useCapability` misreported a corrupt log as `MandateNotIssued`.
 */
export const makeJsonlAuditLive = (storePath: string): MandateAuditService => {
  mkdirSync(dirname(storePath), { recursive: true })

  const readEvents = (): ReadonlyArray<MandateAuditEvent> =>
    readJsonl(storePath) as ReadonlyArray<MandateAuditEvent>

  return {
    record: (event) => {
      appendFileSync(storePath, JSON.stringify(event) + "\n", "utf-8")
    },
    query: (mandateId: MandateId) => readEvents().filter((e) => e.mandateId === mandateId),
    isRevoked: (mandateId: MandateId) =>
      readEvents().some((e) => e.type === "revoke" && e.mandateId === mandateId),
  }
}
