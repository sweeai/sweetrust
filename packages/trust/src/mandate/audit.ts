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
import { canonicalJSON, MANDATE_AUDIT_DOMAIN, sha256Hex, type MandateSignerService } from "./signer.ts"
import type {
  MandateAuditEvent,
  MandateAuditService,
  MandateId,
  SignedMandateAuditEvent,
} from "./types.ts"

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

export const makeJsonlSignedAuditLive = (
  storePath: string,
  signer: MandateSignerService,
): SignedMandateAuditService => {
  mkdirSync(dirname(storePath), { recursive: true })

  const readEvents = (): ReadonlyArray<SignedMandateAuditEvent> => {
    try {
      const text = readFileSync(storePath, "utf-8")
      return text
        .split("\n")
        .filter((l) => l.length > 0)
        .map((l) => JSON.parse(l) as SignedMandateAuditEvent)
    } catch {
      return []
    }
  }

  return {
    recordSigned: (event) => {
      const existing = readEvents()
      const previousHash =
        existing.length > 0
          ? sha256Hex(canonicalJSON(existing[existing.length - 1]!))
          : null
      const signed = signer.sign({ payload: event, previousHash, domain: MANDATE_AUDIT_DOMAIN })
      appendFileSync(storePath, JSON.stringify(signed) + "\n", "utf-8")
      return signed
    },
    querySigned: (mandateId) =>
      readEvents().filter((e) => e.payload.mandateId === mandateId),
    listAllSigned: () => readEvents(),
  }
}

/**
 * Append-only JSONL audit log for production. NOT cryptographically signed —
 * see the signed variants above.
 */
export const makeJsonlAuditLive = (storePath: string): MandateAuditService => {
  mkdirSync(dirname(storePath), { recursive: true })

  const readEvents = (): ReadonlyArray<MandateAuditEvent> => {
    try {
      const text = readFileSync(storePath, "utf-8")
      return text
        .split("\n")
        .filter((l) => l.length > 0)
        .map((l) => JSON.parse(l) as MandateAuditEvent)
    } catch {
      return []
    }
  }

  return {
    record: (event) => {
      appendFileSync(storePath, JSON.stringify(event) + "\n", "utf-8")
    },
    query: (mandateId: MandateId) => readEvents().filter((e) => e.mandateId === mandateId),
    isRevoked: (mandateId: MandateId) =>
      readEvents().some((e) => e.type === "revoke" && e.mandateId === mandateId),
  }
}
