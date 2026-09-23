/**
 * Constitutional pre-check — foundational security primitives.
 *
 * v0.2.0 ships ONE primitive: constitutionalPreCheck — a compile-time-inlined
 * catalog of prompt-injection patterns (MIP-1, MIP-3, MIP-4, MIP-5; MIP-2 +
 * MIP-6 deferred by design) per the security-hardened-judge specification
 * I3 + I4.
 *
 * The pattern catalog is defined as source-code constants so an attacker
 * compromising a runtime config file cannot weaken the defense. Adding a new
 * pattern requires a supersession ADR + new build per
 * security-hardened-judge.allium I4.
 *
 * Consumers call constitutionalPreCheck on EVERY authored input BEFORE EVERY
 * model call (or, in the case of @sweetrust/mandate, before any audit-log
 * persistence of mandate metadata).
 *
 * v0.2.0 deltas vs v0.1.0 (Council 2 audit, 2026-05-07):
 *   - NFKC pre-normalization closes Unicode-confusable bypasses
 *   - MIP-4 charset extended to include base64url (-_)
 *   - MIP-4 exempts 0x-prefixed blobs (chain calldata is not an injection signal)
 *   - MIP-5 character set extended from 4 zero-width code points to the full
 *     invisible/format family: word joiner, soft hyphen, combining grapheme
 *     joiner, Mongolian vowel separator, Hangul choseong filler, bidi-override
 *     family (Trojan Source attacks), and Tag-character family (modern stego)
 *   - MaliciousInputMatch carries startOffset, endOffset, catalogVersion
 *   - toMaliciousInputError() factory ships the typed-error wrap
 *   - CATALOG_VERSION exported for forensic correlation per parent spec I9
 *
 * The catalog covers ASCII-English instruction-override patterns +
 * NFKC-normalized Unicode confusables. Multilingual paraphrase (CJK, RTL
 * scripts) and natural-language paraphrase ("never mind what was said") are
 * deliberately out of scope — defense in depth via sentinel framing (parent
 * spec I1) + tool_choice forcing (I2) + conservative-fail (I7) handles them.
 */

export const CATALOG_VERSION = "0.2.0"

export type MaliciousInputPatternId = "MIP-1" | "MIP-2" | "MIP-3" | "MIP-4" | "MIP-5" | "MIP-6"

export interface MaliciousInputMatch {
  readonly patternId: MaliciousInputPatternId
  readonly description: string
  readonly evidence: string
  readonly catalogVersion: string
  readonly startOffset: number
  readonly endOffset: number
}

const INVISIBLE_OR_FORMAT_CHARS =
  /[​-‍⁠﻿­͏᠎ᅟ‪-‮⁦-⁩\u{E0020}-\u{E007F}]/gu

const BASE64_LIKE = /[A-Za-z0-9+/=_\-]{256,}/g

// MIP-4 0x-prefix exemption — chain calldata blobs (ETH, Solana hex traces)
// routinely exceed 256 chars of [A-Za-z0-9]. A 0x-prefix is a strong signal
// that the blob is hex-encoded chain data, not an injection payload. We must
// check BOTH (a) the 2 chars immediately before the match (when the regex
// match starts after "0x") AND (b) the first 2 chars of the match itself
// (when the regex greedily captures "0x" as part of its run, which it does
// because both '0' and 'x' are in the charset).
const HEX_PREFIX_BEFORE = /0x$/i
const HEX_PREFIX_AT_START = /^0x/i

// Latin-confusable normalization. NFKC handles compatibility decomposition
// (full-width forms, ligatures) but does NOT collapse cross-script visual
// confusables — Cyrillic 'о' (U+043E) and Latin 'o' look identical but are
// different code points. UTS #39 has ~1000 confusable mappings; this table
// covers the ~20 high-leverage Latin-lookalikes used in published
// prompt-injection bypass corpora (Cyrillic + Greek vowels and common
// consonants). Adding new entries is a supersession-ADR-equivalent decision
// per security-hardened-judge.allium I4.
const CONFUSABLE_TO_LATIN: Record<string, string> = {
  "а": "a", "А": "A", // U+0430 / U+0410 Cyrillic
  "е": "e", "Е": "E", // U+0435 / U+0415 Cyrillic
  "о": "o", "О": "O", // U+043E / U+041E Cyrillic
  "р": "p", "Р": "P", // U+0440 / U+0420 Cyrillic
  "с": "c", "С": "C", // U+0441 / U+0421 Cyrillic
  "у": "y", "У": "Y", // U+0443 / U+0423 Cyrillic
  "х": "x", "Х": "X", // U+0445 / U+0425 Cyrillic
  "В": "B",            // U+0412 Cyrillic
  "К": "K",            // U+041A Cyrillic
  "М": "M",            // U+041C Cyrillic
  "Н": "H",            // U+041D Cyrillic
  "Т": "T",            // U+0422 Cyrillic
  "α": "a",            // U+03B1 Greek
  "ο": "o", "Ο": "O", // U+03BF / U+039F Greek
  "ρ": "p",            // U+03C1 Greek
  "ε": "e",            // U+03B5 Greek
  "ι": "i", "Ι": "I", // U+03B9 / U+0399 Greek
  "ν": "v",            // U+03BD Greek
}

const CONFUSABLE_KEYS = Object.keys(CONFUSABLE_TO_LATIN).join("")
const CONFUSABLE_RE = new RegExp(`[${CONFUSABLE_KEYS}]`, "g")

const foldConfusables = (s: string): string =>
  s.replace(CONFUSABLE_RE, (ch) => CONFUSABLE_TO_LATIN[ch] ?? ch)

export const constitutionalPreCheck = (rawInput: string): MaliciousInputMatch | null => {
  // Two-stage normalization:
  //   1. NFKC — compatibility decomposition (full-width, ligatures, circled forms)
  //   2. Latin-confusable folding — cross-script visual lookalikes (Cyrillic/Greek)
  // Both stages run unconditionally. Pure; idempotent; microsecond cost.
  const input = foldConfusables(rawInput.normalize("NFKC"))

  const mip1 =
    /\b(ignore|disregard|forget|skip|bypass|nullify|negate|omit|override)\s+(all\s+)?(the\s+|my\s+|your\s+|these\s+|those\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|prompts?|directives?|rules?|guidance|context)\b/i
  const mip1Match = input.match(mip1)
  if (mip1Match) {
    const start = mip1Match.index!
    return {
      patternId: "MIP-1",
      description: "Explicit instruction-override injection (NFKC-normalized; ASCII-English coverage)",
      evidence: mip1Match[0]!,
      catalogVersion: CATALOG_VERSION,
      startOffset: start,
      endOffset: start + mip1Match[0]!.length,
    }
  }

  const mip3 =
    /\b(you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as|system\s+prompt\s*:|new\s+instructions?\s*:|override\s+(your|my|the)\s+(role|prompt|instructions?))/i
  const mip3Match = input.match(mip3)
  if (mip3Match) {
    const start = mip3Match.index!
    return {
      patternId: "MIP-3",
      description: "Persona-rewriting / system-prompt reframing attempt",
      evidence: mip3Match[0]!,
      catalogVersion: CATALOG_VERSION,
      startOffset: start,
      endOffset: start + mip3Match[0]!.length,
    }
  }

  for (const m of input.matchAll(BASE64_LIKE)) {
    const start = m.index!
    const candidate = m[0]!
    const before = input.slice(Math.max(0, start - 2), start)
    const head = candidate.slice(0, 2)
    if (HEX_PREFIX_BEFORE.test(before) || HEX_PREFIX_AT_START.test(head)) continue
    return {
      patternId: "MIP-4",
      description: "Large contiguous base64-like blob (likely-encoded payload; base64 + base64url; 0x-prefix exempt)",
      evidence: `[redacted ≥256-char encoded blob; ${candidate.length} chars]`,
      catalogVersion: CATALOG_VERSION,
      startOffset: start,
      endOffset: start + candidate.length,
    }
  }

  const positions: number[] = []
  let m: RegExpExecArray | null
  const re = new RegExp(INVISIBLE_OR_FORMAT_CHARS.source, "gu")
  while ((m = re.exec(input)) !== null) {
    positions.push(m.index)
    if (positions.length >= 4) {
      const window = positions[positions.length - 1]! - positions[positions.length - 4]!
      if (window <= 100) {
        return {
          patternId: "MIP-5",
          description:
            "Invisible/format-character cluster (>3 in 100-char window) — steganographic injection signal; covers zero-width, bidi-override, and Tag-character families",
          evidence: `${positions.length} invisible-char hits; cluster window = ${window} chars`,
          catalogVersion: CATALOG_VERSION,
          startOffset: positions[positions.length - 4]!,
          endOffset: positions[positions.length - 1]! + 1,
        }
      }
    }
  }

  // MIP-2 (verdict-tool schema field-name match) + MIP-6 (cross-judge
  // tag-spoofing) are intentionally NOT in v0.2.0 — both require per-judge-
  // family configuration that ships when each hardened judge declares its
  // forced-tool schema explicitly. Tests in the corpus assert null on
  // representative MIP-2/MIP-6 inputs to lock the deferral-by-design.

  return null
}

export type MaliciousInputError = {
  readonly _tag: "MaliciousInputDetected"
  readonly inputKind: string
  readonly inputIdentifier: string
  readonly match: MaliciousInputMatch
}

export const toMaliciousInputError = (
  match: MaliciousInputMatch,
  inputKind: string,
  inputIdentifier: string,
): MaliciousInputError => ({
  _tag: "MaliciousInputDetected",
  inputKind,
  inputIdentifier,
  match,
})
