/**
 * forgery-typecheck — DAN-904's original reproduction, run as a gate.
 *
 * 🛑 IT CHECKS `dist/`, NOT `src/`. That is not a stylistic preference, it is
 * the entire reason this file exists. DAN-904 was found against the PACKED
 * `sweetrust@0.3.0` tarball in a fresh consumer and could not be reproduced
 * against the source tree, because the source tree is what hides it: the
 * compiler sees the real class, while a consumer sees whatever survived
 * declaration emit. The fix — an ECMAScript-private `#brand` — is nominal only
 * if it is EMITTED, and `packages/trust/test/gate/nominal-brand.test.ts` can only
 * assert that the marker is present as text. Present-as-text and
 * rejects-a-forgery are two different claims. This one makes the second.
 *
 * The DoD box for DAN-904 layer 1 says "check the built artifact, not the
 * source". Until this script existed, that instruction was the one box nothing
 * actually performed.
 *
 * ── WHY THERE IS A CONTROL, AND WHY IT IS NOT OPTIONAL ──────────────────────
 * This is a NEGATIVE gate: it passes when a compile FAILS. That is the most
 * dangerous shape a check can have, because a compile fails for every reason in
 * the world — a missing dist, an unresolvable path, a typo in this file, a tsc
 * that never started. Every one of those would be read as "the forgery was
 * rejected", and the gate gets greener the more broken it is.
 *
 * So a positive control compiles first, and it must SUCCEED. If the control
 * cannot compile, this run makes no claim about the forgery at all and says so.
 * An absence — here, the absence of a successful compile — is only evidence
 * when a known positive in the same harness produced one.
 *
 * The failure is also required to be the RIGHT failure: tsc must name the
 * private marker. A forgery rejected because of an unrelated type error is a
 * green measuring something else, which is the family of defect this package
 * keeps auditing out of itself.
 */
import { execFileSync } from "node:child_process"
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const PKG = resolve(dirname(fileURLToPath(import.meta.url)), "..")

/** Keep in step with `exports` in package.json — same map readme-typecheck uses. */
const ENTRIES: Record<string, string> = {
  "sweetrust": "./dist/index.d.mts",
  "sweetrust/mandate": "./dist/mandate.d.mts",
  "sweetrust/gate": "./dist/gate.d.mts",
  "sweetrust/verify": "./dist/verify.d.mts",
}

const die = (...lines: Array<string>): never => {
  for (const l of lines) console.error(l)
  process.exit(1)
}

for (const [name, rel] of Object.entries(ENTRIES)) {
  if (!existsSync(join(PKG, rel))) {
    die(
      `❌ forgery-typecheck: ${name} → ${rel} is missing. Run \`pnpm build\` first.`,
      "   This gate checks the SHIPPED declarations by design. With no build there",
      "   is nothing honest to check, and a gate that cannot check is not a pass.",
    )
  }
}

const work = mkdtempSync(join(tmpdir(), "sweetrust-forgery-"))
mkdirSync(join(work, "src"), { recursive: true })

const compilerOptions = {
  strict: true,
  target: "ES2022",
  module: "ESNext",
  moduleResolution: "bundler",
  noEmit: true,
  skipLibCheck: true,
  typeRoots: [join(PKG, "node_modules/@types")],
  baseUrl: PKG,
  paths: Object.fromEntries(Object.entries(ENTRIES).map(([k, v]) => [k, [v]])),
}

/**
 * The control and the forgery differ in exactly ONE way: where the `Sourced`
 * comes from. Everything else — the sink, the tier, the call — is identical, so
 * a difference in outcome can only be the brand. Any other difference between
 * the two files would be a confound, and this gate would stop measuring
 * nominality and start measuring the confound.
 */
const SINK = `
import { makeSink, ReceiptLog, Sourced } from "sweetrust"

const pay = makeSink<{ to: Sourced<string> }, string>({
  name: "pay",
  requires: { to: "verified" },
  mode: "enforce",
  log: new ReceiptLog(),
  execute: (a) => a.to.value,
})
`

const CONTROL = `${SINK}
// A real Sourced, minted through the class's own door.
const genuine = Sourced.fromAuthority("payee@example.test", "payee-registry")
pay({ to: genuine })
`

const FORGERY = `${SINK}
// DAN-904, verbatim from the ticket: five lines, no cast, strict: true.
const forged = {
  value: "attacker@evil.test",
  tier: "verified" as const,
  provenance: { origin: "forged", ancestors: new Set<string>(), chain: [] as const },
  describe: () => "verified via payee-registry",
}
pay({ to: forged })
`

type Outcome = { readonly ok: boolean; readonly out: string }

const compile = (name: string, source: string): Outcome => {
  writeFileSync(join(work, "src", `${name}.ts`), source)
  writeFileSync(
    join(work, `tsconfig.${name}.json`),
    JSON.stringify({ compilerOptions, files: [join(work, "src", `${name}.ts`)] }),
  )
  try {
    execFileSync("npx", ["tsc", "-p", join(work, `tsconfig.${name}.json`)], {
      stdio: "pipe",
      cwd: PKG,
    })
    return { ok: true, out: "" }
  } catch (err: unknown) {
    const e = err as { stdout?: Buffer; stderr?: Buffer }
    return { ok: false, out: `${e.stdout?.toString() ?? ""}${e.stderr?.toString() ?? ""}` }
  }
}

console.log("forgery-typecheck: compiling against dist/, not src/")

// ── 1. the control ──────────────────────────────────────────────────────────
const control = compile("control", CONTROL)
if (!control.ok) {
  die(
    "❌ forgery-typecheck: THE CONTROL DID NOT COMPILE.",
    "   A genuine `Sourced` was rejected by the shipped declarations, so this run",
    "   proves nothing about the forgery — a compile that fails for everything",
    "   'rejects' a forgery for free. Fix the harness or the build; do not read",
    "   this as a pass, and do not read it as a forgery being caught.",
    "",
    control.out.trim(),
  )
}
console.log("  ✔  control: a genuine Sourced compiles (the harness can produce a clean compile)")

// ── 2. the forgery ──────────────────────────────────────────────────────────
const forgery = compile("forgery", FORGERY)
if (forgery.ok) {
  die(
    "❌ forgery-typecheck: THE FORGERY COMPILED. DAN-904 IS OPEN IN THE SHIPPED ARTIFACT.",
    "   A five-line object literal satisfied `Sourced` against dist/. The brand is",
    "   not surviving declaration emit — check for `#private;` on `declare class",
    "   Sourced` in dist/*.d.mts. Note that a definite-assignment field",
    "   (`#brand!: void`) is NOT guaranteed to be emitted; an initialised one is.",
  )
}

// A config-level error means tsc never looked at the code. Silence from a
// compiler that refused to start is not a rejection.
const configError = forgery.out.split("\n").find((l) => /error TS[56]\d{3}:/.test(l))
if (configError !== undefined) {
  die(
    "❌ forgery-typecheck: the compiler never ran on the forgery.",
    `   ${configError.trim()}`,
    "   This is a harness fault, not a rejected forgery.",
  )
}

// It must fail for the RIGHT reason: the private marker, not some other slip.
if (!forgery.out.includes("#private")) {
  die(
    "❌ forgery-typecheck: the forgery was rejected, but NOT for its missing brand.",
    "   tsc never mentioned `#private`, so this rejection is not evidence of",
    "   nominality — it is some other type error in the fixture, and the gate",
    "   would stay green with the brand deleted.",
    "",
    forgery.out.trim(),
  )
}

const line = forgery.out.split("\n").find((l) => l.includes("#private"))?.trim() ?? ""
console.log(`  ✔  forgery: rejected by the shipped declarations — ${line}`)
console.log("✅ forgery-typecheck: an object literal cannot satisfy `Sourced` in the SHIPPED .d.mts.")
