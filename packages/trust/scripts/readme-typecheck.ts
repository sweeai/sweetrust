/**
 * scripts/readme-typecheck.ts — compile the README's `ts` blocks against the
 * SHIPPED declarations (DAN-905).
 *
 * WHY THIS EXISTS. The README's headline quickstart called `verifyAuditChain`
 * with two arguments against a signature whose third parameter is REQUIRED. It
 * crashed on its own last line, in the published tarball — and the shape it
 * taught was the two-argument call that the third parameter was added to make
 * impossible. A reader "fixing" the crash the obvious way (making `opts`
 * optional) would have reintroduced the vulnerability.
 *
 * Nothing caught it because README code is prose to every tool in this repo.
 * `tsc` had the answer the whole time and was never pointed at the file.
 *
 * 🛑 IT CHECKS `dist/`, NOT `src/`. A README is read by strangers who install
 * from npm, so the surface under test is the emitted `.d.mts` — the same
 * artifact the pre-publish review reproduces findings against. Checking `src`
 * would have passed DAN-905's sibling defect, where `publicKeyHexFromPem`
 * existed in the source tree and was missing from the `mandate` barrel.
 *
 * DIRECTIVES — an HTML comment immediately before a fence:
 *
 *   <!-- readme-check: skip - <reason> -->
 *       Not compiled. The reason is REQUIRED and is PRINTED on every run. A
 *       silently skipped block is how this rotted the first time.
 *
 *   <!-- readme-check: prelude
 *   declare const settle: (to: string, amount: number) => string
 *   -->
 *       Prepended to the block. For excerpts that legitimately reference
 *       application context the README does not define. The block's own code is
 *       still compiled exactly as printed.
 *
 * Run: node --experimental-strip-types scripts/readme-typecheck.ts
 */
import { execFileSync } from "node:child_process"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { dirname, join, resolve } from "node:path"
import { fileURLToPath } from "node:url"

const PKG = resolve(dirname(fileURLToPath(import.meta.url)), "..")
const README = join(PKG, "README.md")

/**
 * The four published entry points, mapped to the declarations npm actually
 * serves. Keep in step with `exports` in package.json — a block importing a
 * subpath absent here fails to resolve, which is the correct outcome.
 */
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
      `❌ readme-typecheck: ${name} → ${rel} is missing. Run \`pnpm build\` first.`,
      "   This gate checks the SHIPPED declarations by design; there is nothing",
      "   honest to check without them. A gate that cannot check is not a pass.",
    )
  }
}

const md = readFileSync(README, "utf-8")

type Block = {
  readonly index: number
  readonly lang: "ts" | "tsx"
  readonly line: number
  readonly body: string
  readonly skip: string | null
  readonly prelude: string
}

const blocks: Array<Block> = []
/**
 * 🛑 EVERY TYPESCRIPT FENCE LANGUAGE, not just ```ts.
 *
 * This was `/```ts\n/` and matched nothing else. sweetrust's own README happens
 * to use ```ts throughout, so the gate worked — but nine sibling READMEs in the
 * same organisation write ```typescript, and a block fenced that way here would have been
 * INVISIBLE to this checker while looking checked to every human reading the
 * file. The `blocks.length === 0` guard below cannot catch it either: it only
 * fires when EVERY block is missed, never when one is.
 *
 * A checker whose coverage depends on which synonym the author happened to type
 * is a checker whose coverage nobody can state.
 */
const fence = /```(ts|typescript|tsx)\n([\s\S]*?)```/g
let m: RegExpExecArray | null
let n = 0
while ((m = fence.exec(md)) !== null) {
  n += 1
  const before = md.slice(0, m.index)
  const tail = before.slice(-1000)
  const skipMatch = /<!--\s*readme-check:\s*skip\s*[-]\s*([^>]*?)-->\s*$/.exec(tail)
  const preludeMatch = /<!--\s*readme-check:\s*prelude\n([\s\S]*?)-->\s*$/.exec(tail)
  blocks.push({
    index: n,
    line: before.split("\n").length,
    body: m[2],
    lang: m[1] === "tsx" ? "tsx" : "ts",
    skip: skipMatch === null ? null : skipMatch[1].trim(),
    prelude: preludeMatch === null ? "" : preludeMatch[1],
  })
}

if (blocks.length === 0) {
  die(
    "❌ readme-typecheck: found ZERO `ts` blocks in README.md.",
    "   Either the README lost its examples or this extractor broke.",
    "   A checker that checked nothing is not a pass.",
  )
}

const work = mkdtempSync(join(tmpdir(), "readme-tc-"))
mkdirSync(join(work, "blocks"), { recursive: true })

const checked = blocks.filter((b) => b.skip === null)
for (const b of checked) {
  writeFileSync(
    join(work, "blocks", `block-${b.index}.${b.lang}`),
    `// README.md line ${b.line} — generated, do not edit\n${b.prelude}${b.body}`,
  )
}

/**
 * 🛑 ONE PROGRAM PER BLOCK, AND THIS IS A CORRECTNESS REQUIREMENT, NOT A STYLE.
 *
 * TypeScript SUPPRESSES ALL SEMANTIC DIAGNOSTICS FOR A PROGRAM when any file in
 * it contains a syntax error. This gate previously wrote every block into one
 * temp project and ran `tsc -p` once — so a single unparseable block would have
 * silently disabled type checking for ALL of them, and the gate would have
 * printed a checkmark per block and exited 0.
 *
 * That is not hypothetical. Measured 2026-08-20 across nine sibling READMEs: three blocks are API signature notation fenced as ```typescript
 * (a call signature written with an optional-argument marker, and `{ ... }` used as an elision), which is
 * not parseable TypeScript. In a shared program they reduced 44 blocks to zero
 * type checking while reporting 44 passes. Isolated, the same corpus produced
 * 31 real failures, including two READMEs claiming an API their package does not export.
 *
 * sweetrust's four blocks all parse TODAY, so this gate has been working. It
 * would have stopped working, silently and permanently, the first time anyone
 * documented a signature the way three sibling packages already do — and the
 * symptom of the failure is that the output gets QUIETER.
 */
const baseCompilerOptions = {
  strict: true,
  target: "ES2022",
  module: "ESNext",
  moduleResolution: "bundler",
  noEmit: true,
  skipLibCheck: true,
  types: ["node"],
  // The generated tsconfig lives in a temp dir, so @types resolution has to be
  // pointed back at the package — otherwise `types: ["node"]` fails to resolve
  // and the gate reports a config error as if it were a README defect.
  typeRoots: [join(PKG, "node_modules/@types")],
  baseUrl: PKG,
  paths: Object.fromEntries(Object.entries(ENTRIES).map(([k, v]) => [k, [v]])),
}

for (const b of checked) {
  writeFileSync(
    join(work, `tsconfig.block-${b.index}.json`),
    JSON.stringify({
      compilerOptions: b.lang === "tsx"
        ? { ...baseCompilerOptions, jsx: "react-jsx" }
        : baseCompilerOptions,
      files: [join(work, "blocks", `block-${b.index}.${b.lang}`)],
    }),
  )
}

console.log(
  `readme-typecheck: ${blocks.length} \`ts\` blocks · ${checked.length} to compile · ${blocks.length - checked.length} skipped`,
)
for (const b of blocks) {
  if (b.skip !== null) console.log(`  ⏭  L${b.line} SKIPPED — ${b.skip}`)
}

/**
 * ── THE COVERAGE FLOOR ──────────────────────────────────────────────────────
 *
 * EVERY GATE HAS A DIRECTION, AND ITS BLIND SPOT SITS ON THE SIDE WHERE DOING
 * LESS LOOKS LIKE SUCCESS.
 *
 * A NEGATIVE gate — one that passes when something fails, like
 * `forgery-typecheck` — gets greener the more broken it is: a missing `dist`, a
 * typo, a `tsc` that never started all read as "rejected". Its control is a
 * POSITIVE CASE that must succeed.
 *
 * This gate points the other way. It passes when everything it looked at
 * compiled, so it gets greener the FEWER things it looks at, and its perfect
 * score is achieved by looking at nothing. Its control is therefore a FLOOR: a
 * count that must be MET, so that silence cannot masquerade as success.
 *
 * `blocks.length === 0` and "every block was skipped" are both floors of one —
 * they fire only in the total case. They cannot see a README that drops from
 * four examples to one, or a fence-synonym drift that hides three blocks out of
 * four, and the symptom of both is that this gate's output gets QUIETER while
 * staying green. That is the failure mode, so the number is pinned here.
 *
 * 🛑 THIS IS DATA, NOT A DIAL. Raise it when you add an example. Lowering it to
 * make a run pass is deleting the check; if a block genuinely goes away, lower
 * it in the same commit that removes the block and say so in the message. There
 * is deliberately no environment override: this repo has already learned that a
 * scope knob is a scope knob for whoever runs the gate LAST (see `pack-audit`'s
 * `PKGS` and `typecheck-honest`'s argv).
 */
const BLOCK_FLOOR = 4

if (checked.length < BLOCK_FLOOR) {
  die(
    `❌ readme-typecheck: compiled ${checked.length} block(s), floor is ${BLOCK_FLOOR}.`,
    `   ${blocks.length} fenced block(s) found, ${blocks.length - checked.length} skipped.`,
    "   This gate gets greener the fewer blocks it looks at, so a shortfall is",
    "   reported as a failure rather than a quieter pass. Either the README lost",
    "   examples, a fence synonym is not being matched, or blocks are being",
    "   skipped that should not be. If the examples really went away, lower",
    "   BLOCK_FLOOR in the same commit that removed them.",
  )
}

// Compile each block alone. The per-block ✔ is printed only after its own
// compile returns clean — previously the checkmarks were emitted before tsc ran
// at all, so they reported "written to disk", not "passed".
let failures = ""
for (const b of checked) {
  try {
    execFileSync("npx", ["tsc", "-p", join(work, `tsconfig.block-${b.index}.json`)], {
      stdio: "pipe",
      cwd: PKG,
    })
    console.log(`  ✔  L${b.line} compiled${b.prelude === "" ? "" : " (with prelude)"}`)
  } catch (err: unknown) {
    const e = err as { stdout?: Buffer; stderr?: Buffer }
    const out = `${e.stdout?.toString() ?? ""}${e.stderr?.toString() ?? ""}`
    // A config-level error (TS5xxx/TS6xxx) means the compiler never looked at
    // the block. Silence from a compiler that refused to start is not a pass.
    const configError = out.split("\n").find((l) => /^error TS[56]\d{3}:/.test(l))
    if (configError !== undefined) {
      die(
        `❌ readme-typecheck: the compiler did not run on the block at README.md:${b.line}.`,
        `   ${configError}`,
        "   That block would otherwise have reported a pass. Refusing.",
      )
    }
    console.log(`  ✘  L${b.line} FAILED`)
    failures += out
  }
}

if (failures !== "") {
  const out = failures
  // Map generated paths back to README line numbers, so the error points at the
  // document a human edits rather than a temp file they will never see.
  const mapped = out.replace(/\S*block-(\d+)\.tsx?\((\d+),(\d+)\)/g, (_all, idx, ln, col) => {
    const b = blocks.find((x) => x.index === Number(idx))
    if (b === undefined) return _all
    const offset = 1 + (b.prelude === "" ? 0 : b.prelude.split("\n").length - 1)
    return `README.md(${b.line + Number(ln) - offset},${col})`
  })
  console.error("\n❌ readme-typecheck FAILED — the README does not compile against the shipped types:\n")
  console.error(mapped.trim())
  process.exit(1)
}

console.log("✅ readme-typecheck: README compiles against the shipped declarations.")
